
"""Streaming parser for large SIEM exports."""

import csv
import io
import json

from services.log_parser import (
    ALLOWED_EXTENSIONS,
    normalize_event,
)

MAX_STREAM_EVENTS = 20000
MAX_JSON_VALUE_CHARS = 1048576
READ_CHARS = 65536

EVENT_ARRAY_KEYS = {
    "events", "records", "logs", "data", "results"
}


class _JsonStream:
    def __init__(self, text_stream):
        self.source = text_stream
        self.buffer = ""
        self.pos = 0
        self.eof = False
        self.decoder = json.JSONDecoder()

    def _more(self):
        if self.eof:
            return False

        if self.pos > READ_CHARS:
            self.buffer = self.buffer[self.pos:]
            self.pos = 0

        chunk = self.source.read(READ_CHARS)

        if not chunk:
            self.eof = True
            return False

        self.buffer += chunk
        return True

    def peek(self):
        while True:
            while (
                self.pos < len(self.buffer)
                and self.buffer[self.pos].isspace()
            ):
                self.pos += 1

            if self.pos < len(self.buffer):
                return self.buffer[self.pos]

            if not self._more():
                return ""

    def expect(self, char):
        if self.peek() != char:
            raise ValueError("Invalid JSON file.")
        self.pos += 1

    def value(self):
        self.peek()

        if not self.buffer or self.pos >= len(self.buffer):
            raise ValueError("Invalid JSON file.")

        while True:
            try:
                parsed, end = self.decoder.raw_decode(
                    self.buffer, self.pos
                )

                if end - self.pos > MAX_JSON_VALUE_CHARS:
                    raise ValueError(
                        "A JSON event or metadata value exceeds 1 MB."
                    )

                # Avoid accepting partial numbers
                # at a streaming chunk boundary.
                if (
                    end == len(self.buffer)
                    and not self.eof
                    and self._more()
                ):
                    continue

                self.pos = end
                return parsed

            except json.JSONDecodeError:
                if (
                    len(self.buffer) - self.pos
                    > MAX_JSON_VALUE_CHARS
                ):
                    raise ValueError(
                        "A JSON event or metadata value exceeds 1 MB."
                    )

                if not self._more():
                    raise ValueError(
                        "Invalid JSON file."
                    ) from None

    def array(self):
        self.expect("[")

        if self.peek() == "]":
            self.pos += 1
            return

        while True:
            yield self.value()

            char = self.peek()

            if char == "]":
                self.pos += 1
                return

            self.expect(",")


def _json_rows(binary_stream):
    text_stream = io.TextIOWrapper(
        binary_stream,
        encoding="utf-8-sig",
        errors="strict",
        newline="",
    )

    try:
        reader = _JsonStream(text_stream)
        first = reader.peek()

        if first == "[":
            yield from reader.array()

        elif first == "{":
            reader.expect("{")

            found = False
            single_record = {}

            if reader.peek() == "}":
                reader.pos += 1
            else:
                while True:
                    key = reader.value()

                    if not isinstance(key, str):
                        raise ValueError("Invalid JSON file.")

                    reader.expect(":")

                    if (
                        not found
                        and key in EVENT_ARRAY_KEYS
                        and reader.peek() == "["
                    ):
                        found = True
                        yield from reader.array()
                    else:
                        value = reader.value()

                        if not found:
                            single_record[key] = value

                    char = reader.peek()

                    if char == "}":
                        reader.pos += 1
                        break

                    reader.expect(",")

            if not found:
                yield single_record

        else:
            raise ValueError(
                "JSON must contain an event object or events array."
            )

        if reader.peek():
            raise ValueError(
                "Invalid JSON file: content after final value."
            )

    except UnicodeDecodeError:
        raise ValueError(
            "Please export logs as UTF-8 text."
        ) from None

    finally:
        text_stream.detach()


def _csv_rows(binary_stream):
    text_stream = io.TextIOWrapper(
        binary_stream,
        encoding="utf-8-sig",
        errors="strict",
        newline="",
    )

    try:
        reader = csv.DictReader(
            text_stream,
            strict=True,
        )

        headers = reader.fieldnames

        if not headers or any(
            not isinstance(h, str) or not h.strip()
            for h in headers
        ):
            raise ValueError(
                "CSV needs nonempty column headers."
            )

        if (
            len({h.strip().casefold() for h in headers})
            != len(headers)
        ):
            raise ValueError(
                "CSV column headers must be unique."
            )

        for row in reader:
            if (
                None in row
                or any(value is None for value in row.values())
            ):
                raise ValueError(
                    f"CSV row ending at line {reader.line_num} "
                    "has extra or missing columns. "
                    "Match the header column count."
                )

            yield row

    except csv.Error:
        raise ValueError(
            "Invalid CSV formatting. Check quoting and columns."
        ) from None

    except UnicodeDecodeError:
        raise ValueError(
            "Please export logs as UTF-8 text."
        ) from None

    finally:
        text_stream.detach()


def _text_rows(binary_stream):
    text_stream = io.TextIOWrapper(
        binary_stream,
        encoding="utf-8-sig",
        errors="strict",
        newline="",
    )

    try:
        for line in text_stream:
            line = line.strip()

            if not line:
                continue

            if line.startswith("{"):
                try:
                    candidate = json.loads(line)

                    yield (
                        candidate
                        if isinstance(candidate, dict)
                        else {"message": line}
                    )

                    continue

                except json.JSONDecodeError:
                    pass

            yield {"message": line}

    except UnicodeDecodeError:
        raise ValueError(
            "Please export logs as UTF-8 text."
        ) from None

    finally:
        text_stream.detach()


def iter_normalized_events(
    binary_stream,
    filename,
    max_events=MAX_STREAM_EVENTS,
):
    """Yield normalized events without loading the whole file."""

    if (
        type(max_events) is not int
        or not 1 <= max_events <= MAX_STREAM_EVENTS
    ):
        raise ValueError(
            f"max_events must be between 1 and {MAX_STREAM_EVENTS}."
        )

    extension = (
        filename.rsplit(".", 1)[-1].lower()
        if "." in filename
        else ""
    )

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError(
            "Supported formats: JSON, CSV, TXT, LOG."
        )

    binary_stream.seek(0)

    if extension == "json":
        rows = _json_rows(binary_stream)
    elif extension == "csv":
        rows = _csv_rows(binary_stream)
    else:
        rows = _text_rows(binary_stream)

    count = 0

    for row in rows:
        count += 1

        if count > max_events:
            raise ValueError(
                f"Maximum {max_events} events per upload. "
                "No changes saved."
            )

        yield normalize_event(row)

    if count == 0:
        raise ValueError(
            "No log events found in this file."
        )
