
import csv
import io
import json
import re
from datetime import datetime, timezone

MAX_EVENTS = 2500
ALLOWED_EXTENSIONS = {"json", "csv", "txt", "log"}


def get_field(record, *names):
    """Read case-insensitive JSON fields, including nested fields."""
    for name in names:
        value = record
        for piece in name.split("."):
            if not isinstance(value, dict):
                value = None
                break

            key = next(
                (key for key in value
                 if key.lower() == piece.lower()),
                None
            )

            value = (
                value.get(key)
                if key is not None
                else None
            )

        if value is not None and value != "":
            return value

    return None


def as_text(value):
    if value is None:
        return ""

    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)

    return str(value).strip()


def normalize_event(record):

    if isinstance(record, str):
        record = {"message": record}

    if not isinstance(record, dict):
        raise ValueError(
            "Each event must be a JSON object or text line."
        )

    message = as_text(get_field(
        record,
        "message", "description", "raw", "log"
    ))

    event_type = as_text(get_field(
        record,
        "event_type", "event.action",
        "event_name", "alert_name",
        "activity", "operationName",
        "EventID", "event_id", "action"
    ))

    outcome = as_text(get_field(
        record,
        "outcome", "event.outcome",
        "result", "resultType",
        "status", "authentication_status",
        "login_status"
    ))

    email = as_text(get_field(
        record,
        "email", "user_email",
        "userPrincipalName", "user.email",
        "actor.email", "identity",
        "username", "user",
        "account_name", "TargetUserName"
    )).lower()

    if "@" not in email or " " in email:
        email = ""

    ip = as_text(get_field(
        record,
        "source_ip", "src_ip",
        "client_ip", "ipAddress",
        "ip", "source.ip",
        "client.ip", "sourceIPAddress",
        "src"
    ))

    device = as_text(get_field(
        record,
        "hostname", "device_name",
        "device", "computer",
        "host.name",
        "deviceDetail.displayName",
        "workstationName"
    ))

    timestamp = as_text(get_field(
        record,
        "timestamp", "@timestamp",
        "TimeGenerated", "time",
        "createdDateTime", "dateTime",
        "eventTime", "datetime"
    ))

    mfa = as_text(get_field(
        record,
        "mfa_status",
        "authenticationDetails.mfaStatus",
        "mfa_result"
    ))

    vpn = as_text(get_field(
        record,
        "vpn_status",
        "vpn_connection_status"
    ))

    # Basic Linux SSH detection
    match = re.search(
        r"(Failed|Accepted) password for "
        r"(?:invalid user )?(\S+) from (\S+)",
        message,
        re.IGNORECASE
    )

    if match:
        outcome = (
            "Failure"
            if match.group(1).lower() == "failed"
            else "Success"
        )

        event_type = "SSH Login"
        ip = ip or match.group(3)

        if not email and "@" in match.group(2):
            email = match.group(2).lower()

    # Extract timestamp from plain text
    if not timestamp:
        iso = re.search(
            r"\b\d{4}-\d{2}-\d{2}[T ]"
            r"\d{2}:\d{2}:\d{2}"
            r"(?:Z|[+-]\d{2}:?\d{2})?",
            message
        )

        if iso:
            timestamp = iso.group(0)

    if not timestamp:
        syslog = re.match(
            r"^([A-Z][a-z]{2}\s+\d{1,2}\s+"
            r"\d{2}:\d{2}:\d{2})",
            message
        )

        if syslog:
            year = datetime.now(timezone.utc).year
            timestamp = (
                f"{year} {syslog.group(1)} "
                "(timezone unknown)"
            )

    if not event_type:
        event_type = "Unclassified Event"

    if event_type == "4625":
        event_type = "Windows Failed Login"
        outcome = outcome or "Failure"

    elif event_type == "4624":
        event_type = "Windows Successful Login"
        outcome = outcome or "Success"

    return {
        "timestamp": timestamp[:80],
        "user_email": email[:254],
        "source_ip": ip[:100],
        "device": device[:160],
        "event_type": event_type[:200],
        "outcome": outcome[:100],
        "mfa_status": mfa[:120],
        "vpn_status": vpn[:120],
        "message": message[:2000],
        "raw_payload": json.dumps(
            record,
            ensure_ascii=False,
            default=str
        )[:20000]
    }


def parse_log_file(contents, filename):

    ext = (
        filename.rsplit(".", 1)[-1].lower()
        if "." in filename else ""
    )

    if ext not in ALLOWED_EXTENSIONS:
        raise ValueError(
            "Supported formats: JSON, CSV, TXT, LOG."
        )

    try:
        content = contents.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ValueError(
            "Please export logs as UTF-8 text."
        ) from None

    if not content.strip():
        raise ValueError("The selected file is empty.")

    if ext == "json":

        try:
            payload = json.loads(content)
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON file.") from None

        if isinstance(payload, dict):

            collection = next(
                (
                    payload[key]
                    for key in (
                        "events", "records",
                        "logs", "data"
                    )
                    if isinstance(payload.get(key), list)
                ),
                None
            )

            rows = (
                collection
                if collection is not None
                else [payload]
            )

        elif isinstance(payload, list):
            rows = payload

        else:
            raise ValueError(
                "JSON must contain an event or events array."
            )

    elif ext == "csv":

        reader = csv.DictReader(
            io.StringIO(content)
        )

        if not reader.fieldnames:
            raise ValueError(
                "CSV needs a header row."
            )

        rows = list(reader)

    else:
        rows = []

        for line in content.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("{"):
                try:
                    candidate = json.loads(line)
                    rows.append(
                        candidate
                        if isinstance(candidate, dict)
                        else {"message": line}
                    )
                except json.JSONDecodeError:
                    rows.append({"message": line})

            else:
                rows.append({"message": line})

            if len(rows) > MAX_EVENTS:
                raise ValueError(
                    f"Maximum {MAX_EVENTS} events per upload."
                )

    if not rows:
        raise ValueError(
            "No log events found in this file."
        )

    if len(rows) > MAX_EVENTS:
        raise ValueError(
            f"Maximum {MAX_EVENTS} events per upload."
        )

    return [
        normalize_event(row)
        for row in rows
    ]
