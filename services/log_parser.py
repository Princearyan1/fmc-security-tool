
import csv
import io
import json
import re

from datetime import datetime, timezone


MAX_EVENTS = 2500

ALLOWED_EXTENSIONS = {
    "json",
    "csv",
    "txt",
    "log"
}


# ==========================================
# FIELD EXTRACTION
# ==========================================

def get_field(record, *names):
    """
    Read fields from SIEM logs.

    Supports:
    - Normal JSON keys
    - Case-insensitive keys
    - Nested JSON objects
    - Flattened CSV/SIEM fields

    Example:
    source.ip
    OR
    {"source": {"ip": "..."}}
    """

    if not isinstance(record, dict):
        return None

    for name in names:

        # Check direct field names first.
        direct_key = next(
            (
                key for key in record
                if isinstance(key, str)
                and key.casefold() == name.casefold()
            ),
            None
        )

        if direct_key is not None:

            value = record[direct_key]

            if value is not None and value != "":
                return value

        # Check nested JSON objects.
        value = record

        for piece in name.split("."):

            if not isinstance(value, dict):
                value = None
                break

            key = next(
                (
                    key for key in value
                    if isinstance(key, str)
                    and key.casefold() == piece.casefold()
                ),
                None
            )

            if key is None:
                value = None
                break

            value = value[key]

        if value is not None and value != "":
            return value

    return None


# ==========================================
# SAFE TEXT CONVERSION
# ==========================================

def as_text(value):

    if value is None:
        return ""

    if isinstance(value, (dict, list)):
        return json.dumps(
            value,
            ensure_ascii=False
        )

    return str(value).strip()


# ==========================================
# NORMALIZE SECURITY EVENT
# ==========================================

def normalize_event(record):
    """
    Convert a raw log into the existing
    SecurityEvent database structure.
    """

    if isinstance(record, str):
        record = {
            "message": record
        }

    if not isinstance(record, dict):
        raise ValueError(
            "Each event must be a JSON object or text line."
        )

    # --------------------------------------
    # EVENT MESSAGE
    # --------------------------------------

    message = as_text(get_field(
        record,

        "message",
        "description",
        "raw",
        "_raw",
        "event.original",
        "log"
    ))

    # --------------------------------------
    # EVENT TYPE
    # --------------------------------------

    event_type = as_text(get_field(
        record,

        "event_type",
        "event.action",
        "event_name",
        "alert_name",
        "activity",
        "operationName",
        "EventID",
        "event_id",
        "action"
    ))

    # --------------------------------------
    # EVENT OUTCOME
    # --------------------------------------

    outcome = as_text(get_field(
        record,

        "outcome",
        "event.outcome",
        "result",
        "resultType",
        "status",
        "authentication_status",
        "login_status"
    ))

    # --------------------------------------
    # USER IDENTITY
    # --------------------------------------

    email = as_text(get_field(
        record,

        "email",
        "user_email",
        "userPrincipalName",
        "user.email",
        "actor.email",
        "identity",
        "username",
        "user",
        "account_name",
        "TargetUserName"
    )).lower()

    # Only an explicit email value is used
    # for email-based case matching.
    if "@" not in email or " " in email:
        email = ""

    # --------------------------------------
    # SOURCE IP ADDRESS
    # --------------------------------------

    ip = as_text(get_field(
        record,

        "source_ip",
        "src_ip",
        "client_ip",
        "ipAddress",
        "ip",
        "source.ip",
        "client.ip",
        "sourceIPAddress",
        "src"
    ))

    # --------------------------------------
    # DEVICE / HOST
    # --------------------------------------

    device = as_text(get_field(
        record,

        "hostname",
        "device_name",
        "device",
        "computer",
        "host.name",
        "deviceDetail.displayName",
        "workstationName"
    ))

    # --------------------------------------
    # TIMESTAMP
    # --------------------------------------

    timestamp = as_text(get_field(
        record,

        "timestamp",
        "@timestamp",
        "TimeGenerated",
        "time",
        "createdDateTime",
        "dateTime",
        "eventTime",
        "datetime",
        "event.created",
        "_time"
    ))

    # Splunk may export _time as Unix seconds.
    raw_splunk_time = get_field(
        record,
        "_time"
    )

    if (
        timestamp
        and raw_splunk_time is not None
        and timestamp == as_text(raw_splunk_time)
        and re.fullmatch(
            r"\d{10}(?:\.\d+)?",
            timestamp
        )
    ):

        try:

            timestamp = datetime.fromtimestamp(
                float(timestamp),
                tz=timezone.utc
            ).isoformat()

        except (
            ValueError,
            OverflowError,
            OSError
        ):
            pass

    # --------------------------------------
    # MFA STATUS
    # --------------------------------------

    mfa = as_text(get_field(
        record,

        "mfa_status",
        "authenticationDetails.mfaStatus",
        "mfa_result"
    ))

    # --------------------------------------
    # VPN STATUS
    # --------------------------------------

    vpn = as_text(get_field(
        record,

        "vpn_status",
        "vpn_connection_status"
    ))

    # ======================================
    # BASIC LINUX SSH DETECTION
    # ======================================

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

        if (
            not email
            and "@" in match.group(2)
        ):
            email = match.group(2).lower()

    # ======================================
    # TIMESTAMP FROM PLAIN TEXT
    # ======================================

    if not timestamp:

        iso = re.search(

            r"\b\d{4}-\d{2}-\d{2}[T ]"
            r"\d{2}:\d{2}:\d{2}"
            r"(?:Z|[+-]\d{2}:?\d{2})?",

            message
        )

        if iso:
            timestamp = iso.group(0)

    # --------------------------------------
    # SYSLOG TIMESTAMP
    # --------------------------------------

    if not timestamp:

        syslog = re.match(

            r"^([A-Z][a-z]{2}\s+\d{1,2}\s+"
            r"\d{2}:\d{2}:\d{2})",

            message
        )

        if syslog:

            year = datetime.now(
                timezone.utc
            ).year

            # Classic syslog does not provide
            # a reliable year or timezone.
            timestamp = (
                f"{year} {syslog.group(1)} "
                "(timezone unknown)"
            )

    # ======================================
    # WINDOWS EVENT RECOGNITION
    # ======================================

    if not event_type:
        event_type = "Unclassified Event"

    if event_type == "4625":

        event_type = "Windows Failed Login"

        outcome = outcome or "Failure"

    elif event_type == "4624":

        event_type = "Windows Successful Login"

        outcome = outcome or "Success"

    # ======================================
    # RETURN NORMALIZED EVENT
    # ======================================

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


# ==========================================
# MAIN LOG FILE PARSER
# ==========================================

def parse_log_file(contents, filename):
    """
    Parse supported SIEM exports.

    Supported:
    - JSON
    - CSV
    - TXT
    - LOG

    Returns normalized SecurityEvent records.
    """

    # --------------------------------------
    # VALIDATE EXTENSION
    # --------------------------------------

    ext = (
        filename.rsplit(".", 1)[-1].lower()
        if "." in filename
        else ""
    )

    if ext not in ALLOWED_EXTENSIONS:

        raise ValueError(
            "Supported formats: JSON, CSV, TXT, LOG."
        )

    # --------------------------------------
    # DECODE CONTENT
    # --------------------------------------

    try:

        content = contents.decode(
            "utf-8-sig"
        )

    except UnicodeDecodeError:

        raise ValueError(
            "Please export logs as UTF-8 text."
        ) from None

    if not content.strip():

        raise ValueError(
            "The selected file is empty."
        )

    # ======================================
    # JSON PARSING
    # ======================================

    if ext == "json":

        try:

            payload = json.loads(content)

        except json.JSONDecodeError:

            raise ValueError(
                "Invalid JSON file."
            ) from None

        if isinstance(payload, dict):

            collection = next(

                (
                    payload[key]

                    for key in (
                        "events",
                        "records",
                        "logs",
                        "data",
                        "results"
                    )

                    if isinstance(
                        payload.get(key),
                        list
                    )
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

    # ======================================
    # CSV PARSING
    # ======================================

    elif ext == "csv":

        reader = csv.DictReader(
            io.StringIO(content),
            strict=True
        )

        try:

            headers = reader.fieldnames

            if (
                not headers
                or any(
                    not isinstance(name, str)
                    or not name.strip()
                    for name in headers
                )
            ):

                raise ValueError(
                    "CSV needs nonempty column headers."
                )

            # Prevent duplicate or ambiguous fields.
            normalized_headers = {
                name.strip().casefold()
                for name in headers
            }

            if len(normalized_headers) != len(headers):

                raise ValueError(
                    "CSV column headers must be unique."
                )

            rows = []

            for row in reader:

                # Reject extra or missing columns.
                if (
                    None in row
                    or any(
                        value is None
                        for value in row.values()
                    )
                ):

                    raise ValueError(

                        f"CSV row ending at line "
                        f"{reader.line_num} has extra "
                        "or missing columns. "
                        "Match the header column count."
                    )

                rows.append(row)

                if len(rows) > MAX_EVENTS:

                    raise ValueError(
                        f"Maximum {MAX_EVENTS} events per upload."
                    )

        except csv.Error:

            raise ValueError(
                "Invalid CSV formatting. "
                "Check quoting and columns."
            ) from None

    # ======================================
    # TXT / LOG PARSING
    # ======================================

    else:

        rows = []

        for line in content.splitlines():

            line = line.strip()

            if not line:
                continue

            # Support JSON objects on individual lines.
            if line.startswith("{"):

                try:

                    candidate = json.loads(
                        line
                    )

                    rows.append(

                        candidate
                        if isinstance(candidate, dict)
                        else {"message": line}
                    )

                except json.JSONDecodeError:

                    rows.append({
                        "message": line
                    })

            else:

                rows.append({
                    "message": line
                })

            if len(rows) > MAX_EVENTS:

                raise ValueError(
                    f"Maximum {MAX_EVENTS} events per upload."
                )

    # ======================================
    # VALIDATE EVENT COUNT
    # ======================================

    if not rows:

        raise ValueError(
            "No log events found in this file."
        )

    if len(rows) > MAX_EVENTS:

        raise ValueError(
            f"Maximum {MAX_EVENTS} events per upload."
        )

    # ======================================
    # NORMALIZE ALL EVENTS
    # ======================================

    return [
        normalize_event(row)
        for row in rows
    ]
