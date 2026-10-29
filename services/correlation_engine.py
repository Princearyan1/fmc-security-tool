
from datetime import datetime, timezone
from collections import Counter


CORRELATION_WINDOW_MINUTES = 30
MAX_TIMELINE_EVENTS = 200


def parse_timestamp(value):
    """
    Convert timezone-aware ISO timestamps to UTC.
    Never guess a timezone if it is missing.
    """
    if not value:
        return None

    try:
        dt = datetime.fromisoformat(
            str(value).strip().replace("Z", "+00:00")
        )

        if dt.tzinfo is None:
            return None

        return dt.astimezone(timezone.utc)

    except (ValueError, TypeError, OverflowError):
        return None


def normalize_value(value):
    if value is None:
        return ""

    return str(value).strip().lower()


def within_window(first, second):
    """
    Check whether two valid timestamps are within
    the configured correlation window.
    """
    if not first or not second:
        return False

    difference = abs(
        (first - second).total_seconds()
    )

    return difference <= (
        CORRELATION_WINDOW_MINUTES * 60
    )


def serialize_event(event):

    parsed_time = parse_timestamp(event.timestamp)

    source_type = (
        event.upload.source_type
        if event.upload else "Other"
    )

    return {
        "ref": f"C{event.id}",
        "event_id": event.id,
        "case_id": event.case_id,
        "source": source_type,
        "timestamp": event.timestamp or "",
        "timestamp_utc": (
            parsed_time.isoformat()
            if parsed_time else None
        ),
        "_datetime": parsed_time,
        "email": normalize_value(event.user_email),
        "ip": normalize_value(event.source_ip),
        "device": normalize_value(event.device),
        "event_type": event.event_type or "Unknown Event",
        "outcome": event.outcome or "",
        "mfa": event.mfa_status or "",
        "vpn": event.vpn_status or "",
        "match_status": event.match_status,
        "message": (event.message or "")[:300]
    }


def find_relationship(event, anchors):
    """
    Compare an event with explicitly email-matched
    current-case events.

    Important:
    Device and IP matches provide context.
    They never prove employee identity.
    """

    event_time = event["_datetime"]

    if event["match_status"] == "Matched":
        return {
            "level": "Direct",
            "reason": "Explicit employee email matches the case.",
            "related_ref": None,
            "basis": "email"
        }

    if event_time is None:
        return {
            "level": "Unverified",
            "reason": (
                "No usable timezone-aware timestamp. "
                "Time-based correlation is unavailable."
            ),
            "related_ref": None,
            "basis": None
        }

    device_match = None
    ip_match = None

    for anchor in anchors:

        if anchor["event_id"] == event["event_id"]:
            continue

        if not within_window(
            event_time,
            anchor["_datetime"]
        ):
            continue

        same_device = (
            event["device"]
            and anchor["device"]
            and event["device"] == anchor["device"]
        )

        same_ip = (
            event["ip"]
            and anchor["ip"]
            and event["ip"] == anchor["ip"]
        )

        if same_device:
            device_match = anchor
            break

        if same_ip and ip_match is None:
            ip_match = anchor

    if device_match:
        return {
            "level": "Contextual",
            "reason": (
                "Same device as an email-matched event "
                "within the investigation time window. "
                "Identity is not confirmed."
            ),
            "related_ref": device_match["ref"],
            "basis": "device_and_time"
        }

    if ip_match:
        return {
            "level": "Weak",
            "reason": (
                "Shared source IP within the time window. "
                "VPN, NAT or shared networks may explain "
                "the match. Identity is not confirmed."
            ),
            "related_ref": ip_match["ref"],
            "basis": "ip_and_time"
        }

    return {
        "level": "Unverified",
        "reason": (
            "No reliable relationship established "
            "with the available matched events."
        ),
        "related_ref": None,
        "basis": None
    }


def historical_comparison(current_events, historical_events):

    previous = [
        serialize_event(event)
        for event in historical_events
        if event.match_status == "Matched"
    ]

    current = [
        event for event in current_events
        if event["match_status"] == "Matched"
    ]

    previous_ips = {
        event["ip"]
        for event in previous
        if event["ip"]
    }

    previous_devices = {
        event["device"]
        for event in previous
        if event["device"]
    }

    current_ips = {
        event["ip"]
        for event in current
        if event["ip"]
    }

    current_devices = {
        event["device"]
        for event in current
        if event["device"]
    }

    return {
        "historical_events_checked": len(previous),

        "has_ip_baseline": bool(previous_ips),

        "has_device_baseline": bool(previous_devices),

        "new_ips": (
            sorted(current_ips - previous_ips)
            if previous_ips else []
        ),

        "shared_ips": sorted(
            current_ips & previous_ips
        ),

        "new_devices": (
            sorted(current_devices - previous_devices)
            if previous_devices else []
        ),

        "shared_devices": sorted(
            current_devices & previous_devices
        )
    }


def build_correlation(current_events, historical_events=None):
    """
    Build a read-only, evidence-linked investigation
    timeline for one case.

    This function does not classify an attack or
    establish a confirmed root cause.
    """

    historical_events = historical_events or []

    serialized = [
        serialize_event(event)
        for event in current_events[:MAX_TIMELINE_EVENTS]
    ]

    # Events directly matched by employee email.
    anchors = [
        event for event in serialized
        if event["match_status"] == "Matched"
    ]

    timeline = []
    relationships = []

    for event in serialized:

        relationship = find_relationship(
            event,
            anchors
        )

        public_event = {
            key: value
            for key, value in event.items()
            if key != "_datetime"
        }

        public_event["correlation_level"] = (
            relationship["level"]
        )

        public_event["correlation_reason"] = (
            relationship["reason"]
        )

        public_event["related_ref"] = (
            relationship["related_ref"]
        )

        timeline.append(public_event)

        if relationship["related_ref"]:
            relationships.append({
                "from_ref": event["ref"],
                "to_ref": relationship["related_ref"],
                "basis": relationship["basis"],
                "level": relationship["level"],
                "reason": relationship["reason"]
            })

    # Known UTC times first, unknown times last.
    timeline.sort(
        key=lambda event: (
            event["timestamp_utc"] is None,
            event["timestamp_utc"] or "",
            event["event_id"]
        )
    )

    sources = Counter(
        event["source"]
        for event in timeline
    )

    levels = Counter(
        event["correlation_level"]
        for event in timeline
    )

    history = historical_comparison(
        serialized,
        historical_events
    )

    return {
        "timeline": timeline,
        "relationships": relationships,
        "sources": dict(sources),
        "levels": dict(levels),
        "history": history,
        "total_processed": len(timeline),
        "unknown_timestamps": sum(
            event["timestamp_utc"] is None
            for event in timeline
        ),
        "investigation_window_minutes": (
            CORRELATION_WINDOW_MINUTES
        ),
        "truncated": (
            len(current_events) > MAX_TIMELINE_EVENTS
        ),
        "limitations": (
            "Correlation shows possible event relationships, "
            "not confirmed user attribution or root cause."
        )
    }
