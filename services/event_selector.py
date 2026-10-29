
import json
import re

from collections import Counter

from services.correlation_engine import parse_timestamp


MAX_AI_EVENTS = 80
MAX_SCAN_EVENTS = 20000


def raw_record(event):
    try:
        data = json.loads(event.raw_payload or "{}")
        return data if isinstance(data, dict) else {}
    except (ValueError, TypeError):
        return {}


def raw_field(record, *names):
    for name in names:

        direct = next(
            (
                key for key in record
                if isinstance(key, str)
                and key.casefold() == name.casefold()
            ),
            None
        )

        if direct is not None:
            value = record[direct]
            if isinstance(value, (str, int, float)):
                return str(value).lower()

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

            value = value.get(key) if key is not None else None

        if isinstance(value, (str, int, float)):
            return str(value).lower()

    return ""


def detect_evidence_type(event):
    """
    Identify likely evidence category from
    actual log metadata and normalized fields.

    This is classification, not root cause proof.
    """

    raw = raw_record(event)

    provider = raw_field(
        raw,
        "sourcetype",
        "event.provider",
        "event.dataset",
        "provider",
        "log_source",
        "channel",
        "source"
    )

    action = str(event.event_type or "").lower()
    label = f"{provider} {action}"

    if (
        event.mfa_status
        or re.search(
            r"\b(mfa|multi.factor|authenticator|2fa)\b",
            label
        )
    ):
        return "MFA"

    if (
        event.vpn_status
        or re.search(
            r"\b(vpn|openvpn|anyconnect|globalprotect)\b",
            label
        )
    ):
        return "VPN"

    if re.search(
        r"\b(edr|endpoint detection|crowdstrike|"
        r"falcon sensor|sentinelone)\b",
        label
    ):
        return "EDR"

    if re.search(
        r"\b(firewall|pan.os|fortigate|fortinet|"
        r"network traffic)\b",
        label
    ):
        return "Firewall"

    if (
        re.search(
            r"\b(windows|wineventlog|securityevent|"
            r"microsoft-windows)\b",
            label
        )
        or action in ("4624", "4625")
    ):
        return "Windows"

    if re.search(
        r"\b(linux|sshd|syslog|auditd|ssh login)\b",
        label
    ):
        return "Linux"

    if re.search(
        r"\b(sign.in|login|logon|authentication|"
        r"identity|signinlogs)\b",
        label
    ):
        return "Authentication"

    upload_source = str(
        getattr(
            getattr(event, "upload", None),
            "source_type",
            "Other"
        ) or "Other"
    )

    allowed = {
        "SIEM", "Windows", "Linux",
        "EDR", "Firewall", "VPN",
        "MFA", "Other"
    }

    return (
        upload_source
        if upload_source in allowed
        else "Other"
    )


def event_score(event, evidence_type, devices, ips):
    """
    Rank investigation leads.

    Scores prioritize evidence retrieval,
    not attack probability or RCA confidence.
    """

    action = str(event.event_type or "").lower()
    outcome = str(event.outcome or "").lower()

    score = 1

    if event.match_status == "Matched":
        score += 8

    elif event.match_status == "Unverified":
        score += 1

    if (
        event.device
        and event.device.strip().lower() in devices
    ):
        score += 3

    # IP alone is weak linking evidence.
    if (
        event.source_ip
        and event.source_ip.strip().lower() in ips
    ):
        score += 1

    if any(word in action for word in (
        "failed", "denied", "blocked",
        "ransomware", "malware",
        "privilege", "suspicious",
        "threat", "alert"
    )):
        score += 5

    if any(word in action for word in (
        "login", "logon", "sign-in",
        "signin", "authentication",
        "session", "process"
    )):
        score += 3

    if outcome in {
        "failure", "failed", "denied",
        "blocked", "success",
        "succeeded", "approved"
    }:
        score += 2

    if evidence_type not in ("SIEM", "Other"):
        score += 2

    if parse_timestamp(event.timestamp):
        score += 1

    return score


def select_relevant_events(
    events,
    total_in_case,
    max_selected=MAX_AI_EVENTS
):
    """
    Select a source-diverse set of current-case
    events from an already bounded scan.
    """

    events = list(events)

    max_selected = max(
        1,
        min(int(max_selected), MAX_AI_EVENTS)
    )

    matched = [
        e for e in events
        if e.match_status == "Matched"
    ]

    devices = {
        e.device.strip().lower()
        for e in matched
        if e.device
    }

    ips = {
        e.source_ip.strip().lower()
        for e in matched
        if e.source_ip
    }

    classified = [
        (e, detect_evidence_type(e))
        for e in events
    ]

    ranked = sorted(
        classified,
        key=lambda pair: (
            -event_score(
                pair[0],
                pair[1],
                devices,
                ips
            ),
            -pair[0].id
        )
    )

    selected = []
    selected_ids = set()

    source_order = (
        "Authentication",
        "Windows",
        "Linux",
        "MFA",
        "VPN",
        "EDR",
        "Firewall",
        "SIEM",
        "Other"
    )

    # Reserve places for different evidence types.
    for source in source_order:

        count = 0

        for event, category in ranked:

            if len(selected) >= max_selected:
                break

            if (
                category != source
                or event.id in selected_ids
                or count >= 3
            ):
                continue

            selected.append(event)
            selected_ids.add(event.id)
            count += 1

    # Fill remaining places with highest-ranked events.
    for event, category in ranked:

        if len(selected) >= max_selected:
            break

        if event.id not in selected_ids:
            selected.append(event)
            selected_ids.add(event.id)

    # Chronological order, unknown times at the end.
    def timeline_key(event):

        dt = parse_timestamp(event.timestamp)

        return (
            dt is None,
            dt.isoformat() if dt else "",
            event.id
        )

    selected.sort(key=timeline_key)

    inventory = Counter(
        category
        for _, category in classified
    )

    return selected, {
        "total_in_case": int(total_in_case),
        "events_scanned": len(events),
        "events_sent_to_ai": len(selected),
        "scan_limited": (
            len(events) < int(total_in_case)
        ),
        "selection_limited": (
            len(events) > len(selected)
        ),
        "evidence_types_detected": dict(
            sorted(inventory.items())
        ),
        "warning": (
            "Only selected events were sent to AI. "
            "Review original logs before confirming RCA."
            if int(total_in_case) > len(selected)
            else ""
        )
    }
