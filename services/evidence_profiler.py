"""Bounded-memory, deterministic SIEM evidence inventory and selection.

Scans every SAVED event supplied by the caller, without external API calls.
This is retrieval prioritization, not an incident verdict or confirmed RCA.
"""

import heapq
import json
import re
from collections import Counter
from datetime import datetime, timezone

from services.evidence_aggregator import EvidenceAggregator
from services.incident_patterns import (
    IPCandidateDiscovery,
    build_ip_pattern_context,
)
MAX_AI_EVENTS = 12  # conservative initial Groq budget; adjustable after measuring
BUCKET_SIZE = 5


# Fixed categories: never send raw source labels or log instructions as metadata.
CATEGORIES = (
    "Authentication Failures", "Authentication Successes",
    "MFA", "VPN", "EDR", "Firewall", "SIEM Alert", "Other"
)


def _parse_utc(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return None
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _metadata(event):
    """Read only common sourcetype/source metadata from stored raw JSON."""
    try:
        data = json.loads(event.raw_payload or "{}")
        if not isinstance(data, dict):
            return ""
    except (ValueError, TypeError):
        return ""

    for name in ("sourcetype", "event.dataset", "log_source", "provider"):
        value = next(
            (v for k, v in data.items()
             if isinstance(k, str) and k.casefold() == name.casefold()),
            None,
        )
        if isinstance(value, str):
            return value[:100].casefold()
    return ""


def _category(event):
    name = str(event.event_type or "").casefold()
    outcome = str(event.outcome or "").casefold()
    source = _metadata(event)
    upload = str(getattr(getattr(event, "upload", None), "source_type", "") or "").casefold()
    combined = f"{source} {upload} {name}"

    # Named event/status data takes priority over generic upload type "SIEM".
    if event.mfa_status or re.search(r"\b(mfa|authenticator|multi.factor|2fa)\b", combined):
        return "MFA"
    if event.vpn_status or re.search(r"\b(vpn|openvpn|anyconnect|globalprotect)\b", combined):
        return "VPN"
    if re.search(r"\b(edr|crowdstrike|sentinelone|endpoint detection)\b", combined):
        return "EDR"
    if re.search(r"\b(firewall|fortinet|fortigate|pan.os)\b", combined):
        return "Firewall"
    if re.search(r"\b(siem:alert|detection rule|correlation alert)\b", combined) or (
        "alert" in name and "login" not in name
    ):
        return "SIEM Alert"

    auth = bool(re.search(r"login|logon|sign.in|signin|authenticat|ssh", name))
    if auth and ("fail" in name or outcome in {"failure", "failed", "denied"}):
        return "Authentication Failures"
    if auth and ("success" in name or outcome in {"success", "succeeded"}):
        return "Authentication Successes"
    return "Other"


def _score(event, category):
    name = str(event.event_type or "").casefold()
    score = 8 if event.match_status == "Matched" else 0
    score += {
        "Authentication Failures": 8,
        "Authentication Successes": 8,
        "MFA": 7, "VPN": 6, "EDR": 8,
        "Firewall": 6, "SIEM Alert": 8, "Other": 0,
    }[category]
    if re.search(r"malware|ransomware|suspicious|privilege|blocked|threat", name):
        score += 3
    if event.source_ip:
        score += 1
    if event.device:
        score += 1
    if _parse_utc(event.timestamp):
        score += 1
    return score


def _keep_best(heap, event, score, capacity):
    item = (score, int(event.id), event)
    if len(heap) < capacity:
        heapq.heappush(heap, item)
    elif item[:2] > heap[0][:2]:
        heapq.heapreplace(heap, item)


def profile_and_select(events, total_in_case=None, max_selected=MAX_AI_EVENTS):
    """Stream SAVED case events once; return (selected_event_objects, digest).

    Caller can provide a SQLAlchemy query ordered by ID with .yield_per(500).
    Keeps only bounded candidate pools in memory, irrespective of event count.
    """
    if type(max_selected) is not int or not 1 <= max_selected <= 40:
        raise ValueError("max_selected must be between 1 and 40")

    totals = Counter()
    by_category = {category: [] for category in CATEGORIES}
    top_all = []
    scanned = 0
    missing_time = 0
    identity_matched = 0
    identity_unverified = 0
    aggregator = EvidenceAggregator()
    ip_discovery = IPCandidateDiscovery()

    for event in events:
        scanned += 1
        category = _category(event)
        totals[category] += 1
        aggregator.observe(event, category, _parse_utc(event.timestamp))
        ip_discovery.observe(event, category)

        if event.match_status == "Matched":
            identity_matched += 1
        else:
            identity_unverified += 1
        if _parse_utc(event.timestamp) is None:
            missing_time += 1

        score = _score(event, category)
        _keep_best(by_category[category], event, score, BUCKET_SIZE)
        _keep_best(top_all, event, score, max_selected * 3)

    # One per category where possible, then round-robin, then global ranking.
    # This avoids selecting only the most frequent source or newest records.
    ranked = {
        category: sorted(heap, key=lambda x: (x[0], x[1]), reverse=True)
        for category, heap in by_category.items()
    }
    chosen = {}
    for depth in range(BUCKET_SIZE):
        for category in CATEGORIES:
            if len(chosen) >= max_selected:
                break
            options = ranked[category]
            if depth < len(options):
                event = options[depth][2]
                chosen[event.id] = event
        if len(chosen) >= max_selected:
            break

    for _, _, event in sorted(top_all, key=lambda x: (x[0], x[1]), reverse=True):
        if len(chosen) >= max_selected:
            break
        chosen.setdefault(event.id, event)

    selected = sorted(
        chosen.values(),
        key=lambda e: (
            _parse_utc(e.timestamp) is None,
            _parse_utc(e.timestamp) or datetime.max.replace(tzinfo=timezone.utc),
            e.id,
        )
    )
    
    # STEP 6D-B: Second-pass IP pattern analysis

    if iter(events) is events:
        incident_patterns = {
            "available": False,
            "reason": "One-shot iterator: second pass unavailable.",
        }

    else:
        incident_patterns = build_ip_pattern_context(
            events=events,
            candidate_ips=ip_discovery.candidates(),
            selected_events=selected,
            category_fn=_category,
            parse_utc=_parse_utc,
            candidates_truncated=(
                ip_discovery.replacements > 0
            ),
        )

        incident_patterns["available"] = True


    digest = {
        "total_in_case": int(total_in_case) if total_in_case is not None else scanned,
        "events_scanned": scanned,
        "events_sent_to_ai": len(selected),
        "identity_matched_scanned": identity_matched,
        "identity_unverified_scanned": identity_unverified,
        "events_with_unusable_timestamp": missing_time,
        "evidence_categories_detected": dict(totals),
        "aggregated_evidence": aggregator.summary(),
        "incident_patterns": incident_patterns,
        "scan_limited": total_in_case is not None and scanned < int(total_in_case),
        "selection_limited": scanned > len(selected),
        "interpretation": (
            "Deterministic inventory across saved case events. "
            "The model sees representative selected events, not every raw event. "
            "Counts are not confirmation of an attack, identity, or root cause. "
            "An absent category does not prove the evidence is unavailable in SIEM."
        ),
    }
    return selected, digest
