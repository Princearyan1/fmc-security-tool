
"""Bounded full-case source-IP activity patterns.

Two-pass analysis:
1. Identify a limited set of relevant IP candidates.
2. Count their events exactly across all saved case records.

Same IP does not prove identity, device, session or compromise.
"""

import ipaddress
from collections import Counter

MAX_CANDIDATE_IPS = 16
MAX_OUTPUT_GROUPS = 4

INTEREST_WEIGHTS = {
    "Authentication Failures": 4,
    "Authentication Successes": 3,
    "MFA": 3,
    "VPN": 3,
    "EDR": 5,
    "Firewall": 3,
    "SIEM Alert": 5,
}

CATEGORY_ORDER = (
    "Authentication Failures",
    "Authentication Successes",
    "MFA",
    "VPN",
    "EDR",
    "Firewall",
    "SIEM Alert",
    "Other",
)


def _ip(value):
    try:
        return str(
            ipaddress.ip_address(
                str(value or "").strip()
            )
        )
    except ValueError:
        return None


class IPCandidateDiscovery:
    """Keep at most 16 candidate IP addresses in memory."""

    def __init__(self, capacity=MAX_CANDIDATE_IPS):
        self.capacity = capacity
        self.estimates = {}
        self.replacements = 0

    def observe(self, event, category):
        weight = INTEREST_WEIGHTS.get(category, 0)
        address = _ip(getattr(event, "source_ip", None))

        if not weight or not address:
            return

        if address in self.estimates:
            self.estimates[address] += weight

        elif len(self.estimates) < self.capacity:
            self.estimates[address] = weight

        else:
            least = min(
                self.estimates,
                key=lambda key: (
                    self.estimates[key],
                    key
                )
            )

            previous = self.estimates.pop(least)
            self.estimates[address] = previous + weight
            self.replacements += 1

    def candidates(self):
        return [
            address
            for address, _ in sorted(
                self.estimates.items(),
                key=lambda item: (
                    -item[1],
                    item[0]
                )
            )
        ]


class _IPCounts:
    def __init__(self):
        self.total = 0
        self.matched = 0
        self.unverified = 0
        self.category = Counter()
        self.first_utc = None
        self.last_utc = None

    def observe(self, event, category, timestamp):
        self.total += 1

        if getattr(event, "match_status", None) == "Matched":
            self.matched += 1
        else:
            self.unverified += 1

        category = (
            category
            if category in CATEGORY_ORDER
            else "Other"
        )

        self.category[category] += 1

        if timestamp is not None:
            if (
                self.first_utc is None
                or timestamp < self.first_utc
            ):
                self.first_utc = timestamp

            if (
                self.last_utc is None
                or timestamp > self.last_utc
            ):
                self.last_utc = timestamp


def build_ip_pattern_context(
    events,
    candidate_ips,
    selected_events,
    category_fn,
    parse_utc,
    max_groups=MAX_OUTPUT_GROUPS,
    candidates_truncated=False,
):
    """Exact counts for bounded candidates, not all IPs."""

    if not 1 <= max_groups <= MAX_OUTPUT_GROUPS:
        raise ValueError("Invalid max_groups")

    unique_ips = list(
        dict.fromkeys(
            address
            for raw in candidate_ips
            if (address := _ip(raw)) is not None
        )
    )[:MAX_CANDIDATE_IPS]

    groups = {
        address: _IPCounts()
        for address in unique_ips
    }

    scanned = 0

    for event in events:
        scanned += 1

        address = _ip(
            getattr(event, "source_ip", None)
        )

        if address not in groups:
            continue

        groups[address].observe(
            event,
            category_fn(event),
            parse_utc(
                getattr(event, "timestamp", None)
            )
        )

    selected_refs = {
        address: []
        for address in groups
    }

    for event in selected_events:
        address = _ip(
            getattr(event, "source_ip", None)
        )

        if address in selected_refs:
            selected_refs[address].append(
                "C" + str(event.id)
            )

    def relevance(address):
        group = groups[address]

        return (
            sum(
                group.category[category] * weight
                for category, weight
                in INTEREST_WEIGHTS.items()
            ),
            group.matched,
            group.total,
        )

    ranked = sorted(
        [
            address
            for address in groups
            if groups[address].total
        ],
        key=lambda address: (
            -relevance(address)[0],
            -relevance(address)[1],
            -relevance(address)[2],
            address,
        ),
    )

    output = []

    for number, address in enumerate(
        ranked[:max_groups],
        start=1
    ):
        group = groups[address]

        fail = group.category[
            "Authentication Failures"
        ]

        success = group.category[
            "Authentication Successes"
        ]

        categories = [
            category
            for category in CATEGORY_ORDER
            if category != "Other"
            and group.category[category]
        ]

        signals = []

        if fail >= 3:
            signals.append(
                "repeated_authentication_failures_on_same_ip"
            )

        if fail and success:
            signals.append(
                "failures_and_successes_on_same_ip_order_unverified"
            )

        if len(categories) >= 2:
            signals.append(
                "multiple_evidence_categories_on_same_ip"
            )

        output.append({
            "group_id": f"IP_GROUP_{number}",
            "saved_events_with_same_ip": group.total,
            "email_field_matched": group.matched,
            "identity_unverified": group.unverified,
            "category_counts": {
                category: group.category[category]
                for category in CATEGORY_ORDER
                if group.category[category]
            },
            "signals": signals,
            "selected_event_refs": (
                selected_refs[address][:6]
            ),
            "first_valid_utc": (
                group.first_utc.isoformat()
                if group.first_utc else None
            ),
            "last_valid_utc": (
                group.last_utc.isoformat()
                if group.last_utc else None
            ),
        })

    return {
        "scope": (
            "selected_IP_groups_across_all_saved_case_events"
        ),
        "second_pass_events_scanned": scanned,
        "candidate_ip_count": len(unique_ips),
        "ip_groups_reported": len(output),
        "some_candidate_ips_not_shown": (
            len(ranked) > max_groups
        ),
        "candidate_discovery_limited": bool(
            candidates_truncated
        ),
        "groups": output,
        "interpretation": (
            "EXACT counts only for the bounded candidate "
            "IP groups; other IP groups may contain "
            "important evidence. IPs are intentionally "
            "omitted. Use selected_event_refs only if "
            "supplied as raw events. Same IP does not "
            "establish identity, endpoint, session, "
            "time order, causation or compromise. "
            "Context is not a root-cause verdict."
        ),
    }
