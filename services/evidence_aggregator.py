"""Compact, bounded-memory facts over already-saved SIEM events.

This module does NOT decide maliciousness, employee identity or root cause.
It does not keep raw messages, addresses, email or user-controlled strings.
A count of observed events never proves that a source is complete.
"""

from collections import Counter

CATEGORIES = (
    "Authentication Failures", "Authentication Successes",
    "MFA", "VPN", "EDR", "Firewall", "SIEM Alert", "Other"
)

# Recognize only explicit status fields; do not infer MFA approval from a log type.
MFA_STATUSES = {
    "approved": "approved", "passed": "approved", "success": "approved",
    "succeeded": "approved", "failed": "failed", "failure": "failed",
    "denied": "denied", "rejected": "denied", "bypassed": "bypassed",
    "not required": "not_required", "not_required": "not_required",
}
VPN_STATUSES = {
    "connected": "connected", "active": "connected", "established": "connected",
    "disconnected": "disconnected", "terminated": "disconnected",
    "not connected": "disconnected", "not_connected": "disconnected",
    "failed": "failed", "failure": "failed",
    "success": "connected", "inactive": "disconnected",
}


class EvidenceAggregator:
    """Incremental deterministic summary, constant-sized counters and time bounds."""

    def __init__(self):
        self.scanned = 0
        self.matched = Counter()
        self.unverified = Counter()
        self.mfa_results = Counter()
        self.vpn_results = Counter()
        self.auxiliary = Counter()
        self.earliest = None
        self.latest = None

    def observe(self, event, category, timestamp_utc=None):
        self.scanned += 1
        category = category if category in CATEGORIES else "Other"
        is_matched = getattr(event, "match_status", None) == "Matched"
        (self.matched if is_matched else self.unverified)[category] += 1

        if timestamp_utc is not None:
            if self.earliest is None or timestamp_utc < self.earliest:
                self.earliest = timestamp_utc
            if self.latest is None or timestamp_utc > self.latest:
                self.latest = timestamp_utc

        # All unverified observations stay a separate context, never an identity claim.
        prefix = "matched" if is_matched else "unverified"
        mfa = str(getattr(event, "mfa_status", "") or "").strip().casefold()
        vpn = str(getattr(event, "vpn_status", "") or "").strip().casefold()
        if mfa:
            self.mfa_results[f"{prefix}:{MFA_STATUSES.get(mfa, 'unresolved')}"] += 1
        if vpn:
            self.vpn_results[f"{prefix}:{VPN_STATUSES.get(vpn, 'unresolved')}"] += 1

        # Bounded fixed-label observations useful for investigating the 'Other' bucket.
        # This is NOT a scan of raw_payload or message text.
        action = str(getattr(event, "event_type", "") or "").casefold()
        if "token" in action and "refresh" in action:
            self.auxiliary[f"{prefix}:token_refresh"] += 1
        if "session" in action and ("terminat" in action or "revok" in action):
            self.auxiliary[f"{prefix}:session_termination"] += 1
        if "privilege" in action or "role change" in action:
            self.auxiliary[f"{prefix}:privilege_change"] += 1

    def summary(self):
        return {
            "scope": "saved_current_case_events_only",
            "events_summarized": self.scanned,
            "matched_category_counts": {
                key: self.matched[key] for key in CATEGORIES if self.matched[key]
            },
            "unverified_category_counts": {
                key: self.unverified[key] for key in CATEGORIES if self.unverified[key]
            },
            "explicit_mfa_status_counts": dict(sorted(self.mfa_results.items())),
            "explicit_vpn_status_counts": dict(sorted(self.vpn_results.items())),
            "other_activity_counts": dict(sorted(self.auxiliary.items())),
            "first_valid_utc": self.earliest.isoformat() if self.earliest else None,
            "last_valid_utc": self.latest.isoformat() if self.latest else None,
            "interpretation": (
                "Counts cover saved case events, not the whole SIEM. "
                "Statuses are explicit parsed fields; match means email-field match only. "
                "Counts cannot prove identity, causation, or compromise."
            ),
        }
