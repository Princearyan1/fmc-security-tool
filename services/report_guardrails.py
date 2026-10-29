
"""Conservative validation of AI SOC investigation reports."""

import re
from collections import Counter


DETAIL_PATTERN = re.compile(
    r"\b(session|challenge|response|device|endpoint|timestamp|"
    r"time of|command.line|hash|client ip|source ip|user id|"
    r"correlation id|authentication method|process|linked|mapping)\b",
    re.IGNORECASE,
)

GENERIC_PATTERN = re.compile(
    r"\b(?:full|all|entire|complete)\s+"
    r"(?:mfa|vpn|edr|firewall|authentication|siem)\s+"
    r"(?:log|record|export)s?\b",
    re.IGNORECASE,
)


def count_value(value):
    return value if type(value) is int and value >= 0 else 0


def as_dict(value):
    return value if isinstance(value, dict) else {}


def get_evidence_stats(selection):
    selection = as_dict(selection)
    aggregate = as_dict(selection.get("aggregated_evidence"))

    matched = as_dict(
        aggregate.get("matched_category_counts")
    )

    unverified = as_dict(
        aggregate.get("unverified_category_counts")
    )

    categories = Counter({
        key: count_value(matched.get(key))
        + count_value(unverified.get(key))
        for key in set(matched) | set(unverified)
    })

    return {
        "scanned": count_value(
            selection.get("events_scanned")
        ),
        "selected": count_value(
            selection.get("events_sent_to_ai")
        ),
        "matched": count_value(
            selection.get("identity_matched_scanned")
        ),
        "unverified": count_value(
            selection.get("identity_unverified_scanned")
        ),
        "categories": categories,
        "matched_categories": matched,
        "mfa_statuses": as_dict(
            aggregate.get("explicit_mfa_status_counts")
        ),
        "vpn_statuses": as_dict(
            aggregate.get("explicit_vpn_status_counts")
        ),
    }


def correct_known_claims(text, stats, historical_count, flags):
    if not isinstance(text, str) or not text:
        return text

    if stats["unverified"] > 0 and stats["scanned"]:
        pattern = (
            r"\ball\s+(?:the\s+)?"
            r"(?:current\s+|case\s+|uploaded\s+)?events\s+"
            r"(?:are|were|have been)\s+"
            r"(?:identity[- ]matched|email[- ]matched|"
            r"matched to the (?:user|employee|account))\b"
        )

        replacement = (
            f"{stats['matched']} saved events have matching "
            f"email fields and {stats['unverified']} "
            "remain unverified"
        )

        text, changed = re.subn(
            pattern, replacement, text,
            flags=re.IGNORECASE
        )

        if changed:
            flags.add(
                "Corrected an unsupported claim that "
                "all events match the employee email."
            )

    if historical_count == 0:
        pattern = (
            r"\b(?:(?:a|an|the)\s+)?"
            r"(?:previously unseen|new|unfamiliar|"
            r"never-before-seen)\s+(?:endpoint|device)\b"
        )

        text, changed = re.subn(
            pattern,
            "a device without a verified historical baseline",
            text,
            flags=re.IGNORECASE
        )

        if changed:
            flags.add(
                "Device novelty cannot be established "
                "without historical evidence."
            )

    pattern = (
        r"\bMFA\s+(?:approval|success|challenge)\s+"
        r"(?:proves|confirms|guarantees)\s+(?:that\s+)?"
        r"(?:the\s+)?"
        r"(?:user|account holder|owner|legitimate|authorized)"
    )

    if re.search(pattern, text, re.IGNORECASE):
        text = (
            "An MFA result was recorded, but it does not "
            "independently establish who approved it or "
            "whether the activity was legitimate."
        )

        flags.add(
            "Removed unsupported user-identity attribution "
            "based only on MFA approval."
        )

    return text


def source_available(source, stats):
    categories = stats["categories"]

    if source == "MFA":
        return (
            count_value(categories.get("MFA")) > 0
            or any(
                count_value(v)
                for v in stats["mfa_statuses"].values()
            )
        )

    if source == "VPN":
        return (
            count_value(categories.get("VPN")) > 0
            or any(
                count_value(v)
                for v in stats["vpn_statuses"].values()
            )
        )

    if source in ("Windows", "Linux"):
        return any(
            count_value(categories.get(category)) > 0
            for category in (
                "Authentication Failures",
                "Authentication Successes",
            )
        )

    return count_value(categories.get(source)) > 0


def known_status(source, stats):
    values = (
        stats["mfa_statuses"]
        if source == "MFA"
        else stats["vpn_statuses"]
    )

    return any(
        isinstance(key, str)
        and key.startswith("matched:")
        and not key.endswith(":unresolved")
        and count_value(value) > 0
        for key, value in values.items()
    )


def prioritize_requests(requests, stats, alert_name):
    remaining = []
    suppressed = 0
    seen = set()

    login_alert = bool(
        re.search(
            r"login|logon|sign.in|authenticat|password",
            alert_name or "",
            re.IGNORECASE
        )
    )

    auth_count = (
        count_value(
            stats["matched_categories"].get(
                "Authentication Failures"
            )
        )
        + count_value(
            stats["matched_categories"].get(
                "Authentication Successes"
            )
        )
    )

    for item in requests[:5]:
        if not isinstance(item, dict):
            continue

        source = item.get("source_type", "Other")
        reason = str(item.get("reason") or "").strip()
        request = str(item.get("request") or "").strip()

        if not request:
            suppressed += 1
            continue

        specific = bool(
            DETAIL_PATTERN.search(reason + " " + request)
        )

        if source == "Other" and not specific:
            suppressed += 1
            continue

        if source in seen:
            suppressed += 1
            continue

        available = source_available(source, stats)

        has_status = (
            source in ("MFA", "VPN")
            and known_status(source, stats)
        )

        generic = bool(GENERIC_PATTERN.search(request))

        if available and has_status and generic and not specific:
            suppressed += 1
            continue

        if available:
            if not specific and not (
                source in ("MFA", "VPN")
                and not has_status
            ):
                suppressed += 1
                continue

            priority = "Useful enrichment"

            if source in ("MFA", "VPN") and not has_status and not specific:
                advice = (
                    "Check the existing SIEM export for "
                    "the event outcome and matching session "
                    "or device identifiers. Request only "
                    "specific fields that are missing."
                )
            else:
                advice = (
                    "Check the existing SIEM export for "
                    "these fields first. Only if unavailable, "
                    "provide targeted context: "
                    + request[:220]
                )

        else:
            priority = (
                "Required to resolve"
                if login_alert
                and auth_count == 0
                and source in (
                    "Windows", "Linux", "SIEM", "Other"
                )
                else "Useful enrichment"
            )

            advice = (
                "First check whether these fields already "
                "exist in the uploaded SIEM export. "
                "If missing and relevant, provide: "
                + request[:210]
            )

        seen.add(source)

        remaining.append({
            "source_type": source,
            "reason": reason[:350],
            "request": advice[:350],
            "priority": priority,
            "already_observed": available,
        })

    remaining.sort(
        key=lambda item: (
            0 if item["priority"] == "Required to resolve" else 1
        )
    )

    return remaining, suppressed


def apply_report_guardrails(
    report,
    current_events,
    selection_context,
    alert_name,
    historical_events_count=0
):
    """
    Conservative post-processing of an AI report.

    This does not verify every AI claim or
    establish a confirmed root cause.
    """

    stats = get_evidence_stats(selection_context)

    report = dict(report)
    flags = set()

    if stats["scanned"] > stats["selected"]:
        flags.add(
            "Only selected raw events were individually "
            "interpreted by AI. Other saved events "
            "contribute category and status counts."
        )

    for field in ("summary", "possible_root_cause"):
        report[field] = correct_known_claims(
            report.get(field, ""),
            stats,
            historical_events_count,
            flags
        )

    checked_evidence = []

    for item in report.get("evidence", []):
        if not isinstance(item, dict):
            continue

        ref = item.get("event_ref")

        explanation = correct_known_claims(
            item.get("explanation", ""),
            stats,
            historical_events_count,
            flags
        )

        event_details = next(
            (
                event
                for event in current_events
                if isinstance(event, dict)
                and event.get("event_ref") == ref
            ),
            None
        )

        if (
            event_details
            and event_details.get("identity_match") != "Matched"
        ):
            flags.add(
                "Unverified evidence does not establish "
                "the employee's identity."
            )

        if event_details and re.search(
            r"\bmfa\b",
            str(event_details.get("event_type", "")),
            re.IGNORECASE
        ):
            if re.search(
                r"\b(?:suggests? user interaction|"
                r"proved? (?:the )?user)",
                explanation,
                re.IGNORECASE
            ):
                explanation = (
                    "An MFA event was recorded. This alone "
                    "does not establish which person "
                    "approved the challenge."
                )

                flags.add(
                    "MFA citation was interpreted as "
                    "proof of user identity."
                )

        checked_evidence.append({
            "event_ref": ref,
            "explanation": explanation,
        })

    report["evidence"] = checked_evidence

    requests, suppressed = prioritize_requests(
        report.get("missing_evidence", []),
        stats,
        alert_name
    )

    report["missing_evidence"] = requests

    if suppressed:
        flags.add(
            f"Removed or merged {suppressed} "
            "generic or duplicate evidence request(s)."
        )

    narrative = (
        str(report.get("summary", ""))
        + " "
        + str(report.get("possible_root_cause", ""))
    ).lower()

    selected_types = " ".join(
        str(event.get("event_type") or "").lower()
        for event in current_events
        if isinstance(event, dict)
    )

    if (
        "password reset" in narrative
        and "password reset" not in selected_types
    ):
        flags.add(
            "Password reset is only a hypothesis, "
            "not an observed fact in selected evidence."
        )

    if (
        "credential leak" in narrative
        and not re.search(
            r"credential leak|credential exposure",
            selected_types
        )
    ):
        flags.add(
            "Credential leakage is speculative; "
            "selected evidence does not establish exposure."
        )
        
    # STEP 6C - Final factual consistency checks

    # 1. Correct identity coverage in the investigation summary.
    if stats["scanned"] and stats["unverified"] > 0:
        correct_coverage = (
            f"Of {stats['scanned']} saved events, "
            f"{stats['matched']} have matching email fields "
            f"and {stats['unverified']} remain identity-unverified. "
            "An email match does not verify the person."
        )

        summary = report.get("summary", "")

        summary, changed = re.subn(
            r"\ball\s+(?:the\s+)?(?:current\s+|case\s+|"
            r"uploaded\s+|saved\s+)?events\s+"
            r"(?:are|were)\s+"
            r"(?:identity|email)[- ]matched(?:\s+only)?\b",
            "the saved events have mixed identity-match status",
            summary,
            flags=re.IGNORECASE
        )

        if changed:
            flags.add(
                "Corrected an unsupported claim that "
                "all saved events were identity-matched."
            )

        if correct_coverage not in summary:
            summary = correct_coverage + " " + summary

        report["summary"] = summary.strip()

    # 2. Do not present attacker activity as established RCA.
    root_cause = report.get("possible_root_cause", "")

    unsupported_attack_claim = re.search(
        r"\ban attacker\s+(?:used|stole|accessed|"
        r"compromised)\b",
        root_cause,
        re.IGNORECASE
    )

    if unsupported_attack_claim:
        report["possible_root_cause"] = (
            "The failed authentication attempts followed by "
            "a successful login may reflect legitimate retries, "
            "user error, or unauthorized credential use. "
            "The available evidence does not establish who "
            "performed the activity or confirm credential "
            "theft or device compromise. Root cause requires "
            "analyst verification."
        )

        flags.add(
            "Changed an unsupported attacker attribution "
            "into unconfirmed investigative hypotheses."
        )

        report["confidence"] = "Low"

    # 3. Never treat an IP address as a confirmed device ID.
    corrected_actions = []

    for action in report.get("recommendations", []):
        ip_match = re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            action
        )

        device_claim = re.search(
            r"\b(device inventory|known device|"
            r"legitimate device|new device|"
            r"employee device|endpoint inventory)\b",
            action,
            re.IGNORECASE
        )

        if ip_match and device_claim:
            ip = ip_match.group(0)

            action = (
                f"Correlate source IP {ip} with authentication, "
                "VPN/session, and endpoint inventory records "
                "to determine device association. An IP "
                "address alone does not verify a device "
                "or employee identity."
            )

            flags.add(
                "Clarified that an IP address alone "
                "cannot identify a specific endpoint."
            )

        corrected_actions.append(action)

    report["recommendations"] = corrected_actions


    # Final check: remove contradictory identity claims.
    if stats["unverified"] > 0:
        summary = report.get("summary", "")

        summary, corrected = re.subn(
            r"\ball\s+(?:the\s+)?events\s+"
            r"(?:are|were)\s+"
            r"(?:identity|email)[-\s]*matched"
            r"(?:\s+only)?\b",
            "the saved events include both matched "
            "and unverified records",
            summary,
            flags=re.IGNORECASE
        )

        report["summary"] = summary

        if corrected:
            flags.add(
                "Corrected contradictory identity-match "
                "wording in the investigation summary."
            )

    # MFA approval alone cannot identify the person.
    mfa_refs = {
        e.get("event_ref")
        for e in current_events
        if isinstance(e, dict)
        and (
            "mfa" in str(e.get("event_type", "")).lower()
            or str(e.get("mfa_status") or "").strip()
        )
    }

    for item in report.get("evidence", []):
        if item.get("event_ref") not in mfa_refs:
            continue

        explanation = item.get("explanation", "")

        if re.search(
            r"\b(confirm(?:s|ed|ing)?|"
            r"prov(?:e|es|ed|ing))\b.{0,120}"
            r"\b(user|employee|account holder|attacker)\b",
            explanation,
            flags=re.IGNORECASE
        ):
            item["explanation"] = (
                "An MFA outcome was recorded. "
                "This does not establish who approved "
                "the challenge or prove session linkage."
            )

            flags.add(
                "Removed unsupported identity attribution "
                "from MFA evidence."
            )

    report["review_flags"] = sorted(flags)

    report["root_cause_status"] = "Unconfirmed"

    # Lower confidence for certain detected
    # unsupported identity claims.
    if any(
        "Corrected an unsupported claim" in flag
        or "MFA citation" in flag
        or "Removed unsupported user-identity" in flag
        for flag in flags
    ):
        report["confidence"] = "Low"

    if stats["scanned"] and stats["matched"] == 0:
        report["assessment"] = "Inconclusive"
        report["confidence"] = "Low"

    return report
