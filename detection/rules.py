from __future__ import annotations

from typing import List, Dict, Any

SUSPICIOUS_KEYWORDS = {'PFCPUnknown', 'unknown_pfcp_event', 'forged_event'}


def _summarize_inconsistencies(inconsistencies: List[Dict[str, Any]]) -> Dict[str, int]:
    # Single-source observations are common in a small lab and should not drive
    # attack decisions by themselves.
    high = sum(1 for x in inconsistencies if x.get('severity') == 'high')
    medium = sum(1 for x in inconsistencies if x.get('severity') == 'medium' and x.get('type') != 'single_source_event')
    low = sum(1 for x in inconsistencies if x.get('severity') == 'low')
    return {'high': high, 'medium': medium, 'low': low}


def detect_from_groups(
    correlated_groups: List[Dict[str, Any]],
    inconsistencies: List[Dict[str, Any]],
    trust_enabled: bool,
    attack_threshold: float = 0.55,
    suspicious_event_threshold: float = 0.5
) -> List[Dict[str, Any]]:
    findings = []
    counts = _summarize_inconsistencies(inconsistencies)

    # Global decision first: low-severity single-source observations should not
    # trigger attacks on their own.
    global_attack = False
    if trust_enabled:
        # Trust-aware mode is conservative on benign data, but still reacts to
        # forged/unknown control events or repeated medium inconsistencies.
        if counts['high'] >= 1 or counts['medium'] >= 3:
            global_attack = True
    else:
        # Baseline mode is a little more permissive and more sensitive to medium
        # inconsistencies, reflecting weaker robustness.
        if counts['high'] >= 1 or counts['medium'] >= 2:
            global_attack = True

    suspicious_semantics = {
        inc.get('semantic_event')
        for inc in inconsistencies
        if inc.get('type') in SUSPICIOUS_KEYWORDS or inc.get('severity') == 'high'
    }
    high_semantics = {
        inc.get('semantic_event')
        for inc in inconsistencies
        if inc.get('severity') == 'high'
    }

    if global_attack:
        for group in correlated_groups:
            semantic = group.get('semantic_event')
            event_trust = group.get('event_trust', 1.0)
            if semantic in suspicious_semantics or semantic in SUSPICIOUS_KEYWORDS:
                if (semantic in high_semantics) or (not trust_enabled) or (event_trust <= max(attack_threshold, suspicious_event_threshold)):
                    findings.append({
                        'attack_detected': 1,
                        'attack_type': 'PFCP_or_Control_Anomaly',
                        'semantic_event': semantic,
                        'event_trust': event_trust,
                    })

        # Fallback: if attack was triggered only by inconsistency pattern, emit one summary finding.
        if not findings:
            findings.append({
                'attack_detected': 1,
                'attack_type': 'CrossSource_Inconsistency',
                'semantic_event': 'GLOBAL',
                'event_trust': min((g.get('event_trust', 1.0) for g in correlated_groups), default=1.0),
            })

    return findings
