from __future__ import annotations

from detection.rules import detect_from_groups


def run_trustaware_detector(correlated_groups, inconsistencies, attack_threshold: float = 0.55, suspicious_event_threshold: float = 0.5):
    return detect_from_groups(correlated_groups, inconsistencies, trust_enabled=True, attack_threshold=attack_threshold, suspicious_event_threshold=suspicious_event_threshold)
