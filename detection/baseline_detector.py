from __future__ import annotations

from detection.rules import detect_from_groups


def run_baseline_detector(correlated_groups, inconsistencies, attack_threshold: float = 0.5):
    return detect_from_groups(correlated_groups, inconsistencies, trust_enabled=False, attack_threshold=attack_threshold)
