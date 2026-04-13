from __future__ import annotations

from typing import Dict, Any
from correlation.semantic_events import evidence_redundancy_score


def compute_event_trust(group: Dict[str, Any], source_trust: Dict[str, float], consistency_score: float, consistency_weight: float = 0.3, redundancy_weight: float = 0.2) -> float:
    evidence = group.get('evidence', [])
    if not evidence:
        return 0.0
    avg_source = sum(source_trust.get(e.source_name, 1.0) for e in evidence) / len(evidence)
    redundancy = evidence_redundancy_score(group)
    score = (1.0 - consistency_weight - redundancy_weight) * avg_source + consistency_weight * consistency_score + redundancy_weight * redundancy
    return round(max(0.0, min(1.0, score)), 4)
