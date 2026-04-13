from __future__ import annotations

from typing import Dict, Any


def evidence_redundancy_score(group: Dict[str, Any]) -> float:
    evidence = group.get('evidence', [])
    unique_sources = {e.source_name for e in evidence}
    return min(1.0, len(unique_sources) / 3.0)
