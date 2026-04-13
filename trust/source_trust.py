from __future__ import annotations

from collections import defaultdict
from typing import Dict, List
from parsers.common import Event


def compute_source_trust(events: List[Event], inconsistencies: List[dict], mismatch_penalty: float = 0.15, min_source_trust: float = 0.2) -> Dict[str, float]:
    totals = defaultdict(int)
    bad = defaultdict(int)
    for e in events:
        totals[e.source_name] += 1
    for item in inconsistencies:
        for src in item.get('sources', []):
            bad[src] += 1

    trust = {}
    for src, total in totals.items():
        score = 1.0 - mismatch_penalty * (bad[src] / max(1, total))
        trust[src] = max(min_source_trust, round(score, 4))
    return trust
