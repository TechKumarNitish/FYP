from __future__ import annotations

import networkx as nx
from typing import List, Dict, Any


def build_baseline_graph(correlated_groups: List[Dict[str, Any]]) -> nx.DiGraph:
    g = nx.DiGraph()
    for group in correlated_groups:
        evidence = group.get('evidence', [])
        for e in evidence:
            sender = e.sender or e.source_name
            receiver = e.receiver or group.get('protocol') or 'unknown'
            g.add_edge(sender, receiver, semantic_event=group.get('semantic_event'), weight=1.0, protocol=group.get('protocol'))
    return g
