from __future__ import annotations

from typing import List, Dict, Any
from parsers.common import Event


def correlate_events(events: List[Event], time_window_sec: float = 3.0) -> List[Dict[str, Any]]:
    """Simple semantic grouping by UE/session/message family.
    Research prototype: intentionally transparent and easy to modify.
    """
    groups: Dict[str, Dict[str, Any]] = {}
    for e in events:
        key = '|'.join([
            e.protocol or 'UNK',
            e.ue_id or 'noue',
            e.session_id or 'nosess',
            e.message_type or 'nomsg',
        ])
        if key not in groups:
            groups[key] = {
                'semantic_event': e.message_type,
                'protocol': e.protocol,
                'ue_id': e.ue_id,
                'session_id': e.session_id,
                'evidence': [],
            }
        groups[key]['evidence'].append(e)
    return list(groups.values())
