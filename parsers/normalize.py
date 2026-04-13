from __future__ import annotations

from typing import Iterable, List
from parsers.common import Event


def normalize_events(*event_lists: Iterable[Event]) -> List[Event]:
    merged: List[Event] = []
    for event_list in event_lists:
        merged.extend(list(event_list))
    merged.sort(key=lambda e: (e.timestamp or '', e.source_name, e.message_type))
    return merged
