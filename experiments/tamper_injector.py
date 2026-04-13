from __future__ import annotations

import random
from typing import List
from parsers.common import Event


def inject_omission(events: List[Event], target_sources: set[str], level: float) -> List[Event]:
    kept = []
    for e in events:
        if e.source_name in target_sources and random.random() < level:
            continue
        kept.append(e)
    return kept


def inject_timestamp_skew(events: List[Event], target_sources: set[str], level: float) -> List[Event]:
    for e in events:
        if e.source_name in target_sources and random.random() < level:
            if e.timestamp:
                e.timestamp = e.timestamp + '_SKEW'
    return events


def inject_forgery(events: List[Event], target_source: str, level: float) -> List[Event]:
    extra = []
    count = max(1, int(len(events) * level * 0.1)) if level > 0 else 0
    for i in range(count):
        if not events:
            break
        template = random.choice(events)
        clone = Event(
            timestamp=template.timestamp,
            source_type=template.source_type,
            source_name=target_source,
            protocol=template.protocol,
            message_type='PFCPUnknown',
            sender=template.sender,
            receiver=template.receiver,
            ue_id=template.ue_id,
            session_id=template.session_id,
            teid=template.teid,
            raw_ref='forged',
            metadata={'forged': True},
        )
        extra.append(clone)
    return events + extra


def apply_tampering(events: List[Event], tamper_level: float) -> List[Event]:
    if tamper_level <= 0:
        return events
    events = inject_omission(list(events), {'amf', 'smf'}, tamper_level)
    events = inject_timestamp_skew(events, {'upf'}, tamper_level)
    events = inject_forgery(events, 'smf', tamper_level)
    return events
