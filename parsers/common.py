from __future__ import annotations

from dataclasses import dataclass, asdict, field
from typing import Any, Dict, Optional, List
import uuid


@dataclass
class Event:
    timestamp: str
    source_type: str
    source_name: str
    protocol: str
    message_type: str
    sender: Optional[str] = None
    receiver: Optional[str] = None
    ue_id: Optional[str] = None
    session_id: Optional[str] = None
    teid: Optional[str] = None
    severity: Optional[str] = None
    raw_ref: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def safe_strip(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def dump_events_jsonl(events: List[Event], path: str) -> None:
    import json
    with open(path, 'w', encoding='utf-8') as f:
        for e in events:
            f.write(json.dumps(e.to_dict()) + "\n")
