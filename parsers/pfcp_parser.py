from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import List
from parsers.common import Event

PFCP_TYPE_MAP = {
    '1': 'HeartbeatRequest',
    '2': 'HeartbeatResponse',
    '5': 'AssociationSetupRequest',
    '6': 'AssociationSetupResponse',
    '7': 'AssociationUpdateRequest',
    '8': 'AssociationUpdateResponse',
    '9': 'AssociationReleaseRequest',
    '10': 'AssociationReleaseResponse',
    '50': 'SessionEstablishmentRequest',
    '51': 'SessionEstablishmentResponse',
    '52': 'SessionModificationRequest',
    '53': 'SessionModificationResponse',
    '54': 'SessionDeletionRequest',
    '55': 'SessionDeletionResponse',
    '56': 'SessionReportRequest',
    '57': 'SessionReportResponse',
}

PFCP_TYPE_KEYS = [
    'pfcp.msg_type',
    'pfcp.message_type',
]
SEID_KEYS = [
    'pfcp.seid',
    'pfcp.f_seid',
    'pfcp.seid_tree',
]


def pcap_to_tshark_json(pcap_path: str, json_path: str) -> None:
    cmd = ['tshark', '-r', pcap_path, '-Y', 'pfcp', '-T', 'json']
    out = subprocess.check_output(cmd)
    Path(json_path).write_bytes(out)


def _pick(d: dict, keys: list[str]):
    for key in keys:
        if key in d:
            val = d[key]
            if isinstance(val, list):
                return val[0]
            return val
    return None


def parse_pfcp_json(json_path: str) -> List[Event]:
    packets = json.loads(Path(json_path).read_text(encoding='utf-8', errors='ignore'))
    events: List[Event] = []
    for idx, pkt in enumerate(packets, start=1):
        layers = pkt.get('_source', {}).get('layers', {})
        frame = layers.get('frame', {})
        pfcp = layers.get('pfcp', {})
        ip = layers.get('ip', {})
        udp = layers.get('udp', {})
        if not pfcp:
            continue
        ts = frame.get('frame.time_epoch', '')
        msg_type = _pick(pfcp, PFCP_TYPE_KEYS)
        seid = _pick(pfcp, SEID_KEYS)
        msg_name = PFCP_TYPE_MAP.get(str(msg_type), str(msg_type) if msg_type is not None else 'PFCPUnknown')
        events.append(Event(
            timestamp=str(ts),
            source_type='pcap_pfcp',
            source_name='pfcp_sniffer',
            protocol='PFCP',
            message_type=msg_name,
            sender=ip.get('ip.src'),
            receiver=ip.get('ip.dst'),
            session_id=str(seid) if seid else None,
            raw_ref=f'{json_path}:{idx}',
            metadata={'udp_srcport': udp.get('udp.srcport'), 'udp_dstport': udp.get('udp.dstport')}
        ))
    return events
