from __future__ import annotations

from typing import List
from copy import deepcopy
from parsers.common import Event

SCENARIOS = [
    {'name': 'benign', 'ground_truth_attack': 0},
    {'name': 'pfcp_attack', 'ground_truth_attack': 1},
    {'name': 'session_anomaly', 'ground_truth_attack': 1},
]


def inject_scenario(events: List[Event], scenario: str) -> List[Event]:
    events = deepcopy(events)
    if scenario == 'benign':
        return events

    if not events:
        return events

    template = events[0]

    if scenario == 'pfcp_attack':
        # Add a forged unknown PFCP control event. This should be detected by both
        # modes, and trust-aware mode should remain more stable under extra tampering.
        events.append(Event(
            timestamp=template.timestamp,
            source_type='pcap_pfcp',
            source_name='pfcp_sniffer',
            protocol='PFCP',
            message_type='PFCPUnknown',
            sender='10.0.0.1',
            receiver='10.0.0.2',
            ue_id=template.ue_id,
            session_id=template.session_id,
            raw_ref='scenario:pfcp_attack',
            metadata={'forged': True, 'scenario_attack': True},
        ))
        return events

    if scenario == 'session_anomaly':
        # Forge a contradictory SMF-side session event to emulate session-state anomaly.
        events.append(Event(
            timestamp=template.timestamp,
            source_type='nf_log',
            source_name='smf',
            protocol='5GC',
            message_type='SMF_IP_ASSIGNED',
            ue_id=template.ue_id,
            session_id='anom-session',
            raw_ref='scenario:session_anomaly',
            metadata={'forged': True, 'scenario_attack': True, 'ip': '10.45.9.9'},
        ))
        return events

    return events
