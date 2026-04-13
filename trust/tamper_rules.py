from __future__ import annotations

from typing import List, Dict, Any

# Some events are naturally visible from only one source in a small Open5GS/UERANSIM
# testbed. Treat them as weak evidence, not attacks.
BENIGN_SINGLE_SOURCE_EVENTS = {
    'AMF_INITIAL_UE_MESSAGE',
    'AMF_REG_REQUEST',
    'AMF_REG_COMPLETE',
    'AMF_SESSION_ADDED',
    'AMF_PDU_SESSION_TRIGGER',
    'AMF_NSMF_API_CALL',
    'GNB_NG_SETUP',
    'GNB_CONTEXT_SETUP',
    'GNB_PDU_SETUP',
    'UE_AUTH_REQ',
    'UE_SECURITY_MODE',
    'UE_REG_ACCEPT',
    'UE_REG_SUCCESS',
    'UE_PDU_REQ',
    'UE_PDU_ACCEPT',
    'UE_PDU_SUCCESS',
    'UE_TUN_UP',
    'SMF_SESSION_ADDED',
    'SMF_IP_ASSIGNED',
    'UPF_SESSION_ADDED',
    'UPF_FSEID',
}

PFCP_KNOWN_MESSAGES = {
    'HeartbeatRequest', 'HeartbeatResponse',
    'AssociationSetupRequest', 'AssociationSetupResponse',
    'AssociationUpdateRequest', 'AssociationUpdateResponse',
    'AssociationReleaseRequest', 'AssociationReleaseResponse',
    'SessionEstablishmentRequest', 'SessionEstablishmentResponse',
    'SessionModificationRequest', 'SessionModificationResponse',
    'SessionDeletionRequest', 'SessionDeletionResponse',
    'SessionReportRequest', 'SessionReportResponse',
    '50', '51', '52', '53', '54', '55',
}


def detect_inconsistencies(correlated_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    for group in correlated_groups:
        evidence = group.get('evidence', [])
        if not evidence:
            continue
        semantic = group.get('semantic_event')
        sources = {e.source_name for e in evidence}
        protocols = {e.protocol for e in evidence}
        forged = any(bool(e.metadata.get('forged')) for e in evidence)
        skewed = any(str(e.timestamp).endswith('_SKEW') for e in evidence)

        if forged:
            findings.append({
                'type': 'forged_event',
                'semantic_event': semantic,
                'sources': list(sources),
                'severity': 'high'
            })

        if skewed:
            findings.append({
                'type': 'timestamp_skew',
                'semantic_event': semantic,
                'sources': list(sources),
                'severity': 'medium'
            })

        # Only one source observed the event. This is common in our lab setup.
        if len(evidence) == 1:
            findings.append({
                'type': 'single_source_event',
                'semantic_event': semantic,
                'sources': list(sources),
                'severity': 'low' if (semantic in BENIGN_SINGLE_SOURCE_EVENTS or semantic in PFCP_KNOWN_MESSAGES) else 'medium',
            })

        # Mixed protocols inside one semantic group can happen after correlation, but
        # it should be a warning, not an automatic attack.
        if len(protocols) > 1:
            findings.append({
                'type': 'protocol_mismatch',
                'semantic_event': semantic,
                'sources': list(sources),
                'severity': 'medium'
            })

        # Unknown PFCP control is suspicious.
        if group.get('protocol') == 'PFCP' and semantic not in PFCP_KNOWN_MESSAGES:
            findings.append({
                'type': 'unknown_pfcp_event',
                'semantic_event': semantic,
                'sources': list(sources),
                'severity': 'high'
            })
    return findings


def consistency_score_for_group(group: Dict[str, Any], inconsistencies: List[Dict[str, Any]]) -> float:
    impacted = [x for x in inconsistencies if x.get('semantic_event') == group.get('semantic_event')]
    if not impacted:
        return 1.0
    high = sum(1 for x in impacted if x.get('severity') == 'high')
    med = sum(1 for x in impacted if x.get('severity') == 'medium')
    low = sum(1 for x in impacted if x.get('severity') == 'low')
    score = 1.0 - 0.35 * high - 0.12 * med - 0.03 * low
    return max(0.0, score)
