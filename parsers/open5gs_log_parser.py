from __future__ import annotations
import re
from pathlib import Path
from typing import List
from parsers.common import Event

IMSI_RE = re.compile(r'(imsi-\d+)')

def parse_open5gs_log(path: str, source_name: str) -> List[Event]:
    events = []

    for idx, line in enumerate(Path(path).read_text(errors="ignore").splitlines(), 1):
        ue_id = None
        m = IMSI_RE.search(line)
        if m:
            ue_id = m.group(1)

        msg = None
        protocol = None

        # AMF events
        if "InitialUEMessage" in line:
            msg = "AMF_INITIAL_UE_MESSAGE"
            protocol = "NGAP"

        elif "Registration request" in line:
            msg = "AMF_REG_REQUEST"
            protocol = "NAS"

        elif "Registration complete" in line:
            msg = "AMF_REG_COMPLETE"
            protocol = "NAS"

        elif "Number of AMF-Sessions is now 1" in line:
            msg = "AMF_SESSION_ADDED"

        elif "nsmf_pdusession" in line:
            msg = "AMF_PDU_SESSION_TRIGGER"

        elif "/nsmf-pdusession" in line:
            msg = "AMF_NSMF_API_CALL"

        # SMF events
        elif "Number of SMF-Sessions is now 1" in line:
            msg = "SMF_SESSION_ADDED"

        elif "UE SUPI" in line and "IPv4" in line:
            msg = "SMF_IP_ASSIGNED"

        # UPF events
        elif "Number of UPF-Sessions is now 1" in line:
            msg = "UPF_SESSION_ADDED"

        elif "UE F-SEID" in line:
            msg = "UPF_FSEID"

        if msg:
            events.append(Event(
                timestamp="",
                source_type="nf_log",
                source_name=source_name,
                protocol=protocol or "5GC",
                message_type=msg,
                ue_id=ue_id,
                raw_ref=f"{path}:{idx}",
                metadata={"line": line.strip()}
            ))

    return events


# from __future__ import annotations

# import re
# from pathlib import Path
# from typing import List
# from parsers.common import Event

# TS_RE = re.compile(r'^(?P<ts>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)')
# IMSI_RE = re.compile(r'(imsi-\d+|IMSI\[?(\d+)\]?)', re.IGNORECASE)
# SEID_RE = re.compile(r'(SEID|seid)[=: ]+([0-9xa-fA-F]+)')
# TEID_RE = re.compile(r'(TEID|teid)[=: ]+([0-9xa-fA-F]+)')
# PDU_RE = re.compile(r'PDU session', re.IGNORECASE)
# REG_RE = re.compile(r'Registration request|Registration accept|Initial Registration', re.IGNORECASE)
# AUTH_RE = re.compile(r'Authentication', re.IGNORECASE)
# PFCP_RE = re.compile(r'PFCP', re.IGNORECASE)
# ASSOC_RE = re.compile(r'Association Setup|Session Establishment|Session Modification|Session Deletion', re.IGNORECASE)


# def _extract_ts(line: str) -> str:
#     m = TS_RE.search(line)
#     return m.group('ts') if m else ''


# def _extract_imsi(line: str):
#     m = IMSI_RE.search(line)
#     if not m:
#         return None
#     return m.group(1)


# def _extract_two(rex: re.Pattern[str], line: str):
#     m = rex.search(line)
#     return m.group(2) if m else None


# def parse_open5gs_log(path: str, source_name: str) -> List[Event]:
#     events: List[Event] = []
#     for idx, line in enumerate(Path(path).read_text(encoding='utf-8', errors='ignore').splitlines(), start=1):
#         ts = _extract_ts(line)
#         ue_id = _extract_imsi(line)
#         seid = _extract_two(SEID_RE, line)
#         teid = _extract_two(TEID_RE, line)

#         protocol = None
#         msg = None
#         sender = source_name
#         receiver = None

#         if REG_RE.search(line):
#             protocol = 'NAS'
#             msg = 'RegistrationEvent'
#         elif AUTH_RE.search(line):
#             protocol = 'NAS'
#             msg = 'AuthenticationEvent'
#         elif PDU_RE.search(line):
#             protocol = 'NAS'
#             msg = 'PDUSessionEvent'
#         elif PFCP_RE.search(line) or ASSOC_RE.search(line):
#             protocol = 'PFCP'
#             msg = 'PFCPControlEvent'

#         if msg:
#             events.append(Event(
#                 timestamp=ts,
#                 source_type='nf_log',
#                 source_name=source_name,
#                 protocol=protocol or 'UNKNOWN',
#                 message_type=msg,
#                 sender=sender,
#                 receiver=receiver,
#                 ue_id=ue_id,
#                 session_id=seid,
#                 teid=teid,
#                 raw_ref=f'{path}:{idx}',
#                 metadata={'line': line.strip()}
#             ))
#     return events
