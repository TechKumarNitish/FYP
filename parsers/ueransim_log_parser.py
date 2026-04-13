from __future__ import annotations
import re
from pathlib import Path
from typing import List
from parsers.common import Event

IMSI_RE = re.compile(r'imsi-\d+')

def parse_ueransim_log(path: str, source_name: str) -> List[Event]:
    events = []

    for idx, line in enumerate(Path(path).read_text(errors="ignore").splitlines(), 1):

        msg = None

        if "Initial Registration" in line:
            msg = "UE_REG_START"

        elif "Authentication Request received" in line:
            msg = "UE_AUTH_REQ"

        elif "Security Mode Command received" in line:
            msg = "UE_SECURITY_MODE"

        elif "Registration accept received" in line:
            msg = "UE_REG_ACCEPT"

        elif "Initial Registration is successful" in line:
            msg = "UE_REG_SUCCESS"

        elif "PDU Session Establishment Request" in line:
            msg = "UE_PDU_REQ"

        elif "PDU Session Establishment Accept received" in line:
            msg = "UE_PDU_ACCEPT"

        elif "PDU Session establishment is successful" in line:
            msg = "UE_PDU_SUCCESS"

        elif "TUN interface" in line:
            msg = "UE_TUN_UP"

        elif "NG Setup procedure is successful" in line:
            msg = "GNB_NG_SETUP"

        elif "Initial Context Setup Request received" in line:
            msg = "GNB_CONTEXT_SETUP"

        elif "PDU session resource" in line:
            msg = "GNB_PDU_SETUP"

        if msg:
            events.append(Event(
                timestamp="",
                source_type="ue_log" if source_name == "ue" else "gnb_log",
                source_name=source_name,
                protocol="NAS",
                message_type=msg,
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
# REG_RE = re.compile(r'Registration|InitialUEMessage|UE Context|RRC Setup', re.IGNORECASE)
# PDU_RE = re.compile(r'PDU Session|establishing session|session established', re.IGNORECASE)
# NGAP_ID_RE = re.compile(r'(RAN_UE_NGAP_ID|AMF_UE_NGAP_ID)[=: ]+([0-9xa-fA-F]+)', re.IGNORECASE)
# IMSI_RE = re.compile(r'(imsi-\d+)', re.IGNORECASE)


# def parse_ueransim_log(path: str, source_name: str) -> List[Event]:
#     events: List[Event] = []
#     for idx, line in enumerate(Path(path).read_text(encoding='utf-8', errors='ignore').splitlines(), start=1):
#         ts_m = TS_RE.search(line)
#         ts = ts_m.group('ts') if ts_m else ''
#         imsi_m = IMSI_RE.search(line)
#         ue_id = imsi_m.group(1) if imsi_m else None
#         ng_m = NGAP_ID_RE.search(line)
#         sess = ng_m.group(2) if ng_m else None

#         msg = None
#         proto = None
#         if REG_RE.search(line):
#             msg = 'UERANRegistrationEvent'
#             proto = 'NGAP'
#         elif PDU_RE.search(line):
#             msg = 'UERANPDUSessionEvent'
#             proto = 'NAS'

#         if msg:
#             events.append(Event(
#                 timestamp=ts,
#                 source_type='ue_log' if source_name == 'ue' else 'gnb_log',
#                 source_name=source_name,
#                 protocol=proto,
#                 message_type=msg,
#                 ue_id=ue_id,
#                 session_id=sess,
#                 raw_ref=f'{path}:{idx}',
#                 metadata={'line': line.strip()}
#             ))
#     return events
