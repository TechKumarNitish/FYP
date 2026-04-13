from parsers.common import Event
from trust.source_trust import compute_source_trust


def test_source_trust_smoke():
    events = [
        Event(timestamp='1', source_type='nf_log', source_name='amf', protocol='NAS', message_type='RegistrationEvent'),
        Event(timestamp='2', source_type='nf_log', source_name='amf', protocol='NAS', message_type='AuthenticationEvent'),
    ]
    inconsistencies = [{'sources': ['amf']}]
    trust = compute_source_trust(events, inconsistencies)
    assert 'amf' in trust
    assert trust['amf'] <= 1.0
