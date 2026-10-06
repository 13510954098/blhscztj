"""Shared, conservative country parsing. No network requests or extra dependencies."""
from __future__ import annotations
import hashlib
import json
import re

# ISO 3166-1 alpha-2 codes; XK is an explicit project extension.
VALID_COUNTRY_CODES = frozenset('''AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ
BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ
CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ
DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR
GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY
HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP
KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY
MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ
NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY
QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ
TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ
VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK'''.split())


def country_code_from_flag(value: str) -> str:
    if not isinstance(value, str) or len(value) < 2:
        return ''
    pair = value[:2]
    if not all(0x1F1E6 <= ord(c) <= 0x1F1FF for c in pair):
        return ''
    code = ''.join(chr(ord('A') + ord(c) - 0x1F1E6) for c in pair)
    return code if code in VALID_COUNTRY_CODES else ''


def normalize_country_code(value) -> str:
    if not isinstance(value, str):
        return ''
    text = value.strip().upper()
    if re.fullmatch(r'[A-Z]{2}', text):
        return text if text in VALID_COUNTRY_CODES else ''
    flag = country_code_from_flag(text)
    if flag:
        suffix = text[2:].strip()
        return flag if not suffix or suffix == flag else ''
    return ''


def proxy_identity_hash(proxy: dict) -> str:
    payload = {k: v for k, v in proxy.items() if k != 'name'}
    serialized = json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str)
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()


def country_for_ip_details(reader, ip: str, trace_country: str) -> dict:
    def result(code='', source='', status='db_no_match', field=''):
        return {'country_code': code, 'country_source': source,
                'country_status': status, 'country_field': field}
    if reader is None:
        code = normalize_country_code(trace_country)
        return result(code, 'cloudflare-trace-loc' if code else '',
                      'identified' if code else 'invalid_trace_country', 'loc')
    try:
        record = reader.get(ip)
    except Exception:
        return result(status='db_lookup_error')
    if record is None:
        return result(status='db_no_match')
    candidates = []
    if isinstance(record, str):
        candidates.append((record, 'string'))
    elif isinstance(record, list):
        candidates.extend((v, 'list') for v in record if isinstance(v, str))
    elif isinstance(record, dict):
        for field in ('country', 'registered_country', 'represented_country'):
            value = record.get(field)
            if isinstance(value, dict):
                candidates.append((value.get('iso_code'), field + '.iso_code'))
    else:
        return result(status='unsupported_record_type')
    for value, field in candidates:
        code = normalize_country_code(value)
        if code:
            return result(code, 'geoip.metadb', 'identified', field)
    # An available database never silently falls back to Cloudflare's loc.
    return result(status='invalid_country_code')


def country_for_ip(reader, ip: str, trace_country: str) -> tuple[str, str]:
    details = country_for_ip_details(reader, ip, trace_country)
    return details['country_code'], details['country_source']
