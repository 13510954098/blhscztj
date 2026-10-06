#!/usr/bin/env python3
"""Offline country policy generation. Never probes proxies or guesses from names."""
from __future__ import annotations
import argparse
import copy
import hashlib
import json
import os
import re
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import yaml
from geo_country import normalize_country_code, country_code_from_flag, proxy_identity_hash
from merge_subscriptions import atomic_write

UNKNOWN = '❓ 未识别地区'
BASE = ('☁️ 代理选择', '🔰 手动选择', '♻️ 自动选择')
BUILTINS = {'DIRECT', 'REJECT', 'REJECT-DROP', 'COMPATIBLE', 'PASS', 'GLOBAL'}
FLAG_RE = re.compile(r'^[\U0001F1E6-\U0001F1FF]{2}')
SHORT_ID_RE = re.compile(r'''(?m)^([ \t]*short-id[ \t]*:[ \t]*)(?!["'])([0-9A-Fa-f]+)([ \t]*(?:#.*)?)$''')
LABELS = json.loads(Path(__file__).with_name('country_labels.json').read_text(encoding='utf-8'))

class ShortId(str):
    pass
class Dumper(yaml.SafeDumper):
    pass
Dumper.add_representer(ShortId, lambda d,v: d.represent_scalar('tag:yaml.org,2002:str', str(v), style='"'))

def load_yaml(path):
    text = SHORT_ID_RE.sub(lambda m: m[1] + '"' + m[2] + '"' + m[3], path.read_text(encoding='utf-8'))
    return yaml.safe_load(text)

def encode_controls(value):
    if isinstance(value, str):
        return ''.join(''.join(f'%{b:02X}' for b in c.encode()) if unicodedata.category(c)=='Cc' and c not in '\t\r\n' else c for c in value)
    if isinstance(value, list):
        return [encode_controls(v) for v in value]
    return value

def prepare_serialization(value):
    if isinstance(value, dict):
        for k,v in list(value.items()):
            if k in ('short-id', 'short_id') and isinstance(v,str):
                value[k] = ShortId(v)
            else:
                prepare_serialization(v)
    elif isinstance(value,list):
        for v in value: prepare_serialization(v)

def has_controls(value):
    if isinstance(value,str):
        return any(unicodedata.category(c)=='Cc' and c not in '\t\r\n' for c in value)
    if isinstance(value,dict): return any(has_controls(k) or has_controls(v) for k,v in value.items())
    if isinstance(value,list): return any(has_controls(v) for v in value)
    return False

def parse_time(value):
    try:
        result = datetime.fromisoformat(str(value).replace('Z','+00:00'))
        return result.astimezone(timezone.utc) if result.tzinfo else None
    except (ValueError, TypeError):
        return None

def classify(proxy, geo_meta, now, ttl_hours, database_sha256=None):
    mapping = geo_meta.get('actual_exit_country_by_identity') or {}
    record = mapping.get(proxy_identity_hash(proxy)) if isinstance(mapping,dict) else None
    if record is None:
        return '', 'missing_verification'
    provenance = geo_meta.get('geo_verification') or {}
    if not isinstance(provenance,dict): provenance = {}
    stamp = (record.get('verified_at') if isinstance(record,dict) else None) or provenance.get('verified_at') or geo_meta.get('generated_at')
    verified = parse_time(stamp)
    if verified is None: return '', 'missing_verification_time'
    age = (now-verified).total_seconds()
    if age < -300: return '', 'invalid_verification_time'
    if age > ttl_hours*3600: return '', 'expired_verification'
    old_db = provenance.get('database_sha256')
    if old_db and database_sha256 and old_db != database_sha256:
        return '', 'database_changed'
    code = normalize_country_code(record.get('country_code') if isinstance(record,dict) else record)
    if code: return code, 'identified'
    reason = record.get('status') if isinstance(record,dict) else None
    return '', reason if reason and reason != 'identified' else 'invalid_country_code'

def normalize_doc(doc, template, geo_meta, now, ttl_hours=24, database_sha256=None):
    doc = copy.deepcopy(doc)
    proxies = doc.get('proxies')
    if not isinstance(proxies,list): raise ValueError('proxies must be a list')
    names = [p.get('name') for p in proxies if isinstance(p,dict)]
    if len(names)!=len(proxies) or any(not isinstance(n,str) or not n for n in names):
        raise ValueError('Every proxy must have a nonempty name')
    if len(set(names))!=len(names): raise ValueError('Duplicate proxy names')
    template_groups = template.get('proxy-groups') or []
    services = [copy.deepcopy(g) for g in template_groups if isinstance(g,dict) and g.get('name') not in {*BASE,UNKNOWN} and not FLAG_RE.match(str(g.get('name','')))]
    by_country = {}; unknown = []; reasons = Counter()
    for proxy in proxies:
        code, reason = classify(proxy,geo_meta,now,ttl_hours,database_sha256)
        if code: by_country.setdefault(code,[]).append(proxy['name'])
        else: unknown.append(proxy['name']); reasons[reason]+=1
    entries = []
    for code,members in sorted(by_country.items()):
        flag = ''.join(chr(0x1F1E6+ord(c)-ord('A')) for c in code)
        entries.append((code, f'{flag} {LABELS.get(code,code)}自动', members))
    region_names = [g[1] for g in entries] + ([UNKNOWN] if unknown else [])
    all_names = set(BASE) | set(region_names) | {g['name'] for g in services}
    if len(all_names) != len(BASE)+len(region_names)+len(services):
        raise ValueError('Duplicate/conflicting group names')
    if all_names & set(names): raise ValueError('Proxy/group name collision')
    def group(name):
        return next((copy.deepcopy(g) for g in template_groups if isinstance(g,dict) and g.get('name')==name), {'name':name,'type':'select'})
    main, manual, automatic = [group(name) for name in BASE]
    main['proxies'] = [BASE[1],BASE[2]]+region_names+['DIRECT']
    manual['proxies'] = names or ['DIRECT']
    automatic['proxies'] = names or ['DIRECT']
    groups = [main,manual,automatic]
    for service in services:
        refs = service.get('proxies') or []
        valid = list(dict.fromkeys(r for r in refs if r in all_names or r in BUILTINS))
        for ref in region_names+['DIRECT']:
            if ref not in valid: valid.append(ref)
        service['proxies'] = valid
        groups.append(service)
    for _,name,members in entries:
        groups.append({'name':name,'type':'url-test','url':'https://www.gstatic.com/generate_204','interval':300,'tolerance':50,'lazy':True,'proxies':members})
    if unknown: groups.append({'name':UNKNOWN,'type':'select','proxies':unknown})
    # Regional classification is a disjoint and complete partition, not the manual/auto groups.
    regional_members = [n for _,_,members in entries for n in members]+unknown
    if Counter(regional_members)!=Counter(names): raise ValueError('Country partition is incomplete or duplicated')
    for g in groups:
        refs = g.get('proxies',[])
        if not refs and not g.get('use'): raise ValueError('Empty group: '+g['name'])
        if any(ref not in all_names and ref not in names and ref not in BUILTINS for ref in refs):
            raise ValueError('Dangling group reference: '+g['name'])
    doc['proxy-groups'] = groups
    for proxy in proxies:
        for key in ('ws-opts','http-opts'):
            opts = proxy.get(key)
            if isinstance(opts,dict) and 'path' in opts: opts['path'] = encode_controls(opts['path'])
    prepare_serialization(doc)
    if has_controls(doc): raise ValueError('Unsupported control character in config')
    stats = {'total_nodes':len(names),'grouped_country_nodes':len(names)-len(unknown),'unknown_nodes':len(unknown),
             'coverage':(len(names)-len(unknown))/len(names) if names else None,
             'unknown_reasons':dict(reasons),'country_groups':len(entries),'country_codes':[g[0] for g in entries],
             'partition_validated':True}
    return doc,stats

def run(root=Path('.'), fresh=False, ttl_hours=24, min_coverage=.8, fail_low=False, now=None):
    root=Path(root); now=now or datetime.now(timezone.utc)
    paths=[root/'sub/clash.yaml',root/'sub/merged/clash.yaml',root/'sub/alive/clash.yaml']
    template=load_yaml(paths[0])
    geo_path=root/'sub/alive/meta.json'
    try:
        geo_meta=json.loads(geo_path.read_text(encoding='utf-8'))
        if not isinstance(geo_meta,dict): raise ValueError('Geo metadata root is not an object')
    except (OSError,ValueError) as exc:
        if fresh: raise ValueError('Fresh verification requires valid geo metadata') from exc
        print('WARNING: missing/unreadable geo metadata; all unmatched nodes go to unknown')
        geo_meta={}
    provenance=geo_meta.get('geo_verification') or {}
    if fresh and os.environ.get('GITHUB_RUN_ID'):
        expected=os.environ['GITHUB_RUN_ID']+':'+os.environ.get('GITHUB_RUN_ATTEMPT','1')
        if provenance.get('run_id')!=expected: raise ValueError('Geo verification belongs to a different workflow run')
    db=root/'sub/geoip.metadb'
    db_sha=hashlib.sha256(db.read_bytes()).hexdigest() if db.is_file() else None
    staged=[]; summary={}; warnings=[]
    for path in paths:
        if not path.exists(): continue
        doc,stats=normalize_doc(load_yaml(path),template,geo_meta,now,ttl_hours,db_sha)
        stats.update({'shared_template':True,'normalization_at':now.isoformat(timespec='seconds'),
                      'verification_run_id':provenance.get('run_id'),
                      'verification_generated_at':provenance.get('verified_at') or geo_meta.get('generated_at'),
                      'verification_reused':not fresh,'stale':not fresh,'ttl_hours':ttl_hours})
        relative=str(path.relative_to(root));summary[relative]=stats
        if path==paths[2] and stats['total_nodes'] and stats['coverage']<min_coverage:
            warning=f"alive country coverage {stats['coverage']:.2%} is below {min_coverage:.2%}"
            warnings.append(warning)
            if fresh and fail_low: raise ValueError(warning)
        data=yaml.dump(doc,Dumper=Dumper,allow_unicode=True,sort_keys=False,default_flow_style=False,width=4096).encode()
        staged.append((path,data))
        meta_path=path.parent/'meta.json'
        meta=json.loads(meta_path.read_text(encoding='utf-8')) if meta_path.exists() else {}
        if not isinstance(meta,dict): raise ValueError('Output metadata must be an object')
        for key in ('nodes','sha256_16'):
            if not isinstance(meta.get(key),dict): meta[key]={}
        digest=hashlib.sha256(data).hexdigest()[:16]
        meta['nodes']['clash']=len(doc['proxies']);meta['sha256_16']['clash']=digest
        if isinstance(meta.get('files'),dict) and isinstance(meta['files'].get('clash.yaml'),dict):
            meta['files']['clash.yaml'].update({'nodes':len(doc['proxies']),'sha256_16':digest})
        previous = meta.get('policy_normalization') or {}
        previous_coverage = previous.get('coverage') if isinstance(previous,dict) else None
        if isinstance(previous_coverage,(int,float)) and stats['coverage'] is not None:
            stats['previous_coverage'] = previous_coverage
            stats['coverage_change'] = stats['coverage'] - previous_coverage
            if fresh and path==paths[2] and stats['coverage_change'] < -.2:
                warnings.append('alive country coverage dropped by more than 20 percentage points; check scope/input changes')
        meta['policy_normalization']=stats
        staged.append((meta_path,(json.dumps(meta,ensure_ascii=False,indent=2)+'\n').encode()))
    # Validate every output before replacing any. Each replacement is atomic.
    for path,data in staged: atomic_write(path,data)
    for warning in warnings: print('WARNING: '+warning)
    print(json.dumps(summary,ensure_ascii=False,indent=2))
    return summary

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path('.'))
    parser.add_argument('--fresh-verification',action='store_true')
    parser.add_argument('--ttl-hours',type=float,default=24)
    parser.add_argument('--min-coverage',type=float,default=.8)
    parser.add_argument('--fail-low-coverage',action='store_true')
    args=parser.parse_args()
    if args.ttl_hours<=0 or not 0<=args.min_coverage<=1: parser.error('Invalid TTL or coverage')
    run(args.root,args.fresh_verification,args.ttl_hours,args.min_coverage,args.fail_low_coverage)

if __name__=='__main__': main()
