from __future__ import annotations
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import geo_country as geo
import mihomo_alive_check as checker
import normalize_country_groups as policy

NOW = datetime(2026,10,6,8,tzinfo=timezone.utc)
class Reader:
    def __init__(self,record): self.record=record
    def get(self,ip): return self.record

def node(name='not-a-country',server='example.test'):
    return {'name':name,'type':'http','server':server,'port':443}

def metadata(nodes,codes):
    return {'generated_at':NOW.isoformat(),'actual_exit_country_by_identity':{
        geo.proxy_identity_hash(p):{'country_code':c,'source':'geoip.metadb','status':'identified' if c else 'db_no_match'}
        for p,c in zip(nodes,codes)}}

class CountryParsingTests(unittest.TestCase):
    def test_direct_strings_go_through_the_actual_checker(self):
        for raw,code in [('us','US'),('cn','CN'),('hk','HK'),('jp','JP'),(' sg ','SG'),(' Jp ','JP'),('🇯🇵JP','JP'),('🇨🇳CN','CN'),('🇯🇵','JP')]:
            with self.subTest(raw=raw):
                self.assertEqual(checker._country_for_ip(Reader(raw),'192.0.2.1','US'),(code,'geoip.metadb'))
    def test_lists_dicts_and_field_provenance(self):
        for record in [['us','google'],{'country':{'iso_code':'US'}},{'registered_country':{'iso_code':'US'}}]:
            self.assertEqual(geo.country_for_ip(Reader(record),'test','JP'),('US','geoip.metadb'))
        result=geo.country_for_ip_details(Reader({'registered_country':{'iso_code':'US'}}),'test','JP')
        self.assertEqual(result['country_field'],'registered_country.iso_code')
    def test_noise_invalid_codes_and_conflicts(self):
        for value in ['private','cloudflare','test-network','EU','AP','A1','A2','ZZ','IP','AS13335','🇯🇵US','foo-US',None,12]:
            with self.subTest(value=value): self.assertEqual(geo.normalize_country_code(value),'')
        for value in ['HK','MO','TW','XK','AX','BQ']:
            self.assertEqual(geo.normalize_country_code(value),value)
    def test_no_silent_fallback_and_error_reasons(self):
        class Broken:
            def get(self,ip): raise ValueError('bad')
        for reader,status in [(Reader(None),'db_no_match'),(Reader(123),'unsupported_record_type'),(Reader('private'),'invalid_country_code'),(Broken(),'db_lookup_error')]:
            result=geo.country_for_ip_details(reader,'test','JP')
            self.assertEqual(result['country_code'],'');self.assertEqual(result['country_status'],status)
        self.assertEqual(geo.country_for_ip(None,'test','jp'),('JP','cloudflare-trace-loc'))
    def test_shared_identity_matches_state(self):
        proxy=node();self.assertEqual(checker.clash_state_key(proxy)[3],geo.proxy_identity_hash(proxy))
        renamed=dict(proxy,name='🇺🇸renamed');self.assertEqual(geo.proxy_identity_hash(proxy),geo.proxy_identity_hash(renamed))
        changed=dict(proxy,password='changed');self.assertNotEqual(geo.proxy_identity_hash(proxy),geo.proxy_identity_hash(changed))

class CountryPolicyTests(unittest.TestCase):
    def test_partition_unknown_and_real_exit_not_name(self):
        nodes=[node('🇯🇵advertised'),node('unknown','other.test')]
        doc={'proxies':nodes,'proxy-groups':[{'name':'Service','type':'select','proxies':['🇭🇰 stale','DIRECT']}]}
        fixed,stats=policy.normalize_doc(doc,doc,metadata(nodes,['US','']),NOW)
        groups={g['name']:g for g in fixed['proxy-groups']}
        self.assertEqual(groups['🇺🇸 美国自动']['proxies'],['🇯🇵advertised'])
        self.assertEqual(groups[policy.UNKNOWN]['proxies'],['unknown'])
        self.assertEqual(stats['unknown_reasons'],{'db_no_match':1})
        self.assertIn(policy.UNKNOWN,groups[policy.BASE[0]]['proxies'])
        self.assertNotIn('🇭🇰 stale',groups['Service']['proxies'])
        self.assertEqual(stats['coverage'],.5)
    def test_every_node_identified_has_no_unknown_group(self):
        nodes=[node()];doc={'proxies':nodes};result,stats=policy.normalize_doc(doc,doc,metadata(nodes,['JP']),NOW)
        self.assertNotIn(policy.UNKNOWN,[g['name'] for g in result['proxy-groups']]);self.assertEqual(stats['coverage'],1)
    def test_unlabelled_valid_country_uses_code(self):
        nodes=[node()];doc={'proxies':nodes};result,_=policy.normalize_doc(doc,doc,metadata(nodes,['AX']),NOW)
        self.assertTrue(any(g['name']=='🇦🇽 AX自动' for g in result['proxy-groups']))
    def test_metadata_age_database_and_missing_identity(self):
        proxy=node();meta=metadata([proxy],['US'])
        self.assertEqual(policy.classify(proxy,meta,NOW+timedelta(hours=25),24)[1],'expired_verification')
        meta['geo_verification']={'database_sha256':'old'}
        self.assertEqual(policy.classify(proxy,meta,NOW,24,'new')[1],'database_changed')
        self.assertEqual(policy.classify(node(server='changed.test'),meta,NOW,24)[1],'missing_verification')
        meta['generated_at']='invalid';self.assertEqual(policy.classify(proxy,meta,NOW,24)[1],'missing_verification_time')
    def test_renormalization_idempotent(self):
        nodes=[node(),node('unknown','other.test')];doc={'proxies':nodes};meta=metadata(nodes,['US',''])
        once,_=policy.normalize_doc(doc,doc,meta,NOW)
        twice,_=policy.normalize_doc(once,once,meta,NOW)
        self.assertEqual(once,twice)
    def test_duplicate_and_collision_rejected(self):
        for nodes in [[node(),node()],[node(policy.BASE[0])]]:
            doc={'proxies':nodes}
            with self.assertRaises(ValueError): policy.normalize_doc(doc,doc,{},NOW)
    def test_empty_subscription_still_has_nonempty_policy_choices(self):
        doc={'proxies':[]};result,stats=policy.normalize_doc(doc,doc,{},NOW)
        self.assertIsNone(stats['coverage']);self.assertTrue(all(g['proxies'] for g in result['proxy-groups']))
    def fixture(self,root,identified=True):
        nodes=[node()]
        for sub in ['sub','sub/merged','sub/alive']:
            path=root/sub;path.mkdir(parents=True)
            (path/'clash.yaml').write_text(yaml.safe_dump({'proxies':nodes}))
            (path/'meta.json').write_text('{}')
        meta=metadata(nodes,['US' if identified else ''])
        (root/'sub/alive/meta.json').write_text(json.dumps(meta))
    def test_cli_engine_updates_three_outputs_and_provenance(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            with contextlib.redirect_stdout(io.StringIO()): summary=policy.run(root,fresh=False,now=NOW)
            self.assertEqual(len(summary),3)
            for stats in summary.values():
                self.assertTrue(stats['partition_validated']);self.assertTrue(stats['verification_reused']);self.assertEqual(stats['coverage'],1)
            self.assertIn('policy_normalization',json.loads((root/'sub/alive/meta.json').read_text()))
    def test_coverage_failure_does_not_overwrite_any_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root,False)
            before={p:p.read_bytes() for p in root.rglob('*') if p.is_file()}
            with patch.dict(os.environ,{},clear=True):
                with self.assertRaises(ValueError): policy.run(root,fresh=True,fail_low=True,now=NOW)
            self.assertEqual(before,{p:p.read_bytes() for p in before})
    def test_fresh_run_id_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            with patch.dict(os.environ,{'GITHUB_RUN_ID':'new','GITHUB_RUN_ATTEMPT':'1'}):
                with self.assertRaises(ValueError): policy.run(root,fresh=True,now=NOW)

if __name__=='__main__': unittest.main()
