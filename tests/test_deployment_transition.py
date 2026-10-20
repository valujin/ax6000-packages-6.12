"""Only the recorded signed predecessor is a retryable Pages transition."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

spec=importlib.util.spec_from_file_location('deployment_transition',Path(__file__).resolve().parents[1]/'scripts/channel-snapshot.py')
snapshot=importlib.util.module_from_spec(spec);spec.loader.exec_module(snapshot)
NAMES=('site-state.json','site-state.sig')
OLD=(b'{"generation":"old signed state"}',b'old authenticated signature\n')
NEW=(b'{"generation":"new signed state"}',b'new authenticated signature\n')


def hashes(pair):return {name:hashlib.sha256(body).hexdigest() for name,body in zip(NAMES,pair)}


class DeploymentTransition(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.file=Path(self.tmp.name)/'check.json'
        self.record={'schema_version':1,'site_url':'https://fixture.github.io/repo','before':hashes(OLD),'after':hashes(NEW)}
        self.now=0

    def run_check(self,responses,phase='after'):
        self.file.write_text(json.dumps(self.record));original=self.file.read_bytes()
        self.sleep=[]
        def pause(seconds):self.sleep.append(seconds);self.now+=seconds
        def response(request,**kwargs):
            item=next(responses)
            if isinstance(item,Exception):raise item
            return io.BytesIO(item)
        with patch.object(urllib.request,'urlopen',side_effect=response) as network, \
             patch.object(time,'sleep',side_effect=pause),patch.object(time,'monotonic',side_effect=lambda:self.now):
            try:snapshot.verify_deployment(self.file,phase)
            finally:
                self.network_calls=network.call_count
                self.assertEqual(self.file.read_bytes(),original,'Expectation record was changed')

    def test_old_then_mixed_then_both_after_succeeds(self):
        self.run_check(iter((*OLD,OLD[0],NEW[1],*NEW)))
        self.assertEqual(self.sleep,[5,5]);self.assertEqual(self.network_calls,6)

    def test_persistent_old_has_twelve_attempts_eleven_waits(self):
        with self.assertRaisesRegex(ValueError,'expectation'):
            self.run_check(iter(OLD*12))
        self.assertEqual(self.network_calls,24);self.assertEqual(self.sleep,[5]*11);self.assertEqual(self.now,55)

    def test_before_remains_one_strict_attempt(self):
        self.run_check(iter(OLD),phase='before')
        self.assertEqual(self.sleep,[]);self.assertEqual(self.network_calls,2)
        with self.assertRaises(ValueError):self.run_check(iter((NEW[0],)),phase='before')
        self.assertEqual(self.sleep,[]);self.assertEqual(self.network_calls,1)

    def test_unknown_state_or_signature_fails_immediately(self):
        for responses in ((b'foreign state',),(OLD[0],b'foreign signature')):
            with self.subTest(responses=responses),self.assertRaises(ValueError):self.run_check(iter(responses))
            self.assertEqual(self.sleep,[]);self.assertEqual(self.network_calls,len(responses))

    def test_oversized_body_fails_without_retry(self):
        with self.assertRaises(ValueError):self.run_check(iter((b'x'*(1024**2+1),)))
        self.assertEqual(self.sleep,[]);self.assertEqual(self.network_calls,1)

    def test_bootstrap_absence_then_mixed_then_new_succeeds(self):
        self.record['before']=None
        missing=lambda:urllib.error.HTTPError('https://fixture.github.io/repo',404,'missing',{},None)
        self.run_check(iter((missing(),missing(),NEW[0],missing(),*NEW)))
        self.assertEqual(self.sleep,[5,5]);self.assertEqual(self.network_calls,6)

    def test_nonbootstrap_404_or_any_other_http_error_is_not_retried(self):
        for status in (404,403,502):
            with self.subTest(status=status),self.assertRaises(urllib.error.HTTPError):
                self.run_check(iter((urllib.error.HTTPError('https://fixture.github.io/repo',status,'failure',{},None),)))
            self.assertEqual(self.sleep,[])

    def test_bootstrap_before_requires_both_absent(self):
        self.record['before']=None
        missing=lambda:urllib.error.HTTPError('https://fixture.github.io/repo',404,'missing',{},None)
        self.run_check(iter((missing(),missing())),phase='before')
        with self.assertRaises(ValueError):self.run_check(iter((missing(),NEW[1])),phase='before')
        self.assertEqual(self.sleep,[])

    def test_malformed_expectation_rejected_before_network(self):
        for field,value in (('after',None),('before',{'site-state.json':'0'*64}),('after',dict(hashes(NEW),**{'site-state.sig':'not a digest'}))):
            self.record={'schema_version':1,'site_url':'https://fixture.github.io/repo','before':hashes(OLD),'after':hashes(NEW)}
            self.record[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):self.run_check(iter(()))
            self.assertEqual(self.network_calls,0)

    def test_known_transition_responses_still_respect_sixty_second_deadline(self):
        self.file.write_text(json.dumps(self.record));clock=[0];calls=[];sleeps=[]
        def response(request,**kwargs):
            calls.append(kwargs['timeout']);clock[0]+=20
            return io.BytesIO(OLD[(len(calls)-1)%2])
        def pause(seconds):sleeps.append(seconds);clock[0]+=seconds
        with patch.object(urllib.request,'urlopen',side_effect=response),patch.object(time,'monotonic',side_effect=lambda:clock[0]),patch.object(time,'sleep',side_effect=pause):
            with self.assertRaises(ValueError):snapshot.verify_deployment(self.file,'after')
        self.assertLessEqual(len(calls),3);self.assertEqual(calls[-1],15)
        self.assertEqual(sleeps,[5])
