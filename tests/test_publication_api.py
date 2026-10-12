import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import urllib.error
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/'scripts/publication_api.py'
if SCRIPT.exists():
    spec=importlib.util.spec_from_file_location('api_under_test',SCRIPT);api=importlib.util.module_from_spec(spec);spec.loader.exec_module(api)
else:api=None


class ImmutableReleaseAPI(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(api,'shared immutable release API implementation is missing')
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.asset=self.root/'channel.tar.zst';self.asset.write_bytes(b'bounded fixture bytes')
        self.client=api.ReleaseAPI('fixture/ax6000-packages-6.12','secret-not-logged')
        self.plan={'tag':'packages-recommended-'+'a'*64,'recipe_commit':'b'*40,
                   'assets':[{'name':self.asset.name,'path':str(self.asset),'size':self.asset.stat().st_size,'sha256':api.sha256_file(self.asset)}]}
        self.release={'id':12,'tag_name':self.plan['tag'],'draft':False,'immutable':True,
                      'assets':[{'id':15,'name':self.asset.name,'size':self.asset.stat().st_size,'digest':'sha256:'+api.sha256_file(self.asset),'state':'uploaded','updated_at':'now'}]}

    def test_exact_immutable_release_reused_without_mutation(self):
        with patch.object(self.client,'get_release',return_value=self.release),patch.object(self.client,'resolve_tag_commit',return_value=self.plan['recipe_commit']),patch.object(self.client,'request') as mutate:
            self.assertEqual(self.client.publish_release(self.plan)['id'],12)
            mutate.assert_not_called()

    def test_wrong_tag_target_or_digest_rejects_existing_release(self):
        for field in ('target','digest'):
            release=copy.deepcopy(self.release)
            if field=='digest':release['assets'][0]['digest']='sha256:'+'0'*64
            target='c'*40 if field=='target' else self.plan['recipe_commit']
            with patch.object(self.client,'get_release',return_value=release),patch.object(self.client,'resolve_tag_commit',return_value=target):
                with self.assertRaises(ValueError):self.client.publish_release(self.plan)

    def test_foreign_draft_never_overwritten(self):
        release=copy.deepcopy(self.release);release['draft']=True;release['immutable']=False
        with patch.object(self.client,'get_release',return_value=release),patch.object(self.client,'request') as mutate:
            with self.assertRaises(ValueError):self.client.publish_release(self.plan)
            mutate.assert_not_called()

    def test_local_asset_drift_rejects_before_remote_calls(self):
        self.asset.write_bytes(b'drift')
        with patch.object(self.client,'get_release') as remote:
            with self.assertRaises(ValueError):self.client.publish_release(self.plan)
            remote.assert_not_called()

    def test_upload_streams_bounded_chunks_and_checks_response(self):
        self.asset.write_bytes(b'x'*(2*1024**2+31))
        asset=dict(self.plan['assets'][0],size=self.asset.stat().st_size,sha256=api.sha256_file(self.asset))
        release={'id':12,'upload_url':'https://uploads.github.com/repos/fixture/ax6000-packages-6.12/releases/12/assets{?name,label}'}
        sent=[];headers={}
        class Response:
            status=201
            def read(_self,_bound):return json.dumps({'name':asset['name'],'state':'uploaded','size':asset['size'],'digest':'sha256:'+asset['sha256']}).encode()
        class Connection:
            def __init__(_self,host,timeout):self.assertEqual(host,'uploads.github.com')
            def putrequest(_self,method,path):self.assertEqual(method,'POST');self.assertIn('/releases/12/assets?',path)
            def putheader(_self,name,value):headers[name]=value
            def endheaders(_self):pass
            def send(_self,data):sent.append(data)
            def getresponse(_self):return Response()
            def close(_self):pass
        with patch.object(api.http.client,'HTTPSConnection',Connection):self.client.upload_asset(release,asset)
        self.assertEqual(b''.join(sent),self.asset.read_bytes())
        self.assertEqual([len(x) for x in sent],[1024**2,1024**2,31])
        self.assertEqual(headers['Content-Length'],str(asset['size']))
        self.assertEqual(headers['Authorization'],'Bearer secret-not-logged')

    def test_publish_uploads_final_catalog_before_freezing_draft(self):
        extra=self.root/'downloads.json';extra.write_bytes(b'signed catalog fixture')
        record={'name':extra.name,'path':str(extra),'size':extra.stat().st_size,'sha256':api.sha256_file(extra)}
        draft=copy.deepcopy(self.release);draft.update(draft=True,immutable=False)
        full=copy.deepcopy(draft);full['assets'].append({'id':16,'name':record['name'],'size':record['size'],'digest':'sha256:'+record['sha256'],'state':'uploaded'})
        published=copy.deepcopy(full);published.update(draft=False,immutable=True)
        uploaded=[];mutations=[]
        def request(method,endpoint,body=None,**_kwargs):
            if method=='GET' and endpoint=='/immutable-releases':return {'enabled':True}
            mutations.append((method,endpoint,body))
            if method=='POST':
                self.assertTrue(body['draft']);return dict(draft,upload_url='unused-by-stub')
            self.assertEqual(uploaded,[self.asset.name,extra.name]);return None
        def finalize(release,*,reuse):
            self.assertFalse(reuse);self.assertEqual([a['name'] for a in release['assets']],[self.asset.name]);return [record]
        with patch.object(self.client,'get_release',side_effect=[None,draft,full,published]), \
             patch.object(self.client,'resolve_tag_commit',side_effect=[None,self.plan['recipe_commit']]), \
             patch.object(self.client,'request',side_effect=request), \
             patch.object(self.client,'upload_asset',side_effect=lambda _release,asset:uploaded.append(asset['name'])):
            self.client.publish_release(self.plan,finalize)
        self.assertEqual([entry[0] for entry in mutations],['POST','PATCH'])
        self.assertEqual(mutations[-1][2],{'draft':False})

    def test_foreign_existing_tag_refuses_before_draft_creation(self):
        with patch.object(self.client,'get_release',return_value=None), \
             patch.object(self.client,'resolve_tag_commit',return_value='0'*40), \
             patch.object(self.client,'request') as mutate:
            with self.assertRaisesRegex(ValueError,'Existing tag'):self.client.publish_release(self.plan)
            mutate.assert_not_called()

    def test_stable_release_identity_ignores_download_counts_only(self):
        other=copy.deepcopy(self.release);other['assets'][0]['download_count']=23
        self.assertEqual(api.release_identity(self.release),api.release_identity(other))
        other['assets'][0]['updated_at']='changed'
        self.assertNotEqual(api.release_identity(self.release),api.release_identity(other))

    def test_incomplete_assets_and_mutable_release_rejected(self):
        for change in ('missing','mutable','duplicate','state'):
            release=copy.deepcopy(self.release)
            if change=='missing':release['assets']=[]
            elif change=='mutable':release['immutable']=False
            elif change=='duplicate':release['assets']*=2
            else:release['assets'][0]['state']='starter'
            with self.assertRaises(ValueError):self.client.verify_assets(release,self.plan['assets'])



class ExplicitDraftResume(unittest.TestCase):
    def setUp(self):
        ImmutableReleaseAPI.setUp(self)
        second=self.root/'profile.json';second.write_bytes(b'exact profile bytes')
        self.second={'name':second.name,'path':str(second),'size':second.stat().st_size,'sha256':api.sha256_file(second)}
        self.plan['assets'].append(self.second)
        self.draft=copy.deepcopy(self.release)
        self.draft.update(draft=True,immutable=False,target_commitish=self.plan['recipe_commit'])
        self.complete=copy.deepcopy(self.draft)
        self.complete['assets'].append({'id':16,'name':self.second['name'],'size':self.second['size'],
                                       'digest':'sha256:'+self.second['sha256'],'state':'uploaded','updated_at':'now'})
        self.published=copy.deepcopy(self.complete);self.published.update(draft=False,immutable=True)

    def test_resume_uploads_only_missing_and_publishes_exact_selected_draft(self):
        mutations=[];uploads=[]
        def request(method,endpoint,body=None,**kwargs):
            if method=='GET':return {'enabled':True}
            mutations.append((method,endpoint,body))
        with patch.object(self.client,'get_release',side_effect=[self.draft,self.complete,self.complete,self.published]), \
             patch.object(self.client,'resolve_tag_commit',side_effect=[None,None,self.plan['recipe_commit']]), \
             patch.object(self.client,'request',side_effect=request), \
             patch.object(self.client,'upload_asset',side_effect=lambda release,record:uploads.append(record['name'])):
            self.assertEqual(self.client.resume_draft(self.plan,12)['id'],12)
        self.assertEqual(uploads,['profile.json'])
        self.assertEqual(mutations,[('PATCH','/releases/12',{'draft':False})])

    def test_resume_validates_core_then_signs_uploads_catalog_before_publication(self):
        extra=self.root/'downloads.json';extra.write_bytes(b'exact signed catalog fixture')
        record={'name':extra.name,'path':str(extra),'size':extra.stat().st_size,'sha256':api.sha256_file(extra)}
        full=copy.deepcopy(self.complete);full['assets'].append({'id':17,'name':record['name'],'size':record['size'],
                                                               'digest':'sha256:'+record['sha256'],'state':'uploaded'})
        published=copy.deepcopy(full);published.update(draft=False,immutable=True)
        uploads=[]
        def finalize(release,*,reuse):
            self.assertFalse(reuse);self.assertEqual({a['name'] for a in release['assets']},{a['name'] for a in self.plan['assets']})
            return [record]
        def request(method,endpoint,body=None,**kwargs):
            if method=='GET':return {'enabled':True}
            self.assertEqual(uploads,['profile.json','downloads.json']);self.assertEqual(body,{'draft':False})
        with patch.object(self.client,'get_release',side_effect=[self.draft,self.complete,full,published]), \
             patch.object(self.client,'resolve_tag_commit',side_effect=[None,None,self.plan['recipe_commit']]), \
             patch.object(self.client,'request',side_effect=request), \
             patch.object(self.client,'upload_asset',side_effect=lambda release,record:uploads.append(record['name'])):
            self.client.resume_draft(self.plan,12,finalize=finalize)

    def test_draft_identity_and_existing_asset_drift_reject_before_any_write(self):
        cases=[]
        for key,value in [('id',13),('tag_name','foreign'),('target_commitish','c'*40),('draft',False),('immutable',True)]:
            r=copy.deepcopy(self.draft);r[key]=value;cases.append(r)
        for key,value in [('digest','sha256:'+'0'*64),('size',999),('state','starter')]:
            r=copy.deepcopy(self.draft);r['assets'][0][key]=value;cases.append(r)
        r=copy.deepcopy(self.draft);r['assets'][0]['name']='foreign.bin';cases.append(r)
        r=copy.deepcopy(self.draft);r['assets']*=2;cases.append(r)
        for release in cases:
            with self.subTest(release=release),patch.object(self.client,'get_release',return_value=release), \
                 patch.object(self.client,'resolve_tag_commit',return_value=None), \
                 patch.object(self.client,'request',return_value={'enabled':True}) as request, \
                 patch.object(self.client,'upload_asset') as upload:
                with self.assertRaises(ValueError):self.client.resume_draft(self.plan,12)
                upload.assert_not_called()
                self.assertTrue(all(c.args[0]=='GET' for c in request.call_args_list))

    def test_foreign_tag_or_disabled_immutability_rejects_without_upload(self):
        for target,enabled in [('c'*40,True),(None,False)]:
            with patch.object(self.client,'get_release',return_value=self.draft), \
                 patch.object(self.client,'resolve_tag_commit',return_value=target), \
                 patch.object(self.client,'request',return_value={'enabled':enabled}) as request, \
                 patch.object(self.client,'upload_asset') as upload:
                with self.assertRaises(ValueError):self.client.resume_draft(self.plan,12)
                upload.assert_not_called()
                self.assertTrue(all(c.args[0]=='GET' for c in request.call_args_list))

    def test_changed_draft_identity_or_original_asset_id_rejects_before_freeze(self):
        changes=[('tag_name','foreign'),('id',13),('target_commitish','c'*40),('draft',False),('immutable',True)]
        for stage in ('core','final'):
            cases=[]
            for key,value in changes:
                r=copy.deepcopy(self.complete);r[key]=value;cases.append(r)
            for key,value in [('id',999),('updated_at','changed'),('digest','sha256:'+'0'*64)]:
                r=copy.deepcopy(self.complete);r['assets'][0][key]=value;cases.append(r)
            for drift in cases:
                returned=[self.draft,drift] if stage=='core' else [self.draft,self.complete,drift]
                with self.subTest(stage=stage,drift=drift),patch.object(self.client,'get_release',side_effect=returned), \
                     patch.object(self.client,'resolve_tag_commit',return_value=None), \
                     patch.object(self.client,'request',return_value={'enabled':True}) as request, \
                     patch.object(self.client,'upload_asset'):
                    with self.assertRaises(ValueError):self.client.resume_draft(self.plan,12)
                    self.assertTrue(all(c.args[0]=='GET' for c in request.call_args_list))

    def test_tag_drift_or_immutability_disable_after_upload_prevents_freeze(self):
        for targets,settings in [([None,'c'*40],[{'enabled':True}]),([None,None],[{'enabled':True},{'enabled':False}])]:
            with patch.object(self.client,'get_release',side_effect=[self.draft,self.complete,self.complete]), \
                 patch.object(self.client,'resolve_tag_commit',side_effect=targets), \
                 patch.object(self.client,'request',side_effect=settings) as request, \
                 patch.object(self.client,'upload_asset'):
                with self.assertRaises(ValueError):self.client.resume_draft(self.plan,12)
                self.assertTrue(all(c.args[0]=='GET' for c in request.call_args_list))

    def test_case_insensitive_local_asset_collision_fails_before_api(self):
        alias=dict(self.plan['assets'][0],name=self.plan['assets'][0]['name'].upper())
        plan=dict(self.plan,assets=[self.plan['assets'][0],alias])
        with patch.object(self.client,'get_release') as remote:
            with self.assertRaisesRegex(ValueError,'Duplicate'):self.client.resume_draft(plan,12)
            remote.assert_not_called()

class ImmutableSettingsPrivileges(unittest.TestCase):
    def setUp(self):
        ImmutableReleaseAPI.setUp(self)
        self.draft = copy.deepcopy(self.release)
        self.draft.update(draft=True, immutable=False, target_commitish=self.plan['recipe_commit'])

    def test_request_error_reports_only_method_endpoint_and_status(self):
        error = urllib.error.HTTPError(self.client.base + '/immutable-releases', 403,
            'private response text', {'Authorization': 'Bearer secret-not-logged'}, None)
        with patch.object(api.urllib.request, 'urlopen', side_effect=error):
            with self.assertRaises(api.APIRequestError) as captured:
                self.client.request('GET', '/immutable-releases')
        failure = captured.exception
        self.assertEqual((failure.method, failure.endpoint, failure.status), ('GET', '/immutable-releases', 403))
        self.assertIn('GET /immutable-releases', str(failure))
        self.assertIn('HTTP 403', str(failure))
        self.assertNotIn('secret-not-logged', str(failure))
        self.assertNotIn('private response text', str(failure))
        with patch.object(api.urllib.request, 'urlopen', side_effect=urllib.error.HTTPError(
                self.client.base + '/releases/999', 404, 'missing', {}, None)):
            self.assertIsNone(self.client.request('GET', '/releases/999', missing_ok=True))

    def test_known_settings_true_and_false_are_distinct_from_exact_403_unknown(self):
        with patch.object(self.client, 'request', return_value={'enabled': True}):
            self.assertIs(self.client.immutable_preflight(), True)
        with patch.object(self.client, 'request', return_value={'enabled': False}):
            with self.assertRaises(ValueError): self.client.immutable_preflight()
        with patch.object(self.client, 'request', side_effect=api.APIRequestError('GET', '/immutable-releases', 403)):
            self.assertIsNone(self.client.immutable_preflight())

    def test_other_errors_and_malformed_settings_fail_before_draft_creation(self):
        failures = [api.APIRequestError('GET', '/immutable-releases', status) for status in (401, 404, 429, 500)]
        failures += [api.APIRequestError('GET', '/releases', 403),
                     api.APIRequestError('POST', '/immutable-releases', 403), ValueError('generic error')]
        for failure in failures:
            writes = []
            def request(method, endpoint, body=None, **kwargs):
                if method != 'GET': writes.append((method, endpoint))
                raise failure
            with self.subTest(failure=str(failure)), patch.object(self.client, 'get_release', return_value=None), \
                 patch.object(self.client, 'resolve_tag_commit', return_value=None), \
                 patch.object(self.client, 'request', side_effect=request):
                with self.assertRaises(ValueError): self.client.publish_release(self.plan)
                self.assertEqual(writes, [])
        for settings in ({'enabled': False}, {'enabled': 1}, {}, None):
            with self.subTest(settings=settings), patch.object(self.client, 'get_release', return_value=None), \
                 patch.object(self.client, 'resolve_tag_commit', return_value=None), \
                 patch.object(self.client, 'request', return_value=settings) as request:
                with self.assertRaises(ValueError): self.client.publish_release(self.plan)
                self.assertTrue(all(call.args[0] == 'GET' for call in request.call_args_list))

    def test_unknown_settings_allows_publish_only_with_actual_immutable_final_release(self):
        for immutable in (True, False, None):
            published = copy.deepcopy(self.release)
            published['immutable'] = immutable
            writes = []; pointer = self.root / ('pointer-' + str(immutable) + '.json')
            def request(method, endpoint, body=None, **kwargs):
                if method == 'GET' and endpoint == '/immutable-releases':
                    raise api.APIRequestError(method, endpoint, 403)
                writes.append((method, endpoint, body))
                if method == 'POST': return self.draft
            with self.subTest(immutable=immutable), patch.object(self.client, 'get_release',
                    side_effect=[None, self.draft, self.draft, published]), \
                 patch.object(self.client, 'resolve_tag_commit', side_effect=[None, self.plan['recipe_commit']]), \
                 patch.object(self.client, 'request', side_effect=request), patch.object(self.client, 'upload_asset'):
                def publish_and_point():
                    result = self.client.publish_release(self.plan)
                    pointer.write_text(json.dumps({'release_id': result['id']}))
                if immutable is True:
                    publish_and_point(); self.assertTrue(pointer.is_file())
                else:
                    with self.assertRaises(ValueError): publish_and_point()
                    self.assertFalse(pointer.exists(), 'Mutable release must never produce an authoritative pointer')
                self.assertEqual([m[0] for m in writes], ['POST', 'PATCH'])

    def test_resume_unknown_settings_preserves_assets_and_checks_final_immutable_flag(self):
        for immutable in (True, False):
            published = copy.deepcopy(self.release); published['immutable'] = immutable
            writes = []
            def request(method, endpoint, body=None, **kwargs):
                if method == 'GET' and endpoint == '/immutable-releases':
                    raise api.APIRequestError(method, endpoint, 403)
                writes.append((method, endpoint, body))
            with self.subTest(immutable=immutable), patch.object(self.client, 'get_release',
                    side_effect=[self.draft, self.draft, self.draft, published]), \
                 patch.object(self.client, 'resolve_tag_commit', side_effect=[None, None, self.plan['recipe_commit']]), \
                 patch.object(self.client, 'request', side_effect=request), patch.object(self.client, 'upload_asset') as upload:
                if immutable:
                    self.assertEqual(self.client.resume_draft(self.plan, 12)['id'], 12)
                else:
                    with self.assertRaises(ValueError): self.client.resume_draft(self.plan, 12)
                upload.assert_not_called()
                self.assertEqual(writes, [('PATCH', '/releases/12', {'draft': False})])

if __name__=='__main__':unittest.main()
