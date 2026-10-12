import copy
import importlib.util
import json
from pathlib import Path
import tempfile
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


if __name__=='__main__':unittest.main()
