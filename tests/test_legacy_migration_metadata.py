"""Actual legacy metadata shape; mocked transport never authorizes migration."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

from test_channel_snapshot import ROOT, snapshot

FIXTURE=ROOT/'tests/fixtures/legacy-rec-migration'
sha=lambda value:hashlib.sha256(value).hexdigest()


class LegacyMigrationMetadata(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.old=self.root/'signed-old';self.new=self.root/'raw-new'
        self.old.mkdir();self.new.mkdir()
        self.manifest=gzip.decompress((FIXTURE/'firmware-manifest.json.gz').read_bytes())
        self.assertEqual(sha(self.manifest),'a83b1a64183353df18a098f3487bfe7cde01d32b37665235ff96190613c70813')
        self.catalog=gzip.decompress((FIXTURE/'downloads.json.gz').read_bytes())
        (self.old/'downloads.json').write_bytes(self.catalog)
        (self.old/'downloads.sig').write_bytes((FIXTURE/'downloads.sig').read_bytes())
        old=json.loads(self.manifest);new=copy.deepcopy(old);new['build_id']='fixture-successor'
        data=(json.dumps(new)+'\n').encode();(self.new/'firmware-manifest.json').write_bytes(data)
        self.proof={'schema_version':2,'predecessor_build_id':old['build_id'],'successor_build_id':new['build_id'],
                    'source_commit':old['source_commit'],'kernel_version':old['kernel_version'],
                    'source_patches':{'before':old['source_patches'],'after':old['source_patches']},
                    'firmware_manifest_sha256':{'before':sha(self.manifest),'after':sha(data)}}
        catalog=json.loads(self.catalog);self.commit=catalog['release']['recipe_commit']
        self.release={'id':catalog['release']['id'],'tag_name':catalog['release']['tag'],
                      'draft':False,'immutable':True,'assets':[{'name':'firmware-manifest.json','id':660866656,
                      'state':'uploaded','size':len(self.manifest),'digest':'sha256:'+sha(self.manifest),'updated_at':'unchanged'}]}
        self.requests=[];self.gets=0;self.change_after=None;self.payload=self.manifest
        outer=self
        class API:
            def __init__(self,repository):outer.assertEqual(repository,'valujin/ax6000-packages-6.12')
            def get_release(self,identity):
                outer.assertEqual(identity,419005116);outer.gets+=1
                value=copy.deepcopy(outer.release)
                if outer.gets%2==0 and outer.change_after:outer.change_after(value)
                return value
            def resolve_tag_commit(self,tag):return outer.commit
            def download_asset(self,release,asset,destination,digest,size):
                outer.requests.append((release['id'],asset['name'],digest,size))
                Path(destination).write_bytes(outer.payload)
        self.transport=types.SimpleNamespace(ReleaseAPI=API,release_identity=snapshot.module('publication_api').release_identity)
        self.validated=[]
        def payloads(trees,proof,read,transport,cache,budget):
            for phase,tree in trees:
                if sha((Path(tree)/'firmware-manifest.json').read_bytes()) != proof['firmware_manifest_sha256'][phase]:
                    raise ValueError('V2 migration native firmware manifest checksum differs')
            self.validated.append([(phase,str(tree)) for phase,tree in trees])
            self.assertEqual(read(Path(trees[0][1])/'firmware-manifest.json'),old)
            self.assertEqual((Path(trees[0][1])/'downloads.json').read_bytes(),self.catalog)
            self.assertEqual((Path(trees[0][1])/'downloads.sig').read_bytes(),(FIXTURE/'downloads.sig').read_bytes())
            self.assertIs(cache,snapshot._MIGRATION_IMAGE_CACHE)
            self.assertIs(budget,snapshot._MIGRATION_DOWNLOAD_BUDGET)
        self.kernel=types.SimpleNamespace(validate_payloads=payloads)
        snapshot._MIGRATION_DOWNLOAD_BUDGET['used']=0
        self.original_module=snapshot.module

    def validate(self):
        def module(name):
            return {'publication_api':self.transport,'kernel_migration':self.kernel}.get(name) or self.original_module(name)
        with patch.object(snapshot,'module',side_effect=module):
            snapshot.validate_migration_manifests(self.old,self.new,self.proof)

    def test_actual_signed_legacy_inventory_omits_manifest_and_resolves_without_altering_tree(self):
        raw=gzip.decompress((FIXTURE/'snapshot-manifest.json.gz').read_bytes())
        self.assertEqual(sha(raw),'ebb8dd5033ee8e4ec5e9d1bb5f5b186d41ef7c57b9858bd698fcaf4b2ba23311')
        inventory=json.loads(raw)['files'];self.assertEqual(len(inventory),1395)
        names={row['path'] for row in inventory};self.assertNotIn('firmware-manifest.json',names)
        self.assertTrue({'downloads.json','downloads.sig','profile.json'}<=names)
        for name in ('downloads.json','downloads.sig'):
            row=next(row for row in inventory if row['path']==name)
            self.assertEqual(sha((self.old/name).read_bytes()),row['sha256'])
        before={p.name:p.read_bytes() for p in self.old.iterdir()}
        self.validate();self.validate()
        self.assertEqual({p.name:p.read_bytes() for p in self.old.iterdir()},before)
        self.assertEqual(len(self.validated),2);self.assertEqual(len(self.requests),2)
        self.assertEqual(snapshot._MIGRATION_DOWNLOAD_BUDGET['used'],2*len(self.manifest))
        self.assertNotEqual(self.validated[0][0][1],str(self.old))
        self.assertFalse(Path(self.validated[0][0][1]).exists())

    def test_present_corrupt_linked_oversized_or_malformed_local_manifest_never_falls_back(self):
        path=self.old/'firmware-manifest.json'
        for payload in (b'{',self.manifest+b' ',b'x'*(8*1024**2+1)):
            path.write_bytes(payload)
            with self.subTest(size=len(payload)),self.assertRaises(ValueError):
                self.validate()
            self.assertEqual(self.requests,[])
        path.unlink();path.symlink_to(self.new/'firmware-manifest.json')
        with self.assertRaises(ValueError):self.validate()
        self.assertEqual(self.requests,[])

    def test_wrong_catalog_or_release_or_asset_fails_before_download(self):
        original=copy.deepcopy(self.release)
        changes=[lambda r:r.update(id=123),lambda r:r.update(draft=True),lambda r:r.update(immutable=False),
                 lambda r:r.update(tag_name='firmware-other'),lambda r:r['assets'][0].update(state='new'),
                 lambda r:r['assets'][0].update(digest='sha256:'+'0'*64),
                 lambda r:r['assets'][0].update(size=8*1024**2+1),
                 lambda r:r['assets'][0].update(size=0),lambda r:r['assets'][0].update(id=True),
                 lambda r:r['assets'][0].update(name='foreign-manifest.json'),
                 lambda r:r['assets'].append(copy.deepcopy(r['assets'][0]))]
        for change in changes:
            self.release=copy.deepcopy(original);change(self.release)
            with self.subTest(change=change),self.assertRaises(ValueError):self.validate()
            self.assertEqual(self.requests,[])
        self.release=original;self.commit='0'*40
        with self.assertRaises(ValueError):self.validate()
        self.assertEqual(self.requests,[])
        for field,value in [('repository','foreign/repo'),('id',True),('tag','firmware-other'),('recipe_commit','bad')]:
            catalog=json.loads(self.catalog);catalog['release'][field]=value
            (self.old/'downloads.json').write_text(json.dumps(catalog))
            with self.subTest(field=field),self.assertRaises(ValueError):self.validate()
            self.assertEqual(self.requests,[])

    def test_transport_wrong_bytes_changed_release_and_budget_fail_closed(self):
        self.payload=self.manifest+b'!'
        with self.assertRaises(ValueError):self.validate()
        self.payload=b'{'
        with self.assertRaises(ValueError):self.validate()
        self.payload=self.manifest;self.change_after=lambda r:r['assets'][0].update(updated_at='changed')
        with self.assertRaises(ValueError):self.validate()
        self.assertEqual(self.validated,[])
        snapshot._MIGRATION_DOWNLOAD_BUDGET['used']=512*1024**2
        before=len(self.requests)
        with self.assertRaises(ValueError):self.validate()
        self.assertEqual(len(self.requests),before)

    def test_v1_or_missing_successor_never_uses_legacy_download_fallback(self):
        self.proof['schema_version']=1
        with self.assertRaises(ValueError):self.validate()
        self.assertEqual(self.requests,[])
        self.proof['schema_version']=2;(self.old/'firmware-manifest.json').write_bytes(self.manifest)
        (self.new/'firmware-manifest.json').unlink()
        with self.assertRaises(ValueError):self.validate()
        self.assertEqual(self.requests,[])


if __name__=='__main__':unittest.main()
