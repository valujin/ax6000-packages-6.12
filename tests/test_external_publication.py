import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import test_channel_snapshot as fixtures
USIGN, ROOT = fixtures.USIGN, fixtures.ROOT


@unittest.skipUnless(USIGN,'Real usign required')
class ExternalPublication(unittest.TestCase):
    setUp = fixtures.ChannelSnapshots.setUp
    channel = fixtures.ChannelSnapshots.channel
    sign = fixtures.ChannelSnapshots.sign

    def publish(self, tree, output, release):
        metadata = self.root/'generation.json'
        metadata.write_text(json.dumps(release))
        return subprocess.run(['python3',str(ROOT/'scripts/publish.py'),'--profile',str(tree/'profile.json'),
            '--input',str(tree),'--output',str(output),'--key',str(self.key),'--public-key',str(self.public),
            '--usign',USIGN,'--lock',str(tree/'state/lock.json'),'--external-assets',str(tree/'downloads.json'),
            '--external-assets-signature',str(tree/'downloads.sig'),'--generation-release-metadata',str(metadata)],capture_output=True,text=True)

    def metadata(self, tree):
        catalog=json.loads((tree/'downloads.json').read_text())
        return {'id':catalog['release']['id'],'tag_name':catalog['release']['tag'],'draft':False,'immutable':True,
            'assets':[{'id':x['asset_id'],'name':x['filename'],'size':x['size'],'state':'uploaded',
                       'updated_at':x['updated_at'],'digest':'sha256:'+x['sha256']} for x in catalog['assets']]}

    def test_signed_external_catalog_publishes_feed_without_firmware_copy(self):
        tree,profile=self.channel('recommended');output=self.root/'publication'
        result=self.publish(tree,output,self.metadata(tree))
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((output/'downloads.json').read_bytes(),(tree/'downloads.json').read_bytes())
        self.assertFalse((output/'firmware').exists())
        feed=output/'feeds'/profile['id']/profile['firmware']['kernel_version']
        subprocess.run([USIGN,'-V','-m',str(feed/'Packages'),'-p',str(self.public),'-x',str(feed/'Packages.sig')],check=True,capture_output=True)

    def test_mutable_generation_refuses_before_output(self):
        tree,_=self.channel('recommended');metadata=self.metadata(tree);metadata['immutable']=False
        output=self.root/'publication';result=self.publish(tree,output,metadata)
        self.assertNotEqual(result.returncode,0);self.assertFalse(output.exists())
    def test_missing_external_catalog_rejected_before_output(self):
        tree,profile=self.channel('recommended')
        output=self.root/'publication'
        result=subprocess.run(['python3',str(ROOT/'scripts/publish.py'),'--profile',str(tree/'profile.json'),
                               '--input',str(tree),'--output',str(output),'--key',str(self.key),
                               '--public-key',str(self.public),'--usign',USIGN,'--lock',str(tree/'state/lock.json'),
                               '--external-assets',str(self.root/'missing.json'),'--external-assets-signature',str(self.root/'missing.sig'),
                               '--generation-release-metadata',str(self.root/'missing-release.json')],capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('unrecognized arguments',result.stderr)
        self.assertFalse(output.exists())

if __name__=='__main__':unittest.main()
