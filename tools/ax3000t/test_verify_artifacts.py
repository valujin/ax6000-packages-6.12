import importlib.util
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

spec=importlib.util.spec_from_file_location('verify',Path(__file__).with_name('verify-artifacts.py'))
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

class VerifyTests(unittest.TestCase):
    def test_metadata_rejects_foreign_board(self):
        good={'supported_devices':[v.BOARD],'version':{'target':'mediatek/filogic'}}
        v.metadata_check(good)
        for board in ['xiaomi,redmi-router-ax6000-stock','xiaomi,mi-router-ax3000t-ubootmod']:
            with self.assertRaisesRegex(ValueError,'metadata board'):
                v.metadata_check(dict(good,supported_devices=[board]))

    def test_real_dtb_geometry_and_chip(self):
        template='''/dts-v1/; / { compatible = "BOARD", "mediatek,CHIP";
        flash { compatible="spi-nand"; mediatek,nmbm;
        mediatek,bmt-mtd-overridden-oobsize=<64>;
        partitions { #address-cells=<1>; #size-cells=<1>;
        kernel@600000 { label="ubi_kernel"; reg=<0x600000 SIZE>; };
        root@2800000 { label="ubi"; reg=<0x2800000 0x4e00000>; }; }; }; };'''
        with tempfile.TemporaryDirectory() as tmp:
            source=Path(tmp)/'test.dts'; output=Path(tmp)/'test.dtb'
            def dtb(board=v.BOARD,chip='mt7981',size='0x2200000'):
                source.write_text(template.replace('BOARD',board).replace('CHIP',chip).replace('SIZE',size))
                subprocess.run(['dtc','-I','dts','-O','dtb','-o',output,source],check=True,capture_output=True)
                return output.read_bytes()
            v.dtb_check(dtb())
            for kwargs in ({'size':'0x1e00000'},{'chip':'mt7986a'},{'board':'xiaomi,mi-router-ax3000t-ubootmod'}):
                with self.assertRaises(ValueError): v.dtb_check(dtb(**kwargs))

    def test_packages_forbid_asu_and_tailscale(self):
        paths=['lib/apk/db/installed','etc/wireless/mediatek/mt7981.dbdc.b0.dat',
               'etc/wireless/mediatek/mt7981.dbdc.b1.dat','etc/wireless/l1profile.dat','etc/init.d/ax6000-mesh']
        def db(names): return ''.join('P:'+n+'\nV:1-r1\nA:aarch64_cortex-a53\n\n' for n in sorted(names)).encode()
        v.packages_check(db(v.REQUIRED),paths)
        for bad in ('tailscale','luci-app-attendedsysupgrade','kmod-mt7986-firmware'):
            with self.assertRaisesRegex(ValueError,'Forbidden packages'):
                v.packages_check(db(v.REQUIRED|{bad}),paths)
        with self.assertRaisesRegex(ValueError,'Missing required'):
            v.packages_check(db(v.REQUIRED-{'wapp'}),paths)
        with self.assertRaisesRegex(ValueError,'inherited image path'):
            v.packages_check(db(v.REQUIRED),paths+['etc/wireless/mediatek/mt7986-ax6000.dbdc.b0.dat'])

    def test_tar_rejects_escape_and_oversized_kernel(self):
        import io
        import tarfile
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            for name,size in [('../escape',1),('sysupgrade-'+v.DEVICE+'/kernel',v.LIMIT)]:
                image=root/'bad.tar'
                # Header-only oversized entry must fail before reading payload.
                member=tarfile.TarInfo(name);member.size=size
                image.write_bytes(member.tobuf()+b'x'+b'\0'*2047)
                with self.assertRaises(ValueError):v.tar_check(image,root)

    def test_native_chip_evidence_is_required(self):
        flags=('TARGET_mediatek','TARGET_mediatek_filogic','PACKAGE_kmod-mt_wifi',
               'MTK_CHIP_MT7981','MTK_FIRST_IF_MT7981','MTK_CONNINFRA_APSOC_MT7981',
               'MTK_MAP_SUPPORT','MTK_MAP_R2_VER_SUPPORT','MTK_MAP_R3_VER_SUPPORT',
               'MTK_MAP_R2_6E_SUPPORT','MTK_MAP_R3_6E_SUPPORT','MTK_DFS_SLAVE_SUPPORT',
               'TARGET_DEVICE_mediatek_filogic_DEVICE_'+v.DEVICE)
        config=''.join('CONFIG_'+f+'=y\n' for f in flags)+'CONFIG_first_card_name="MT7981"\n'
        v.config_check(config,'CONFIG_CHIP_MT7981=y\n')
        for native in ('CONFIG_CHIP_MT7986=y\n','CONFIG_CHIP_MT7981=y\nCONFIG_CHIP_MT7986=y\n'):
            with self.assertRaises(ValueError):v.config_check(config,native)
        with self.assertRaisesRegex(ValueError,'Foreign device'):
            v.config_check(config+'CONFIG_TARGET_DEVICE_mediatek_filogic_DEVICE_other=y\n','CONFIG_CHIP_MT7981=y\n')

    def test_tool_sidefile_larger_than_stdout_bound(self):
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            output=Path(tmp)/'ramdisk'
            command=[sys.executable,'-c',"import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'x'*(9*1024*1024)); print('ok')",str(output)]
            with self.assertRaisesRegex(ValueError,'Host tool failed'):v.run(command)
            self.assertEqual(v.run(command,cap=4096,sidefile_cap=9*v.MIB),b'ok\n')
            self.assertEqual(output.stat().st_size,9*v.MIB)
            with self.assertRaisesRegex(ValueError,'output cap'):
                v.run([sys.executable,'-c',"print('x'*8192)"],cap=4096,sidefile_cap=9*v.MIB)

    def test_genuine_compiler_chip_tokens(self):
        v.native_chip_check('savedcmd_obj := aarch64-gcc -O2 -DMT7981 -c source.c\n')
        v.native_chip_check('savedcmd_obj := cc -DMT7981=1 -DPRE_CAL_MT7986_SUPPORT\n')
        v.native_chip_check('#define CHIP_MT7981 1\n')
        for fake in ('-DMT79810','-DMT7981_EXTRA','-DPRE_CAL_MT7981_SUPPORT',
                     '/chip/mt7981.h','prefix-DMT7981','-DMT7981=0'):
            with self.assertRaisesRegex(ValueError,'No independent'):
                v.native_chip_check('savedcmd := cc '+fake+' -c source.c\n')
        for mixed in ('-DMT7986','-DMT7986=1','-DMT7986=0'):
            with self.assertRaisesRegex(ValueError,'compiled for MT7986'):
                v.native_chip_check('savedcmd := cc -DMT7981 '+mixed+' -c source.c\n')

    def test_stale_hardware_helper_fails_both_images(self):
        with tempfile.TemporaryDirectory() as tmp:
            assets=Path(tmp)
            names=['usr/libexec/ax6000-mesh-control','usr/bin/wifi_config_save',
                   'etc/config/ax6000_mesh','usr/libexec/ax6000-mesh-hardware']
            for name in names:
                path=assets/name;path.parent.mkdir(parents=True,exist_ok=True)
                path.write_bytes(b'reviewed-MT7981-port')
            hashes={name:v.sha((assets/name).read_bytes()) for name in names}
            entries={name:{'kind':v.stat.S_IFREG,'data_sha256':digest} for name,digest in hashes.items()}
            v.mesh_assets_check(assets,hashes,entries)
            helper=names[-1]
            with self.assertRaisesRegex(ValueError,'Squashfs Mesh payload'):
                v.mesh_assets_check(assets,dict(hashes,**{helper:v.sha(b'stale-AX6000-only')}),entries)
            entries[helper]['data_sha256']=v.sha(b'stale-AX6000-only')
            with self.assertRaisesRegex(ValueError,'Initramfs Mesh payload'):
                v.mesh_assets_check(assets,hashes,entries)

    def test_clean_disabled_enrollment_state(self):
        config=b"config mesh 'main'\n option enabled '0'\n option backhaul_security 'sae'\n"
        v.clean_mesh_check(config,['etc/config/ax6000_mesh','etc/apk/keys/public.pem'])
        with self.assertRaisesRegex(ValueError,'disabled'):
            v.clean_mesh_check(config.replace(b"enabled '0'",b"enabled '1'"),[])
        with self.assertRaisesRegex(ValueError,'credential'):
            v.clean_mesh_check(config+b" option session_key 'secret'\n",[])
        for path in ['etc/ax6000-mesh/snapshot.sha256','root/.ssh/authorized_keys','etc/mesh-session-key']:
            with self.assertRaises(ValueError):v.clean_mesh_check(config,[path])

    def test_identity_allows_mesh_namespace_not_feed(self):
        v.identity_check('etc/uci-defaults/test',b'uci set ax6000_mesh.main.enabled=0')
        with self.assertRaisesRegex(ValueError,'feed/installer'):
            v.identity_check('etc/apk/repositories.d/custom.list',b'https://valujin.github.io/ax6000-packages-6.12/channels/recommended')

    def test_ubi_rejects_corrupt_header_and_wrong_geometry(self):
        payload=b'test-fit'
        def crc(data): return data+struct.pack('>I',v.ubi_crc(data))
        table=b''
        for i in range(128):
            row=bytearray(168)
            if i==0:
                struct.pack_into('>IIIBBH',row,0,1,1,0,1,0,6); row[16:22]=b'kernel'
            table+=crc(row)
        table+=b'\xff'*(v.LEB-len(table))
        def block(volid=0,lnum=0,body=b'',eof=False):
            ec=bytearray(60);struct.pack_into('>IB',ec,0,0x55424923,1)
            if eof: ec[5:8]=b'EOF'
            struct.pack_into('>QIII',ec,8,0,v.PAGE,v.DATA,123)
            if eof:return crc(ec)+b'\xff'*(v.PEB-64)
            vid=bytearray(60);struct.pack_into('>IBBBBII',vid,0,0x55424921,1,1,0,5 if volid==v.LAYOUT else 0,volid,lnum)
            return crc(ec)+b'\xff'*(v.PAGE-64)+crc(vid)+b'\xff'*(v.DATA-v.PAGE-64)+body+b'\xff'*(v.LEB-len(body))
        good=block(v.LAYOUT,0,table)+block(v.LAYOUT,1,table)+block(body=payload)+block(eof=True)*5
        self.assertEqual(v.ubi(good,payload)['partition_limit'],34*v.MIB)
        bad=bytearray(good);bad[20]^=1
        with self.assertRaises(ValueError):v.ubi(bad,payload)
        with self.assertRaisesRegex(ValueError,'payload/padding'):v.ubi(good,b'otherfit')
        with self.assertRaisesRegex(ValueError,'five native EOF'):v.ubi(good[:-v.PEB],payload)

if __name__=='__main__':unittest.main()
