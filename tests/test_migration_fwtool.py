"""fwtool envelopes around a static FIT; actual measured tails are data only."""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib
from test_kernel_migration import image, sysupgrade
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import kernel_migration as m

def chunk(prefix,payload,kind=1,pad=b'\0'*3):
    trailer=struct.pack('>IIB3sI',0x46577830,zlib.crc32(prefix+payload)^0xffffffff,kind,pad,len(payload)+16)
    return prefix+payload+trailer

def metadata(layout='ubootmod'):
    return b'\0'*8+json.dumps({'metadata_version':'1.1','supported_devices':['xiaomi,redmi-router-ax6000-'+layout], 'version':{'target':'mediatek/filogic','board':'xiaomi_redmi-router-ax6000-'+layout}}).encode()

class MigrationFwtool(unittest.TestCase):
    def test_signed_and_unsigned_metadata_fit_yield_exact_whole_image(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);kernel=image(b'fwtool');bare=sysupgrade('ubootmod',kernel)
            for label,data in [('metadata',chunk(bare,metadata())),('signed',chunk(chunk(bare,metadata()),b'opaque certificate/signature',0))]:
                path=root/(label+'.itb');path.write_bytes(data);before=path.read_bytes()
                self.assertEqual(m.functional_image(path,'ubootmod',root/label),{'size':len(kernel),'sha256':hashlib.sha256(kernel).hexdigest()});self.assertEqual(path.read_bytes(),before)
    def test_generic_fit_reader_keeps_rejecting_any_outer_envelope(self):
        import fit_payload
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'signed.itb';path.write_bytes(chunk(sysupgrade('ubootmod',image(b'strict')),metadata()))
            with self.assertRaisesRegex(ValueError,'trailing static FIT'):
                fit_payload.extract_fit(path,root,external=True)

    def test_actual_measured_fwtool_tails_and_crc_prefixes(self):
        fixture=json.loads((Path(__file__).parent/'fixtures/migration-fwtool-tails.json').read_text())
        for row in fixture['assets']:
            tail=bytes.fromhex(row['tail_hex'])
            self.assertEqual(m.fwtool_fit_end(tail,'ubootmod',crc_prefix=row['fit_crc32']),0)
            bad=bytearray(tail);bad[10]^=1
            with self.assertRaisesRegex(ValueError,'CRC'):m.fwtool_fit_end(bad,'ubootmod',crc_prefix=row['fit_crc32'])
    def test_bad_envelope_crc_padding_type_board_and_trailing_bytes_rejected(self):
        bare=sysupgrade('ubootmod',image(b'bad'))
        cases={'CRC':chunk(bare,metadata())[:-12]+b'X'+chunk(bare,metadata())[-11:],
               'padding':chunk(bare,metadata(),pad=b'X\0\0'),'type':chunk(bare,b'unknown',7),
               'board':chunk(bare,metadata('stock')),'trailing':chunk(bare,metadata())+b'unknown tail',
               'signature-only':chunk(bare,b'opaque signature',0)}
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            for label,data in cases.items():
                with self.subTest(label=label):
                    path=root/(label+'.itb');path.write_bytes(data)
                    with self.assertRaises(ValueError):m.functional_image(path,'ubootmod',root/label)
    def test_nonzero_fit_alignment_padding_rejected_even_with_valid_envelope_crc(self):
        bare=bytearray(sysupgrade('ubootmod',image(b'padding')));bare[8191]=1
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);path=root/'bad.itb';path.write_bytes(chunk(bare,metadata()))
            with self.assertRaisesRegex(ValueError,'alignment padding'):m.functional_image(path,'ubootmod',root/'work')

if __name__=='__main__':unittest.main()
