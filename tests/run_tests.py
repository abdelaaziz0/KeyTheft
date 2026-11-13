#!/usr/bin/env python3
import os
import struct
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PNG_SIG = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])
IHDR_BODY = bytes([0, 0, 0, 13]) + b'IHDR' + bytes(
    [0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0])
IHDR = IHDR_BODY + struct.pack('>I', 0x64553F54)

try:
    import sam_extract
    HAVE_SAM = True
except ImportError:
    HAVE_SAM = False


class TestPngHeader(unittest.TestCase):
    def test_ihdr_crc_matches_contents(self):
        import zlib
        self.assertEqual(zlib.crc32(IHDR_BODY), 0x64553F54)

    def test_decode_roundtrip(self):
        import subprocess
        import tempfile
        key = bytes(range(16))
        data = b'regf' + os.urandom(5000)
        enc = bytes(data[i] ^ key[i % 16] for i in range(len(data)))
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 't.png')
            with open(p, 'wb') as f:
                f.write(PNG_SIG + IHDR + enc)
            r = subprocess.run(
                [sys.executable,
                 os.path.join(os.path.dirname(os.path.dirname(
                     os.path.abspath(__file__))), 'decode.py'),
                 key.hex(), p],
                capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(d, 't.hiv'), 'rb') as f:
                self.assertEqual(f.read(), data)


@unittest.skipUnless(HAVE_SAM, 'sam_extract needs pycryptodomex')
class TestSamCrypto(unittest.TestCase):
    def test_sid_to_key_split(self):
        for rid in (500, 1000, 1234567, 0xFFFFFFFF):
            k = struct.pack('<L', rid)
            s1 = [k[0], k[1], k[2], k[3], k[0], k[1], k[2]]
            s2 = [k[3], k[0], k[1], k[2], k[3], k[0], k[1]]
            k1, k2 = sam_extract.sid_to_key(rid)
            self.assertEqual(k1, sam_extract.str_to_key(s1))
            self.assertEqual(k2, sam_extract.str_to_key(s2))

    def test_str_to_key_transform(self):
        s = bytes([0xFF, 0x37, 0x50, 0x9C, 0x00, 0x00, 0x00])
        self.assertEqual(sam_extract.str_to_key(s),
                         bytes.fromhex('fe9ad412c0000000'))

    def test_decrypt_blob_roundtrip_both_styles(self):
        from Cryptodome.Cipher import DES, AES, ARC4
        from Cryptodome.Hash import MD5

        def encrypt_hash(rid, plain, hbk, constant, new_style):
            k1, k2 = sam_extract.sid_to_key(rid)
            e = DES.new(k1, DES.MODE_ECB).encrypt(plain[:8]) + \
                DES.new(k2, DES.MODE_ECB).encrypt(plain[8:16])
            if not new_style:
                rc4 = MD5.new(hbk[:16] + struct.pack('<L', rid) + constant).digest()
                return struct.pack('<HH', 0, 1) + ARC4.new(rc4).encrypt(e)
            salt = os.urandom(16)
            return struct.pack('<HHI', 0, 2, 0) + salt + \
                AES.new(hbk[:16], AES.MODE_CBC, salt).encrypt(e)

        hbk, rid, nt = os.urandom(16), 500, os.urandom(16)
        for style in (False, True):
            blob = encrypt_hash(rid, nt, hbk, b"NTPASSWORD\0", style)
            self.assertEqual(
                sam_extract.decrypt_blob(rid, blob, hbk, b"NTPASSWORD\0"), nt)

    def test_decrypt_blob_rejects_junk(self):
        hbk = os.urandom(16)
        self.assertIsNone(sam_extract.decrypt_blob(500, b'', hbk, b'X'))
        self.assertIsNone(sam_extract.decrypt_blob(500, os.urandom(19), hbk, b'X'))
        self.assertIsNone(sam_extract.decrypt_blob(
            500, bytes([0, 0, 3]) + os.urandom(17), hbk, b'X'))
        self.assertIsNone(sam_extract.decrypt_blob(
            500, bytes([0, 0, 2]) + os.urandom(17), hbk, b'X'))


@unittest.skipUnless(HAVE_SAM, 'sam_extract needs pycryptodomex')
class TestRegParser(unittest.TestCase):
    def make_hive(self, cells):
        h = sam_extract.RegHive.__new__(sam_extract.RegHive)
        h.hbin_start = 0x1000
        h.data = bytearray(0x1200)
        for off, payload in cells:
            a = 0x1000 + off
            h.data[a:a + 4] = struct.pack('<i', -(4 + len(payload)))
            h.data[a + 4:a + 4 + len(payload)] = payload
        return h

    def test_ri_recurses_into_li(self):
        h = self.make_hive([
            (0x40, b'li' + struct.pack('<H', 2) + struct.pack('<II', 0x1080, 0x10C0)),
            (0, b'ri' + struct.pack('<H', 1) + struct.pack('<I', 0x40)),
        ])
        self.assertEqual(h._subkey_offsets(0), [0x1080, 0x10C0])

    def test_corrupt_cell_raises(self):
        h = sam_extract.RegHive.__new__(sam_extract.RegHive)
        h.hbin_start = 0x1000
        h.data = b'\x00' * 0x1000
        with self.assertRaises(ValueError):
            h._read_cell(0xFFFFF)

    def test_default_value_name_is_empty(self):
        vk_cell = b'vk' + struct.pack('<H', 0) + struct.pack('<I', 0) + \
            struct.pack('<I', 0) + struct.pack('<I', 1) + \
            struct.pack('<H', 0) + b'\x00\x00'
        h = self.make_hive([
            (0, struct.pack('<I', 0x40)),
            (0x40, vk_cell),
        ])
        nk = {'num_values': 1, 'values_list_off': 0}
        self.assertEqual(h.get_value(nk, ''), vk_cell[20:20 + 1])


if __name__ == '__main__':
    unittest.main(verbosity=2)
