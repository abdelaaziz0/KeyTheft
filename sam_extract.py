#!/usr/bin/env python3

import sys
import struct
import hashlib
import os

from Cryptodome.Cipher import DES, AES, ARC4
from Cryptodome.Hash import MD5


class RegHive:

    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = f.read()

        if self.data[:4] != b'regf':
            raise ValueError(f"Not a registry hive: {path}")

        self.root_offset = struct.unpack_from('<I', self.data, 0x24)[0]
        self.hbin_start = 0x1000

    def _abs(self, offset):
        return self.hbin_start + offset

    def _read_cell(self, offset):
        abs_off = self._abs(offset)
        if abs_off < 0 or abs_off + 4 > len(self.data):
            raise ValueError(f"Cell offset out of range: 0x{offset:x}")
        size = struct.unpack_from('<i', self.data, abs_off)[0]
        cell_size = abs(size)
        if cell_size < 4 or abs_off + cell_size > len(self.data):
            raise ValueError(f"Corrupt cell at 0x{offset:x}")
        return self.data[abs_off + 4 : abs_off + cell_size]

    def _parse_nk(self, offset):
        cell = self._read_cell(offset)
        if cell[:2] != b'nk':
            return None
        if len(cell) < 0x4C:
            return None

        flags = struct.unpack_from('<H', cell, 2)[0]
        num_subkeys = struct.unpack_from('<I', cell, 0x14)[0]
        subkeys_list_off = struct.unpack_from('<I', cell, 0x1C)[0]
        num_values = struct.unpack_from('<I', cell, 0x24)[0]
        values_list_off = struct.unpack_from('<I', cell, 0x28)[0]
        class_name_off = struct.unpack_from('<I', cell, 0x30)[0]
        class_name_len = struct.unpack_from('<H', cell, 0x4A)[0]
        name_len = struct.unpack_from('<H', cell, 0x48)[0]
        name = cell[0x4C : 0x4C + name_len]

        if flags & 0x20:
            name = name.decode('ascii', errors='replace')
        else:
            name = name.decode('utf-16-le', errors='replace')

        class_name = None
        if class_name_off != 0xFFFFFFFF and class_name_len > 0:
            cn_cell = self._read_cell(class_name_off)
            class_name = cn_cell[:class_name_len].decode('utf-16-le', errors='replace')

        return {
            'name': name,
            'flags': flags,
            'num_subkeys': num_subkeys,
            'subkeys_list_off': subkeys_list_off,
            'num_values': num_values,
            'values_list_off': values_list_off,
            'class_name': class_name,
            'offset': offset,
        }

    def _enum_subkeys(self, nk):
        if nk['num_subkeys'] == 0:
            return []
        return self._subkey_offsets(nk['subkeys_list_off'])

    def _subkey_offsets(self, list_off):
        cell = self._read_cell(list_off)
        sig = cell[:2]
        count = struct.unpack_from('<H', cell, 2)[0]

        if sig in (b'lf', b'lh'):
            return [struct.unpack_from('<I', cell, 4 + i * 8)[0]
                    for i in range(count)]
        if sig == b'li':
            return [struct.unpack_from('<I', cell, 4 + i * 4)[0]
                    for i in range(count)]
        if sig == b'ri':
            offsets = []
            for i in range(count):
                sub_off = struct.unpack_from('<I', cell, 4 + i * 4)[0]
                offsets.extend(self._subkey_offsets(sub_off))
            return offsets
        return []

    def _enum_values(self, nk):
        if nk['num_values'] == 0:
            return []

        cell = self._read_cell(nk['values_list_off'])
        values = []
        for i in range(nk['num_values']):
            vk_off = struct.unpack_from('<I', cell, i * 4)[0]
            vk = self._parse_vk(vk_off)
            if vk:
                values.append(vk)
        return values

    def _parse_vk(self, offset):
        cell = self._read_cell(offset)
        if cell[:2] != b'vk':
            return None
        if len(cell) < 0x14:
            return None

        name_len = struct.unpack_from('<H', cell, 2)[0]
        data_len = struct.unpack_from('<I', cell, 4)[0]
        data_off = struct.unpack_from('<I', cell, 8)[0]
        val_type = struct.unpack_from('<I', cell, 0xC)[0]
        flags = struct.unpack_from('<H', cell, 0x10)[0]

        if name_len > 0:
            name_bytes = cell[0x14 : 0x14 + name_len]
            if flags & 1:
                name = name_bytes.decode('ascii', errors='replace')
            else:
                name = name_bytes.decode('utf-16-le', errors='replace')
        else:
            name = "(Default)"

        real_len = data_len & 0x7FFFFFFF
        if data_len & 0x80000000:
            data = struct.pack('<I', data_off)[:real_len]
        else:
            if real_len > 0:
                data = self._read_cell(data_off)[:real_len]
            else:
                data = b''

        return {'name': name, 'data': data, 'type': val_type}

    def open_key(self, path):
        parts = path.strip('\\').split('\\')
        nk = self._parse_nk(self.root_offset)
        if not nk:
            return None

        for part in parts:
            found = False
            for sub_off in self._enum_subkeys(nk):
                sub_nk = self._parse_nk(sub_off)
                if sub_nk and sub_nk['name'].lower() == part.lower():
                    nk = sub_nk
                    found = True
                    break
            if not found:
                return None
        return nk

    def get_value(self, nk, name):
        for vk in self._enum_values(nk):
            if vk['name'].lower() == name.lower():
                return vk['data']
        return None

    def get_subkeys(self, nk):
        result = []
        for off in self._enum_subkeys(nk):
            sub = self._parse_nk(off)
            if sub:
                result.append(sub)
        return result

    def get_class_name(self, path):
        nk = self.open_key(path)
        if nk:
            return nk['class_name']
        return None


BOOT_KEY_PERM = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
LSA_KEYS = ['JD', 'Skew1', 'GBG', 'Data']

EMPTY_LM = 'aad3b435b51404eeaad3b435b51404ee'
EMPTY_NT = '31d6cfe0d16ae931b73c59d7e0c089c0'

def extract_boot_key(system_hive):
    select_nk = system_hive.open_key('Select')
    if select_nk:
        current = system_hive.get_value(select_nk, 'Current')
        if current:
            cs_num = struct.unpack('<I', current)[0]
            cs_name = f'ControlSet{cs_num:03d}'
        else:
            cs_name = 'ControlSet001'
    else:
        cs_name = 'ControlSet001'

    hex_str = ''
    for key_name in LSA_KEYS:
        path = f'{cs_name}\\Control\\Lsa\\{key_name}'
        cn = system_hive.get_class_name(path)
        if cn is None:
            raise ValueError(f"Cannot read class name for {path}")
        hex_str += cn

    if len(hex_str) != 32:
        raise ValueError(f"Boot key hex string is {len(hex_str)} chars, expected 32")

    scrambled = bytes.fromhex(hex_str)
    boot_key = bytes(scrambled[BOOT_KEY_PERM[i]] for i in range(16))
    return boot_key


def str_to_key(s):
    key = bytearray(8)
    key[0] = s[0] >> 1
    key[1] = ((s[0] & 0x01) << 6) | (s[1] >> 2)
    key[2] = ((s[1] & 0x03) << 5) | (s[2] >> 3)
    key[3] = ((s[2] & 0x07) << 4) | (s[3] >> 4)
    key[4] = ((s[3] & 0x0F) << 3) | (s[4] >> 5)
    key[5] = ((s[4] & 0x1F) << 2) | (s[5] >> 6)
    key[6] = ((s[5] & 0x3F) << 1) | (s[6] >> 7)
    key[7] = s[6] & 0x7F
    for i in range(8):
        key[i] = (key[i] << 1) & 0xFE
    return bytes(key)


def sid_to_key(rid):
    s1 = bytearray(7)
    s1[0] = rid & 0xFF
    s1[1] = (rid >> 8) & 0xFF
    s1[2] = (rid >> 16) & 0xFF
    s1[3] = (rid >> 24) & 0xFF
    s1[4] = s1[0]
    s1[5] = s1[1]
    s1[6] = s1[2]

    s2 = bytearray(7)
    s2[0] = s1[3]
    s2[1] = s1[0]
    s2[2] = s1[1]
    s2[3] = s1[2]
    s2[4] = s1[3]
    s2[5] = s1[0]
    s2[6] = s1[1]

    return str_to_key(s1), str_to_key(s2)


def decrypt_single_hash(rid, enc_data):
    key1, key2 = sid_to_key(rid)
    des1 = DES.new(key1, DES.MODE_ECB)
    des2 = DES.new(key2, DES.MODE_ECB)
    return des1.decrypt(enc_data[:8]) + des2.decrypt(enc_data[8:16])


def decrypt_blob(rid, blob, hashed_boot_key, constant):
    if len(blob) < 20:
        return None
    style = blob[2]

    if style == 1:
        md5 = MD5.new()
        md5.update(hashed_boot_key[:16] + struct.pack('<I', rid) + constant)
        dec = ARC4.new(md5.digest()).decrypt(blob[4:20])
        return decrypt_single_hash(rid, dec)

    if style == 2:
        if len(blob) < 40 or (len(blob) - 24) % 16 != 0:
            return None
        salt = blob[8:24]
        dec = AES.new(hashed_boot_key[:16], AES.MODE_CBC,
                      salt).decrypt(blob[24:])[:16]
        return decrypt_single_hash(rid, dec)

    return None


def extract_sam_hashes(sam_hive, boot_key):

    QWERTY = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
    DIGITS = b"0123456789012345678901234567890123456789\0"

    account_nk = sam_hive.open_key('SAM\\Domains\\Account')
    if not account_nk:
        raise ValueError("Cannot open SAM\\Domains\\Account")

    f_value = sam_hive.get_value(account_nk, 'F')
    if not f_value or len(f_value) < 0xA8:
        raise ValueError("Cannot read F value")

    revision = struct.unpack_from('<I', f_value, 0x68)[0]

    if revision == 1:
        md5 = MD5.new()
        md5.update(f_value[0x70:0x80])
        md5.update(QWERTY)
        md5.update(boot_key)
        md5.update(DIGITS)
        blob = ARC4.new(md5.digest()).decrypt(f_value[0x80:0xA0])
        sam_key = blob[:16]

        check = MD5.new()
        check.update(sam_key + DIGITS + sam_key + QWERTY)
        if check.digest() != blob[16:]:
            raise ValueError(
                "Hashed boot key checksum failed (Syskey startup password in use?)")

    elif revision == 2:
        data_len = struct.unpack_from('<I', f_value, 0x74)[0]
        salt = f_value[0x78:0x88]
        enc_data = f_value[0x88:0x88 + data_len]
        if len(enc_data) == 0 or len(enc_data) % 16 != 0:
            raise ValueError("Bad AES key material length in F value")
        sam_key = AES.new(boot_key, AES.MODE_CBC, salt).decrypt(enc_data)[:16]

    else:
        raise ValueError(f"Unknown SAM revision: {revision}")

    users_nk = sam_hive.open_key('SAM\\Domains\\Account\\Users')
    if not users_nk:
        raise ValueError("Cannot open SAM\\Domains\\Account\\Users")

    results = []
    for sub_nk in sam_hive.get_subkeys(users_nk):
        rid_str = sub_nk['name']
        if not rid_str.startswith('0') or len(rid_str) != 8:
            continue

        try:
            rid = int(rid_str, 16)
        except ValueError:
            continue

        v_data = sam_hive.get_value(sub_nk, 'V')
        if not v_data or len(v_data) < 0xCC:
            continue

        name_off = struct.unpack_from('<I', v_data, 0x0C)[0] + 0xCC
        name_len = struct.unpack_from('<I', v_data, 0x10)[0]
        username = v_data[name_off : name_off + name_len].decode('utf-16-le', errors='replace')

        lm_off = struct.unpack_from('<I', v_data, 0x9C)[0] + 0xCC
        lm_len = struct.unpack_from('<I', v_data, 0xA0)[0]
        nt_off = struct.unpack_from('<I', v_data, 0xA8)[0] + 0xCC
        nt_len = struct.unpack_from('<I', v_data, 0xAC)[0]

        lm_blob = v_data[lm_off : lm_off + lm_len] if lm_len >= 20 else b''
        nt_blob = v_data[nt_off : nt_off + nt_len] if nt_len >= 20 else b''

        lm_hash = decrypt_blob(rid, lm_blob, sam_key, b"LMPASSWORD\0")
        nt_hash = decrypt_blob(rid, nt_blob, sam_key, b"NTPASSWORD\0")

        results.append({
            'rid': rid,
            'username': username,
            'lm_hash': lm_hash.hex() if lm_hash else EMPTY_LM,
            'nt_hash': nt_hash.hex() if nt_hash else EMPTY_NT,
        })

    return results


def main():
    if len(sys.argv) < 3:
        print("SAM Hash Extractor")
        print(f"Usage: python {sys.argv[0]} <sam.hiv> <system.hiv>")
        sys.exit(1)

    sam_path = sys.argv[1]
    system_path = sys.argv[2]

    print(f"[*] Loading SYSTEM hive: {system_path}")
    system_hive = RegHive(system_path)

    print(f"[*] Extracting boot key...")
    boot_key = extract_boot_key(system_hive)
    print(f"[+] Boot key: {boot_key.hex()}")

    print(f"[*] Loading SAM hive: {sam_path}")
    sam_hive = RegHive(sam_path)

    print(f"[*] Extracting hashes...")
    hashes = extract_sam_hashes(sam_hive, boot_key)

    print(f"\n[*] Dumping local SAM hashes ({len(hashes)} users):")
    for h in hashes:
        line = f"{h['username']}:{h['rid']}:{h['lm_hash']}:{h['nt_hash']}:::"
        print(line)


if __name__ == '__main__':
    main()
