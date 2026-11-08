#!/usr/bin/env python3
#
# SPDX-FileCopyrightText: The LineageOS Project
# SPDX-License-Identifier: Apache-2.0
#
# Set vendor tags in odm/etc/camera/config/oplus_camera_config.
# The stock file is AES-128-ECB encrypted (2 byte magic, 2 byte header,
# 4 byte trailer). OplusCamera falls back to the raw bytes when decoding
# fails, so the result is written back as plain JSON.
#
# usage: oplus_camera_config.py FILE TAG=VALUE [TAG=VALUE ...]

import json
import os
import subprocess
import sys
import tempfile

KEY = '6f2170406c247525535e4326412a4d28'


def decrypt(raw):
    if raw[:2] != b'\x01\x01':
        return raw
    with tempfile.TemporaryDirectory() as d:
        src, dst = os.path.join(d, 'in'), os.path.join(d, 'out')
        open(src, 'wb').write(raw[4:-4])
        subprocess.run(['openssl', 'enc', '-d', '-aes-128-ecb', '-K', KEY,
                        '-nopad', '-in', src, '-out', dst], check=True)
        pt = open(dst, 'rb').read()
    pad = pt[-1]
    if 1 <= pad <= 16 and pt.endswith(bytes([pad]) * pad):
        pt = pt[:-pad]
    return pt


def main(path, sets):
    text = decrypt(open(path, 'rb').read()).rstrip(b'\x00').decode()
    doc = json.loads(text[:text.rfind('}') + 1])
    for item in sets:
        tag, value = item.split('=', 1)
        for entry in doc['file_data']:
            if entry.get('VendorTag') == tag:
                entry['Value'] = value
                break
        else:
            doc['file_data'].append({'VendorTag': tag, 'Type': 'Byte',
                                     'Count': '1', 'Value': value})
    open(path, 'w').write(json.dumps(doc, indent=2) + '\n')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2:])
