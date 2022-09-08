import hmac
import os
import re
import tkinter
import base64
import base58
import hashlib
# whirlpool
# from ttkbootstrap.tooltip import ToolTip
from cryptography.fernet import Fernet

from hMorse import Morse_codes


def monitor(window:tkinter.Tk):
    return {"width": window.winfo_screenwidth(), "height": window.winfo_screenheight()}


class HEXOR_UTIL:
    """
    - Base:
        - base64.b16encode
        - base64.b32encode
        - base58.b58encode
        - base64.b64encode
        - base64.b85encode
        - base64.urlsafe_b64encode
    - Hash:
        - hashlib.md5
        -
    """

    all = { # d is for dict
        'encode':
        [
            'base16',
            'base32',
            'base58',
            'base64',
            'base85',
            'base64.urlsafe',
            'binary',
            'morse',
            'rot13',
            'caesar',
            'hexdump',
            # 'magic', # detect hashing/encoding/encryption types.
            'dummy'
         ],

        'hash':
        sorted([
            'md2',
            'md4',
            'md5',
            'sha1',
            'sha224',
            'sha256',
            'sha384',
            'sha512',
            'sha3.224',
            'sha3.256',
            'sha3.384',
            'sha3.512',
            'shake.128',
            'shake.256',
            'black2s',
            'blake2b',
            'cmac'
            'hmac'
            'poly1305'
        ]),

        'encrypt': [
            'aes128'
        ]
    }

    def All_types(self):
        all = []
        for type in hexor_util.all.values():
            for t in type:
                all.append(t)
        return all

    def increase_font(self, widget):
        try:
            current_val = int(re.findall('\d+', widget['font'])[0]) + 1
            widget.config(font=("' %s" % current_val))
        except Exception:
            pass

    def decrease_font(self, widget):
        try:
            current_val = int(re.findall('\d+', widget['font'])[0]) - 1
            if current_val > 0:
                widget.config(font=("' %s" % current_val))
        except Exception:
            pass
hexor_util = HEXOR_UTIL()

class File:
    def size(self, file):
        if os.path.isfile(file):
            b = os.path.getsize(file)
            for x in ['Bytes', 'KB', 'MB', 'GB', 'TB']:
                if b < 1024.0:return "%3.0f %s" % (b, x)
                b /= 1024.0
_file_ = File()