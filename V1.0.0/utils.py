import hmac
import os
import re
import tkinter
import base64
import base58
import hashlib
# whirlpool
# from ttkbootstrap.tooltip import ToolTip

from morse import Morse_codes


def monitor(window:tkinter.Tk):
    return {"width": window.winfo_screenwidth(), "height": window.winfo_screenheight()}


class EDHC_UTIL:
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
            # 'binary',
            'morse',
            'rot13',
            'caesar',
            'hexdump',
            # 'magic',
            'dummy'
         ],

        'hash':
        [
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
            'hmac',
        ],

        'encrypt': []
    }

    def All_types(self):
        all = []
        for type in edhc_util.all.values():
            for t in type:
                all.append(t)
        return all
    def Encode_base16(self, string):
        try:return base64.b16encode(string.encode())
        except Exception:return ''
    def Decode_base16(self, string):
        try:return base64.b16decode(string)
        except Exception:return ''

    def Encode_base32(self, string):
        try:return base64.b32encode(string.encode())
        except Exception:return ''
    def Decode_base32(self, string):
        try:return base64.b32decode(string)
        except Exception:return ''

    def Encode_base58(self, string):
        try:return base58.b58encode(string.encode())
        except Exception:return ''
    def Decode_base58(self, string):
        try:return base58.b58encode(string)
        except Exception:return ''

    def Encode_base64(self, string):
        try:return base64.b64encode(string.encode())
        except Exception:return ''
    def Decode_base64(self, string):
        try:return base64.b64decode(string)
        except Exception:return ''

    def Encode_base85(self, string):
        try:return base64.b85encode(string.encode())
        except Exception:return ''
    def Decode_base85(self, string):
        try:return base64.b85decode(string)
        except Exception:return ''

    def Encode_base64_urlsafe(self, string):
        try:return base64.urlsafe_b64encode(string.encode())
        except Exception:return ''
    def Decode_base64_urlsafe(self, string):
        try:return base64.urlsafe_b64decode(string)
        except Exception:return ''

    def Morse_encrypt(self, text):
        cipher = ''
        for letter in text.upper():
            if letter != ' ':
                try:
                    cipher += ' ' + Morse_codes[letter] + ' '
                except:
                    cipher += letter
            else:
                cipher += ' '
        return cipher

    # Test-> #1 @1 $10000000, dude that's great I like it... Loading !@#$%^&*()_+}{|":?><~!`
    # _ . ... _ _...._    .____  .__._. .____  $ .____ _____ _____ _____ _____ _____ _____ _____ __.__  _.. .._ _.. .  _ .... ._ _ .____. ...  __. ._. . ._ _  ..  ._.. .. _._ .  .. _ ._._._ ._._._ ._._._  ._.. ___ ._ _.. .. _. __.  _._.__ .__._.  $   ._...  _.__. _.__._  ._._.    ._.._. ___... ..__..    _._.__
    def Morse_decrypt(self, morse):
        text = ''
        for Cipher in morse.split(' '):
            if Cipher != ' ':
                try:
                    text += list(Morse_codes.keys())[list(Morse_codes.values()).index(Cipher)]
                except:
                    text += Cipher
            else:
                text += ' '
        return text

    def Caesar_encode(self, string, shift:int=3):
        """
        :param string: Any
        :param shift: padding of characters
        here the shift value is 3:
           ABCDEFGHIJKLMNOPQRSTUVWXYZ
        ABCDEFGHIJKLMNOPQRSTUVWXYZ
        shift=13:
            - rot13
        :return: (caesar cipher) encrypted string
        """
        encrypted = ""
        # traverse text
        for ind in range(len(string)):
            char = string[ind]
            # Encrypt uppercase characters

            if char.isalpha():
                charis = 65 if char.isupper() else 97
                encrypted += chr((ord(char) + shift - charis) % 26 + charis)
            # Encrypt lowercase characters
            else:
                encrypted += char
        return encrypted

    def Caesar_decode(self, string, shift:int=3):
        """
        :param string: Any
        :param shift: padding of characters
        here the shift value is 3:
           ABCDEFGHIJKLMNOPQRSTUVWXYZ
        ABCDEFGHIJKLMNOPQRSTUVWXYZ
        shift=13:
            - rot13
        :return: (caesar cipher) decrypted string
        """
        decrypted = ''
        for char in string:
            if char.isalpha():
                # find the position in 0-25
                char_unicode = ord(char)
                char_index = ord(char) - (ord("A") if char.isupper() else ord('a'))
                # perform the negative shift
                new_index = (char_index - shift) % 26
                # convert to new character
                new_unicode = new_index + (ord("A") if char.isupper() else ord('a'))
                new_character = chr(new_unicode)
                # append to plain string
                decrypted += new_character
            else:
                decrypted += char
        return decrypted

    def HexDump(self, file, type: str = 'hex', fence: str = '|'):
        try:
            table = ""
            with open(file, "rb") as f:
                n = 0
                b = f.read(16)

                while b:
                    if type == 'hex':
                        s1 = " ".join([f"{i:02x}" for i in b])  # hex string
                        s1 = s1[0:23] + " " + s1[23:]  # insert extra space between groups of 8 hex values
                        width = 48
                    else:
                        s1 = " ".join([f"{i:08b}" for i in b])  # binary string
                        s1 = s1[0:71] + " " + s1[71:]  # insert extra space between groups of 8 binary values
                        width = 144
                    # as> 72<here>20<here>61
                    # 72 74 20 61 72 67 70 61

                    s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])  # ascii string; chained comparison
                    # 32 -> 127 (this is every single possible character other than spaces and else)
                    table += f"{n * 16:08x}  {s1:<{width}}  {fence}{s2}{fence}\n"  # make (this.line) of table
                    # {s1:<48} is the below between brackets (spaces also counted):
                    # (72 74 20 61 72 67 70 61  72 73 65 0d 0a 0d 0a 70)
                    n += 1
                    b = f.read(16)
                f.close()
            return table.strip()
        except Exception as e:
            return str(e)

    alphapet = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
                'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
                'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    def Encode_dummy(self, string: str, seperator: str = '.'):
        encoded = []
        for letter in string:
            if letter in self.alphapet:
                encoded.append(str(self.alphapet.index(letter) + 1))
            else:
                encoded.append(letter)
        return seperator.join(encoded)

    def Decode_dummy(self, string: str, seperator: str = '.'):
        decoded = ''
        for l in string.split(seperator):
            try:
                decoded += self.alphapet[int(l) - 1]
            except Exception:
                decoded += l
        return decoded

    def Md5(self, string:str, type:str):
        if type == 'hex':
            return hashlib.md5(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.md5(string.encode()).digest())[2:-1]
    def Sha1(self, string:str, type:str):
        if type == 'hex':
            return hashlib.sha1(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.sha1(string.encode()).digest())[2:-1]
    def Sha224(self, string:str, type:str):
        if type == 'hex':
            return hashlib.sha224(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.sha224(string.encode()).digest())[2:-1]
    def Sha256(self, string:str, type:str):
        if type == 'hex':
            return hashlib.sha256(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.sha256(string.encode()).digest())[2:-1]
    def Sha384(self, string:str, type:str):
        if type == 'hex':
            return hashlib.sha384(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.sha384(string.encode()).digest())[2:-1]
    def Sha512(self, string:str, type:str):
        if type == 'hex':
            return hashlib.sha512(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.sha512(string.encode()).digest())[2:-1]
    def Sha3_224(self, string:str, type:str):
        if type == 'hex':
            return hashlib.sha3_224(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.sha3_224(string.encode()).digest())[2:-1]
    def Sha3_256(self, string:str, type:str):
        if type == 'hex':
            return hashlib.sha3_256(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.sha3_256(string.encode()).digest())[2:-1]
    def Sha3_384(self, string:str, type:str):
        if type == 'hex':
            return hashlib.sha3_384(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.sha3_384(string.encode()).digest())[2:-1]
    def Sha3_512(self, string:str, type:str):
        if type == 'hex':
            return hashlib.sha3_512(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.sha3_512(string.encode()).digest())[2:-1]
    def Shake128(self, string:str, type:str, length:int):
        if type == 'hex':
            return hashlib.shake_128(string.encode()).hexdigest(length)
        elif type == 'dig':
            return str(hashlib.shake_128(string.encode()).digest(length))[2:-1]
    def Shake256(self, string:str, type:str, length:int):
        if type == 'hex':
            return hashlib.shake_256(string.encode()).hexdigest(length)
        elif type == 'dig':
            return str(hashlib.shake_256(string.encode()).digest(length))[2:-1]
    def Black2s(self, string:str, type:str):
        if type == 'hex':
            return hashlib.blake2s(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.blake2s(string.encode()).digest())[2:-1]
    def Black2b(self, string:str, type:str):
        if type == 'hex':
            return hashlib.blake2b(string.encode()).hexdigest()
        elif type == 'dig':
            return str(hashlib.blake2b(string.encode()).digest())[2:-1]
    def Hmac(self, key:str, msg:str, digestmod:str, type:str):
        if type == 'hex':
            return hmac.new(key=key.encode(), msg=msg.encode(), digestmod=digestmod).hexdigest()
        elif type == 'dig':
            return str(hmac.new(key=key.encode(), msg=msg.encode(), digestmod=digestmod).digest())[2:-1]

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


edhc_util = EDHC_UTIL()

class File:
    def size(self, file):
        if os.path.isfile(file):
            b = os.path.getsize(file)
            for x in ['Bytes', 'KB', 'MB', 'GB', 'TB']:
                if b < 1024.0:return "%3.0f %s" % (b, x)
                b /= 1024.0
_file_ = File()