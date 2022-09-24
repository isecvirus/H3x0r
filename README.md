![Logo](hexor.ico)

# Version 1.0.0
## EDHC
###### E (ncode/ncrypt), D (ecode/ecrypt), Hash, Crack

# Types
- base16:
  - encode
  - decode

- base32:
    - encode
    - decode

- base58:
    - encode
    - decode

- base64:
    - encode
    - decode

- base85:
    - encode
    - decode

- base64.urlsafe:
    - encode
    - decode

- morse:
    - encode
    - decode

- rot13:
    - shift
    - unshift

- caesar:
    - shift
    - unshift

- hexdump:
    - encode

- dummy:
    - encode
    - decode

- md5:
    - hash

- sha1:
    - hash

- sha224:
    - hash

- sha256:
    - hash

- sha384:
    - hash

- sha512:
    - hash

- sha3.224:
    - hash

- sha3.256:
    - hash

- sha3.384:
    - hash

- sha3.512:
    - hash

- shake128:
    - hash

- shake256:
    - hash

- black2s:
    - hash

- black2b:
    - hash

- hmac:
    - hash

# Version 2.0.0
## H3x0r
    - no need to think hexor is taken from the word (hex/hexadecimal)

---

- binary:
    - encode
    - decode

- braille:
    - encode
    - decode

- url:
    - encode
    - decode

- md2:
    - hash

- md4:
    - hash

- adler32:
    - hash

- ripemd160:
    - hash

- keccak224:
    - hash

- keccak256:
    - hash

- keccak384:
    - hash

- keccak512:
    - hash

- crc8:
    - hash

- crc16:
    - hash

- crc32:
    - hash

- ntlm:
    - hash

- cmac:
    - hash

- bcrypt:
    - hash

- poly1305:
    - hash

- whirlpool:
    - hash

- aes128:
    - encrypt
    - decrypt

- punycode:
    - encode
    - decode

# Version 2.0.1
### Patches:
- hBase58.py:12
  - Base58 encode even if it put on decode.
- hSha224.py:6,8
  - Sha224 hash on sha1

# v2_1_2
### Added:
    1. added 11 more new types.
    2. searchable types.
    3. added morse code seperators.
    3. added morse code spacers.
    4. added more and implementable morse code, _ and . characters.
### Edited:
    1. From (Window starts in full-screen mode) to (normal mode).
    2. implemented morse (code).
### Updated:
    Dummy:
        1. can select characters:
            1. english letters upper
            2. english letters lower
            3. global punctuations
            4. arabic letters
            5. arabic numbers
            6. arabic punctuations
            7. arabic formatters
        2. added more characters:
            1. arabic punctuations
            2. arabic formatters
        3. added 5 more seperators:
            1. arabic punctuations
### Patches:
    1. morse characters wrong implementation
