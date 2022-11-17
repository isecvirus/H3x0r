![Logo](logo/hexor.ico)

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

# Version 2.1.2
### Added:
  - added 11 more new types.
  - searchable types.
  - added morse code seperators.
  - added morse code spacers.
  - added more and implementable morse code, _ and . characters.
  - paste button for input and output
  - Types:
    - hexadecimal
      - encode
      - decode
    - color to rgb
      - convert
    - color to hex
      - convert
    - hex to color
      - convert
    - hex to rgb
      - convert
    - rgb to hex
      - convert
    - rgb to color
      - convert
    - html
      - encode
      - decode
    - kmac128
      - hash
    - kmac256
      - hash
    - timestamp
      - convert
    - replace
      - replace
    - remove
      - remove
### Edited:
  - From (Window starts in full-screen mode) to (normal mode).
  - implemented morse (code).
  - safe/unsafe/checksum buttons are unique now and renamed and shows based on what type are you selecting
### Updated:
  - Dummy:
    - can select characters:
      - english letters upper
      - english letters lower
      - global punctuations
      - arabic letters
      - arabic numbers
      - arabic punctuations
      - arabic formatters
    - added more characters:
      - arabic punctuations
        - arabic formatters
    - added 5 more seperators:
      - arabic punctuations
### Patches:
  - morse characters wrong implementation
