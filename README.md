![Logo](hexor.ico)

# Version 1.0.0
## EDHC
###### E (ncode/ncrypt), D (ecode/ecrypt), Hash, Crack

# Types
```json
{
  "base16": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
  },
  "base32": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
  },
  "base58": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
  },
  "base64": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
  },
  "base85": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
  },
  "base64.urlsafe": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
  },
  "morse": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
  },
  "rot13": {
    "description": "",
    "methods": [
      "shift",
      "unshift"
    ],
    "options": ["text"]
  },
  "caesar": {
    "description": "",
    "methods": [
      "shift",
      "unshift"
    ],
    "options": ["text", "shifts"]
  },
  "hexdump": {
    "description": "",
    "methods": [
      "encode"
    ],
    "options": ["file", "fence", "type"]
  },
  "dummy": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
   },
    "md5": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "sha1": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "sha224": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "sha256": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "sha384": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "sha512": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "sha3.224": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "sha3.256": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "sha3.384": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "sha3.512": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "shake128": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "shake256": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "black2s": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "black2b": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
      },
    "hmac": {
        "description": "",
        "methods": [
          "hash"
        ],
        "options": ["text", "type"]
  }
}
```

# Version 2.0.0
## H3x0r
###### no need to think hexor is taken from the word (hex/hexadecimal)
```json
{
  "binary": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text", "separator"]
  },
  "braille": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
  },
  "url": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["url/parameters"]
  },
  "md2": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "md4": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "adler32": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text"]
  },
  "ripemd160": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "keccak224": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "keccak256": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "keccak384": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "keccak512": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "crc8": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "crc16": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text"]
  },
  "crc32": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text"]
  },
  "ntlm": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text"]
  },
  "cmac": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "bcrypt": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "password"]
  },
  "poly1305": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "whirlpool": {
    "description": "",
    "methods": [
      "hash"
    ],
    "options": ["text", "type"]
  },
  "aes128": {
    "description": "",
    "methods": [
      "encrypt",
      "decrypt"
    ],
    "options": ["text", "key"]
  },
  "punycode": {
    "description": "",
    "methods": [
      "encode",
      "decode"
    ],
    "options": ["text"]
  }
}
```