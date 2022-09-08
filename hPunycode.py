import idna

class PUNYCODE:
    def encode(self, string:bytes):
        try:
            return idna.encode(string)
        except Exception: # idna.core.InvalidCodepoint
            return ''
    def decode(self, string:bytes):
        try:
            return idna.decode(string)
        except Exception: # idna.core.InvalidCodepoint
            return ''
Punycode = PUNYCODE()