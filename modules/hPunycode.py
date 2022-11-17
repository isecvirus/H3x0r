import idna

class PUNYCODE:
    def encode(self, domain:str):
        try:
            return idna.encode(s=domain)
        except Exception: # idna.core.InvalidCodepoint
            return ''
    def decode(self, domain:bytes):
        try:
            return idna.decode(s=domain)
        except Exception: # idna.core.InvalidCodepoint
            return ''
Punycode = PUNYCODE()