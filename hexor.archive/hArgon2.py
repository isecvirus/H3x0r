from argon2 import PasswordHasher

class Argon2:
    ph = PasswordHasher()
    def hash(self, password):
        try:
            return self.ph.hash(password)
        except Exception:
            return ''
    def verify(self, hash, password):
        try:
            self.ph.verify(hash=hash, password=password)
            return "Password matches the provided hash"
        except Exception as error:
            return str(error)
argon2 = Argon2()