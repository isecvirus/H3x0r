import urllib.parse

class URL:
    def encode(self, url):
        return urllib.parse.quote(url)
    def decode(self, url):
        return urllib.parse.unquote(url)

Url = URL()