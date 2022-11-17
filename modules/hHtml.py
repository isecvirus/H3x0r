from html import escape, unescape
from bs4 import BeautifulSoup

def HTML_Extract(data:str, name:str, parser:str, type:str, limit:int=10):
    # https://www.crummy.com/software/BeautifulSoup/bs4/doc/

    """
    :param data: html code
    :param name: html tag
    :param parser: html.parser, lxml, lxml-xml, html5lib
        ~ html5lib (installation):
            * apt-get install python-html5lib
            * pip install html5lib
        ~ lxml, lxml-xml (installation):
            * apt-get install python-lxml
            * pip3 install lxml

    :param type str: all, this
    :param limit (default: 10) int:
    :return:
    """
    try:
        b = BeautifulSoup(data, features=parser)

        if type == "all":
            all = []
            found = b.find_all(name=name, limit=limit)
            for f in found:
                all.append(str(f).replace('\n', '').replace('\t', ''))
            return '\n'.join(all)
        elif type == "this":
            return b.find(name=name)
    except Exception:
        return ''

def HTML_encode(string:str, quote:bool):
    """
    :param string:
    :param quote:
        if quote:
            s = s.replace('"', "&quot;")
            s = s.replace('\'', "&#x27;")
    :return:
    """
    return escape(s=string, quote=quote)
def HTML_decode(string:str):
    return unescape(s=string)