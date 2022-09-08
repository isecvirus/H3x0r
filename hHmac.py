import hmac


def Hmac(key: str, msg: str, digestmod: str, type: str):
    if type == 'hexdigest':
        return hmac.new(key=key.encode(), msg=msg.encode(), digestmod=digestmod).hexdigest()
    elif type == 'digest':
        return str(hmac.new(key=key.encode(), msg=msg.encode(), digestmod=digestmod).digest())[2:-1]
