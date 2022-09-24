from json import loads, dumps
from csv import writer

def Json2Csv(input:str, output:str):
    try:
        data = loads(open(input, "r").read())

        d2 = open(output, 'w')
        w = writer(d2)

        oneTime = 0 # add header one time.
        for d in data:
            if oneTime == 0:
                w.writerow(d.keys())
                oneTime+=1
            w.writerow(d.values())
    except Exception:
        pass

def ToJSON(data, skipkeys:bool, ensure_ascii:bool, check_circular:bool, allow_nan:bool, indent:int=4, sort_keys:bool=False):
    """
      skipkeys: bool,
      ensure_ascii: bool,
      check_circular: bool,
      allow_nan: bool,
      indent: int,
      sort_keys: bool

          If ``skipkeys`` is true then ``dict`` keys that are not basic types
    (``str``, ``int``, ``float``, ``bool``, ``None``) will be skipped
    instead of raising a ``TypeError``.

    If ``ensure_ascii`` is false, then the return value can contain non-ASCII
    characters if they appear in strings contained in ``obj``. Otherwise, all
    such characters are escaped in JSON strings.

    If ``check_circular`` is false, then the circular reference check
    for container types will be skipped and a circular reference will
    result in an ``RecursionError`` (or worse).

    If ``allow_nan`` is false, then it will be a ``ValueError`` to
    serialize out of range ``float`` values (``nan``, ``inf``, ``-inf``) in
    strict compliance of the JSON specification, instead of using the
    JavaScript equivalents (``NaN``, ``Infinity``, ``-Infinity``).

    If ``indent`` is a non-negative integer, then JSON array elements and
    object members will be pretty-printed with that indent level. An indent
    level of 0 will only insert newlines. ``None`` is the most compact
    representation.

    If specified, ``separators`` should be an ``(item_separator, key_separator)``
    tuple.  The default is ``(', ', ': ')`` if *indent* is ``None`` and
    ``(',', ': ')`` otherwise.  To get the most compact JSON representation,
    you should specify ``(',', ':')`` to eliminate whitespace.

    ``default(obj)`` is a function that should return a serializable version
    of obj or raise TypeError. The default simply raises TypeError.

    If *sort_keys* is true (default: ``False``), then the output of
    dictionaries will be sorted by key.
    """
    try:
        return dumps(FromJSON(data), skipkeys=skipkeys, ensure_ascii=ensure_ascii, check_circular=check_circular, allow_nan=allow_nan, indent=indent, sort_keys=sort_keys)
    except Exception:
        return ''
def FromJSON(data:str):
    try:
        return loads(data)
    except Exception:
        return ''