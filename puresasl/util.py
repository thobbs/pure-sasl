import sys


def bytes(text):
    """
    Convert Unicode text to UTF-8 encoded bytes.

    Since Python 2.6+ and Python 3+ have similar but incompatible
    signatures, this function unifies the two to keep code sane.

    :param text: Unicode text to convert to bytes
    :rtype: bytes (Python3), str (Python2.6+)
    """
    if sys.version_info < (3, 0):
        import __builtin__
        return __builtin__.bytes(text)
    else:
        import builtins
        if isinstance(text, builtins.bytes):
            # We already have bytes, so do nothing
            return text
        if isinstance(text, list):
            # Convert a list of integers to bytes
            return builtins.bytes(text)
        else:
            # Convert UTF-8 text to bytes
            return builtins.bytes(text, encoding='utf-8')

