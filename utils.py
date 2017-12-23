import re
import struct

_ESCAPE_PATTERN = re.compile(b'''\\\\(
x[0-9a-fA-F]{2} |
[0-7]{1,3} |
.)''', re.VERBOSE)
_ESCAPE_MAP = {
    b'n': b'\n',
    b'r': b'\r',
    b't': b'\t',
}
_ESCAPED_CHARS = b'"\\\''


def text_unescape(text):
    """Converts a string with escape sequences to bytes."""
    text_bin = text.encode("utf8")
    def sub_char(m):
        what = m.group(1)
        if what[0:1] == b'x' and len(what) == 3:
            return int_as_byte(int(what[1:], 16))
        elif what[0:1] in b'01234567':
            return int_as_byte(int(what, 8))
        elif what in _ESCAPE_MAP:
            return _ESCAPE_MAP[what]
        elif what in _ESCAPED_CHARS:
            return what
        else:
            raise RuntimeError('Unknown escape sequence \\%s' %
                    what.decode('utf8'))
    return re.sub(_ESCAPE_PATTERN, sub_char, text_bin)


def parse_number_or_escape(text):
    try:
        return int(text, 0) if text else 0
    except ValueError:
        return text_unescape(text)


def int_as_byte(i):
    if '\0' == b'\0':
        return chr(i)
    else:
        return bytes([i])


def crc16(data):
    """CRC-16-CCITT computation with LSB-first and inversion."""
    crc = 0xffff
    for byte in data:
        crc ^= byte
        for bits in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return crc ^ 0xffff


def invert_dword(dword_bin):
    dword = struct.unpack("I", dword_bin)[0]
    return struct.pack("I", dword ^ 0xffffffff)
