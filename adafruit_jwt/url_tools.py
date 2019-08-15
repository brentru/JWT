# The MIT License (MIT)
#
# Copyright (c) 2019 Johan Brichau
# Copyright Paul Sokolovsky, 2014
# Modified by Brent Rubell for Adafruit Industries, 2019
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""
`url_tools.py`
======================================================
AS920 The Things Network Frequency Plans
* Author(s): Johan Brichau, Paul Sokolovsky, Brent Rubell
"""

import io
from adafruit_rsa.tools.binascii import b2a_base64, a2b_base64

# Types acceptable as binary data
BYTES_TYPES = (bytes, bytearray)

def _bytes_from_decode_data(str_data):
    if isinstance(str_data, str):
        try:
            return str_data.encode('ascii')
        except:
            raise ValueError(
                'string argument should contain only ASCII characters')
    elif isinstance(str_data, BYTES_TYPES):
        return str_data
    else:
        raise TypeError(
            "argument should be bytes or ASCII string, not %s" % str_data.__class__.__name__)

def urlsafe_b64encode(payload):
    """Encode bytes-like object s using the URL-
    and filesystem-safe alphabet"""
    return translate(b2a_base64(payload)[:-1].decode("utf-8"), {ord("+"): "-", ord("/"): "_"})


def urlsafe_b64decode(payload):
    """Decode bytes-like object or ASCII string s using the URL-
    and filesystem-safe alphabet"""
    return a2b_base64(_bytes_from_decode_data(payload)).decode("utf-8")

# pylint: disable=invalid-name
def translate(str_data, table):
    """Delete all characters from s that are in deletechars
    (if present), and then translate the characters using table
    """
    sb = io.StringIO()
    for c in str_data:
        v = ord(c)
        if v in table:
            v = table[v]
            if isinstance(v, int):
                sb.write(chr(v))
            elif v is not None:
                sb.write(v)
        else:
            sb.write(c)
    return sb.getvalue()
