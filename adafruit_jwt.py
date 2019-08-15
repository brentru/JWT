# The MIT License (MIT)
#
# Copyright (c) 2019 Brent Rubell for Adafruit Industries
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
`adafruit_jwt`
================================================================================

CircuitPython helper library for generation and verification of JSON Web Tokens.


* Author(s): Brent Rubell

Implementation Notes
--------------------

**Hardware:**

**Software and Dependencies:**

* Adafruit CircuitPython firmware for the supported boards:
  https://github.com/adafruit/circuitpython/releases

* Adafruit's RSA library:
  https://github.com/adafruit/Adafruit_CircuitPython_RSA
"""
import time
import json
from adafruit_rsa import PrivateKey, sign
from adafruit_jwt.tools import string

try:
    from binascii import b2a_base64
except ImportError:
    from adafruit_rsa.tools.binascii import b2a_base64
    pass

__version__ = "0.0.0-auto.0"
__repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_JWT.git"

# 4.1. Registered Claim names
reg_claims = {"iss", "sub", "aud",
              "exp", "nbf", "iat",
              "jti"}

class JWT:
    """JSON Web Token helper for CircuitPython.
        :param dict claims: JSON object whose members are the
                            claims conveyed by the JWT.
        :param str algo: Encryption algorithm used for claims. Can be None.
    Warning: JWTs are credentials, which can grant access to resources.
                Be careful where you paste them!

    """
    def __init__(self, claims, algo="RSA"):
        self._claims = claims
        self._algo =algo
        # 4.1. Registered Claim Names
        self._iss = None
        self._sub = None
        self._aud = None
        self._exp = None
        self._nbf = None
        self._iat = None
        self._jti = None
    
    def create_jwt(self, private_key_data):
        """Creates and returns a new JSON Web Token.
        :param str: Decoded RSA private key data.
        """
        # Create a private key object with private_key_data
        if self._algo == "RSA":
            priv_key = PrivateKey(*self.private_key_data)
        else:
            raise TypeError("This library currently only supports RSA private keys.")
        # Create a JWT Claims Set containing the provided claims.
        # https://tools.ietf.org/html/rfc7519#section-7.1
        # Decode the provided claims, starting with Registered Claim Names

