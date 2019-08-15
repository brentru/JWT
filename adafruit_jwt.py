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
from adafruit_jwt.tools.string import b42_urlsafe_encode

try:
    from binascii import b2a_base64
except ImportError:
    from adafruit_rsa.tools.binascii import b2a_base64
    pass

__version__ = "0.0.0-auto.0"
__repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_JWT.git"

# 4.1. Registered Claim names
CLAIM_SET = {"iss": None, "sub": None, "aud": None,
              "exp": None, "nbf": None, "iat": None,
              "jti": None}

class JWT:
    """JSON Web Token helper for CircuitPython.
        :param str algo: Encryption algorithm used for claims. Can be None.
    Warning: JWTs are credentials, which can grant access to resources.
                Be careful where you paste them!

    """

    def __init__(self, algo="RSA"):
        self._algo = algo

    def create_jwt(self, claims, private_key_data):
        """Creates and returns a new JSON Web Token.
        :param str: Decoded RSA private key data.
        """
        # Create a private key object with private_key_data
        if self._algo == "RSA":
            print("Creating private key...")
            priv_key = PrivateKey(*private_key_data)
        else:
            raise TypeError(
                "This library currently only supports RSA private keys.")
        # Create a JWT Claims Set containing the provided claims.
        # https://tools.ietf.org/html/rfc7519#section-7.1
        # Decode the provided claims, starting with Registered Claim Names
        claim = None
        for claim in claims:
            print(claim)
            print(CLAIM_SET)
            if claim in CLAIM_SET:
                CLAIM_SET[claim] = claims[claim]
            # Check the Private Claim Names
            if claim not in CLAIM_SET:
                CLAIM_SET[claim] = claims[claim]
        # Encode the claims set
        claim_set = b42_urlsafe_encode(json.dumps(CLAIM_SET).encode("utf-8"))
        # Create the JOSE Header
        # https://tools.ietf.org/html/rfc7519#section-5
        jose_header = {
            "alg" : self._algo,
            "type" : "jwt"
        }
        # Encode the jose_header
        jose_header = b42_urlsafe_encode(json.dumps(jose_header).encode("utf-8"))
        # Build the full payload to-be-encoded
        # TODO: this could all be done in one step within format method...
        payload = "{}.{}".format(jose_header, claim_set)
        # Compute the signature
        if self._algo == None:
            jwt = "{}.{}".format(jose_header, claim_set)
        elif self._algo == "RSA":
            signature = b42_urlsafe_encode(sign(payload, priv_key, "SHA-256"))
            jwt = "{}.{}".format(payload, signature)
        print("generating..")
        print("JWT: ", jwt)
        return jwt
