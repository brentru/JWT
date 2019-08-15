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
import json
from adafruit_rsa import PrivateKey, sign

# pylint: disable=no-name-in-module
from adafruit_jwt.url_tools import urlsafe_b64encode, urlsafe_b64decode

__version__ = "0.0.0-auto.0"
__repo__ = "https://github.com/adafruit/Adafruit_CircuitPython_JWT.git"

# pylint: disable=no-member
class JWT:
    """JSON Web Token helper for CircuitPython.
        :param str algo: Encryption algorithm used for claims. Can be None.
    Warning: JWTs are credentials, which can grant access to resources.
                Be careful where you paste them!

    """

    def __init__(self, algo="RSA"):
        self._algo = algo
        self._claim_set = {}

    @staticmethod
    def validate(jwt):
        """Validates a provided JWT. Does not support nested signing.
        :param str jwt: JSON Web Token.
        :returns: The message's decoded JOSE header and claims.
        :rtype: tuple
        """
        # Verify JWT contains at least one period ('.')
        if jwt.find(".") == -1:
            raise ValueError("JWT must have at least one period")
        # Separate the encoded JOSE Header
        jose_header = jwt.split(".")[0]
        # Decode JOSE Header
        try:
            jose_header = urlsafe_b64decode(jose_header)
        except UnicodeError:
            raise UnicodeError("Invalid JOSE Header encoding.")
        if "type" not in jose_header:
            raise TypeError("JOSE Header does not contain required type key.")
        if "alg" not in jose_header:
            raise TypeError("Jose Header does not contain required alg key.")
        # Separate encoded claim set
        claims = jwt.split(".")[1]
        try:
            claims = json.loads(urlsafe_b64decode(claims))
        except UnicodeError:
            raise UnicodeError("Invalid claims encoding.")
        if not hasattr(claims, "keys"):
            raise TypeError("Provided claims is not a JSON dict. object")
        return (jose_header, claims)

    def generate(self, claims, private_key_data):
        """Generates and returns a new JSON Web Token.
        :param str: Decoded RSA private key data.
        :rtype: str
        """
        # Create a private key object with private_key_data
        if self._algo == "RSA":
            priv_key = PrivateKey(*private_key_data)
        else:
            raise TypeError(
                "This library currently only supports RSA private keys.")
        # Create a JWT Claims Set containing the provided claims.
        # https://tools.ietf.org/html/rfc7519#section-7.1
        # Decode the provided claims, starting with Registered Claim Names
        for claim in claims:
            self._claim_set[claim] = claims[claim]
        # Encode the claims set
        #self._claim_set = urlsafe_b64encode(json.dumps(self._claim_set).encode("utf-8"))
        # Create the JOSE Header
        # https://tools.ietf.org/html/rfc7519#section-5
        jose_header = {
            "alg": self._algo,
            "type": "jwt"
        }
        # Encode the jose_header
        #jose_header = urlsafe_b64encode(json.dumps(jose_header).encode("utf-8"))
        # Build the full payload-to-be-encoded
        # TODO: this could all be done in one step within format method...
        payload = "{}.{}".format(urlsafe_b64encode(json.dumps(jose_header).encode("utf-8")),
                                 urlsafe_b64encode(json.dumps(self._claim_set).encode("utf-8")))
        # Compute the signature
        if self._algo is None:
            jwt = "{}.{}".format(jose_header, self._claim_set)
        elif self._algo == "RSA":
            signature = urlsafe_b64encode(sign(payload, priv_key, "SHA-256"))
            jwt = "{}.{}".format(payload, signature)
        return jwt
