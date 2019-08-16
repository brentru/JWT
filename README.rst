Introduction
============

.. image:: https://readthedocs.org/projects/adafruit-circuitpython-jwt/badge/?version=latest
    :target: https://circuitpython.readthedocs.io/projects/jwt/en/latest/
    :alt: Documentation Status

.. image:: https://img.shields.io/discord/327254708534116352.svg
    :target: https://discord.gg/nBQh6qu
    :alt: Discord

.. image:: https://travis-ci.com/adafruit/Adafruit_CircuitPython_JWT.svg?branch=master
    :target: https://travis-ci.com/adafruit/Adafruit_CircuitPython_JWT
    :alt: Build Status

CircuitPython helper library for generation and verification of JSON Web Tokens (JWT).

JSON Web Tokens are an open, industry standard `RFC 7519 <https://tools.ietf.org/html/rfc7519>`_ method for representing claims securely between two parties.


Dependencies
=============
This driver depends on:

* `Adafruit CircuitPython <https://github.com/adafruit/circuitpython>`_
* `Adafruit CircuitPython RSA <https://github.com/adafruit/Adafruit_CircuitPython_RSA>`_

Please ensure all dependencies are available on the CircuitPython filesystem.
This is easily achieved by downloading
`the Adafruit library and driver bundle <https://github.com/adafruit/Adafruit_CircuitPython_Bundle>`_.

Installing from PyPI
=====================
.. note:: This library is not available on PyPI yet. Install documentation is included
   as a standard element. Stay tuned for PyPI availability!

On supported GNU/Linux systems like the Raspberry Pi, you can install the driver locally `from
PyPI <https://pypi.org/project/adafruit-circuitpython-jwt/>`_. To install for current user:

.. code-block:: shell

    pip3 install adafruit-circuitpython-jwt

To install system-wide (this may be required in some cases):

.. code-block:: shell

    sudo pip3 install adafruit-circuitpython-jwt

To install in a virtual environment in your current project:

.. code-block:: shell

    mkdir project-name && cd project-name
    python3 -m venv .env
    source .env/bin/activate
    pip3 install adafruit-circuitpython-jwt

Usage Example
=============

JWT Generation

.. code-block:: python

    import adafruit_jwt.adafruit_jwt as JWT
    # Get private RSA key from a secrets.py file
    try:
        from secrets import secrets
    except ImportError:
        print("WiFi secrets are kept in secrets.py, please add them there!")
        raise

    # JWT Claims
    claims = {"iss": "joe",
            "exp": 1300819380,
            "name": "John Doe",
            "admin": True}

    # Create a JWT Helper with a defined algorithm
    jwt_helper = JWT.JWT(algo="RSA")

    # Generate a JWT
    jwt = jwt_helper.generate(claims, secrets["private_key"])
    print("Generated JWT: ", jwt)

JWT Decoding and Verification

.. code-block:: python

    import adafruit_jwt.adafruit_jwt as JWT

    # Example JWT String
    jwt = "eyJ0eXBlIjogImp3dCIsICJhbGciOiAiUlNBIn0=.eyJpc3MiOiAiam9lIiwgImV4cCI6IDEzMDA4MTkzODAsICJuYW1lIjogIkpvaG4gRG9lIiwgImFkbWluIjogdHJ1ZX0=
            .BQV3aeiPgJbxR2/CyLEnVUM+ZGVaHCR2QRKxRtZUeOaVqDv7DMDQFCfF76vBDQAeKeZDzK1a4NndjQxhdzZ4TiPCb+UOB2CtFIhZCmDMMQwuU4UW12LWBogg21rBVVO8AWTcO7Kj9q+wzD8crkdOcq5qCxOFq4/u+gaXh58OYWj/dwaa0YYghz9Qa+gU0YqSuGgMZ97aCLkw37Y4X5yVsqUFtwN
            dGxhDpFQtdtrxYGcRC1RotvE2C9mKFeu0DaGv6O6JwXkdsNVd2jsFj/b3Ndeh+eIj1Suek2Ebkhkyp/Q9tqz84mkb2ZBREO2AUnsQDSYAFk0XD9HJRsm8F6xlow=="
    decoded_jwt = jwt_helper.validate(jwt)
    print('Decoded JWT:\nJOSE Header: {}\nJWT Claims: {}'.format(decoded_jwt[0], decoded_jwt[1]))


Contributing
============

Contributions are welcome! Please read our `Code of Conduct
<https://github.com/adafruit/Adafruit_CircuitPython_JWT/blob/master/CODE_OF_CONDUCT.md>`_
before contributing to help this project stay welcoming.

Sphinx documentation
-----------------------

Sphinx is used to build the documentation based on rST files and comments in the code. First,
install dependencies (feel free to reuse the virtual environment from above):

.. code-block:: shell

    python3 -m venv .env
    source .env/bin/activate
    pip install Sphinx sphinx-rtd-theme

Now, once you have the virtual environment activated:

.. code-block:: shell

    cd docs
    sphinx-build -E -W -b html . _build/html

This will output the documentation to ``docs/_build/html``. Open the index.html in your browser to
view them. It will also (due to -W) error out on any warning like Travis will. This is a good way to
locally verify it will pass.
