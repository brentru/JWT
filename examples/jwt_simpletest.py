import adafruit_jwt.adafruit_jwt as JWT

# Get private RSA key from a secrets.py file
try:
    from secrets import secrets
except ImportError:
    print("WiFi secrets are kept in secrets.py, please add them there!")
    raise

# Sample JWT Claims
claims = {"iss": "joe",
          "exp": 1300819380,
          "name": "John Doe",
          "admin": True}

# Create a JWT Helper with defined algorithm
jwt_helper = JWT.JWT(algo="RSA")

# Generate a JWT
print("Generating JWT...")
jwt = jwt_helper.generate(claims, secrets["private_key"])
print("Generated JWT: ", jwt)

# Validate a provided JWT
decoded_jwt = jwt_helper.validate(jwt)
print('Decoded JWT:\nJOSE Header: {}\nJWT Claims: {}'.format(decoded_jwt[0], decoded_jwt[1]))
