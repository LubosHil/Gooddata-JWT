import json
import cryptography
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk
import jwt
from datetime import datetime, timedelta


def generate_rsa_key_pair(
        size: int = 2048,  # User-configurable: Key size
        kid: str = "hilse_python",  # User-configurable: Key ID
        passphrase: str = "passphrase",  # User-configurable: Key passphrase
) -> cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey:

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
    )

    private_key_data = private_key.private_bytes(
        encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
        format=cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=cryptography.hazmat.primitives.serialization.BestAvailableEncryption(passphrase.encode('utf-8')),
    )

    print("Private Key (X.509 PEM Format):")
    print(private_key_data.decode('latin-1'))

    public_key_data = private_key.public_key().public_bytes(
        encoding=cryptography.hazmat.primitives.serialization.Encoding.PEM,
        format=cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("\nPublic Key (X.509 PEM Format):")
    print(public_key_data.decode('latin-1'))

    jwk_dict = make_jwk_from_public_key(public_key_data, kid=kid)

    print("\nJWK:")
    print(json.dumps(jwk_dict, indent=4))

    return private_key


def make_jwk_from_public_key(
        pem_data: bytes,
        kid: str
) -> dict:
    jwk_dict = dict()

    public_key = jwk.JWK.from_pem(pem_data)
    jwk_dict = json.loads(public_key.export_public())
    jwk_dict['kid'] = kid
    jwk_dict['alg'] = 'RS256'
    return jwk_dict


def JWT(private_key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey, expiration: timedelta, jti, sub, name):
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "hilse_python"
    }

    payload = {
        "sub": sub,  #User-configurable: Gooddata userId
        "name": name,
        "jti": jti,  # User-configurable: Unique identifier for the JWT
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + expiration  # User-configurable: JWT expiration time
    }

    print("JWT valid from:", datetime.utcnow())
    print("JWT valid to:", datetime.utcnow() + expiration)

    jwt_token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers=header
    )

    print("JWT Token:", jwt_token)


if __name__ == "__main__":
    print("Generating private key...")
    private_key = generate_rsa_key_pair()

    while True:
        print("New JWT generator")
        sub = input("Input claim sub: ")
        name = input("Input claim name: ")
        jti = input("Input jti: ")
        exp = input("Input expiration in seconds from now: ")
        JWT(private_key, timedelta(seconds=int(exp)), jti=jti, sub=sub, name=name)
        end = input("Do you want to create another JWT? [yes] ")
        if end != "yes":
            break


"""
JWT(private_key, timedelta(seconds=3600000), jti="mytest1")
print("\n")
JWT(private_key, timedelta(seconds=3600), jti="mytest2")
print("\n")
JWT(private_key, timedelta(seconds=60), jti="mytest3")
"""