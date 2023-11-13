import typer
import json
import logging
import datetime
import cryptography
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwcrypto import jwk
import jwt
from datetime import datetime, timedelta

def generate(
        size: int = 2048,
        alg: str = typer.Option(default="RS256",
                                help="The specific cryptographic algorithm used with the key. Supported values: RS256, RS384, RS512"),
        use: str = typer.Option(default="sig", help="How the key was meant to be used. Supported values: sig"),
        kid: str = "lhilse",
        passphrase: str = "passphrase",
) -> cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey:

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=size,
    )

    private_key_data = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode('utf-8')),
    )

    print("Private Key (X.509 PEM Format):")
    print(private_key_data.decode('latin-1'))

    public_key_data = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    print("\nPublic Key (X.509 PEM Format):")
    print(public_key_data.decode('latin-1'))

    # User-configurable: example of X509 certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"GoodData"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"gooddata.com"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        # Our certificate will be valid for 30 days
        datetime.utcnow() + timedelta(days=30)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
        # Sign our certificate with our private key
    ).sign(private_key, hashes.SHA256())

    print("\nSelf-Signed Certificate:")
    cert_data = cert.public_bytes(serialization.Encoding.PEM).decode('latin-1')
    print(cert_data)

    x5c = "".join(cert_data.splitlines()[1:-1])
    jwk_dict = make_jwk_from_pem(public_key_data, alg=alg, use=use, x5c=[x5c], kid=kid)

    print("\nJWK:")
    print(json.dumps(jwk_dict, indent=4))

    return private_key


def make_jwk_from_pem(
        pem_data: bytes,
        alg: str,
        use: str,
        x5c: list,
        kid: str
) -> dict:
    """Convert a PEM into a JWK

    :param pem_data:
    :return jwk_dict:
    """
    jwk_dict = dict()

    try:
        key_obj = jwk.JWK.from_pem(pem_data)
    except Exception as e:
        logging.debug('{}'.format(e))
    else:
        jwk_dict = json.loads(key_obj.export())
        if kid:
            jwk_dict['kid'] = kid
        else:
            jwk_dict['kid'] = key_obj.thumbprint(hashalg=hashes.SHA1())

        jwk_dict['x5t'] = key_obj.thumbprint(hashalg=hashes.SHA1())
        jwk_dict['x5c'] = x5c
        jwk_dict['alg'] = alg
        jwk_dict['use'] = use

        # Convert OptionInfo objects to their values
        jwk_dict = convert_optioninfo_values(jwk_dict)

    return jwk_dict


def convert_optioninfo_values(jwk_dict: dict) -> dict:
    """Convert OptionInfo objects to their values in a dictionary.

    :param jwk_dict:
    :return converted_dict:
    """
    converted_dict = {}
    for key, value in jwk_dict.items():
        if isinstance(value, dict):
            converted_dict[key] = convert_optioninfo_values(value)
        elif hasattr(value, "default"):  # Check if the object has a 'default' attribute
            converted_dict[key] = value.default
        else:
            converted_dict[key] = value
    return converted_dict


def JWT(private_key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey, expiration: timedelta, jti):
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "lhilse"
    }
    current_time = datetime.now()
    payload = {
        "sub": "example", # User-configurable: sub
        "name": "example", # User-configurable: name
        "jti": jti,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + expiration
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



private_key = generate()

JWT(private_key, timedelta(seconds=3600000), jti="mytest1")
print("\n")
JWT(private_key, timedelta(seconds=3600), jti="mytest2")
print("\n")
JWT(private_key, timedelta(seconds=60), jti="mytest3")
