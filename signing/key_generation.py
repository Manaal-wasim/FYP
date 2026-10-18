
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

#Generates a 3072-bit RSA key pair for each account.
#Returns the public key in readable PEM format for MySQL.
#Encrypts the private key before it is written to a file.
#Uses KEY_ENCRYPTION_SECRET from .env to encrypt the private key.
def generate_key_pair(encryption_secret):
    """
    Generate an RSA key pair.

    The public key is returned in PEM format.
    The private key is encrypted before it is returned.
    """
    if not encryption_secret or len(encryption_secret) < 32:
        raise ValueError(
            "KEY_ENCRYPTION_SECRET must be at least 32 characters."
        )

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )

    public_key = private_key.public_key()

    # Public key: stored in MySQL
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Private key: encrypted before it is saved to disk
    encrypted_private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            encryption_secret.encode("utf-8")
        ),
    )

    return public_pem.decode("utf-8"), encrypted_private_pem