"""
Demonstrates:
1. Symmetric encryption using AES-256-GCM
2. Asymmetric encryption using RSA-2048-OAEP
"""

import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


MESSAGE = b"My name is kyle."


def b64(data):
    """Convert bytes to data so they can be displayed as text."""
    return base64.b64encode(data).decode("utf-8")


# SYMMETRIC ENCRYPTION - AES-256-GCM


print("SYMMETRIC ENCRYPTION - AES-256-GCM")


# Generate a 256-bit key
symmetric_key = AESGCM.generate_key(bit_length=256)

# Generate a 12-byte nonce
nonce = AESGCM.generate_key(bit_length=128)[:12]

aes = AESGCM(symmetric_key)

# Encrypt
encrypted_message = aes.encrypt(nonce, MESSAGE, None)

# Decrypt
decrypted_message = aes.decrypt(nonce, encrypted_message, None)

print("Input message:")
print(MESSAGE.decode())

print("\nAES Key (Base64):")
print(b64(symmetric_key))

print("\nNonce (Base64):")
print(b64(nonce))

print("\nEncrypted message (Base64):")
print(b64(encrypted_message))

print("\nDecrypted message:")
print(decrypted_message.decode())



# ASYMMETRIC ENCRYPTION - RSA-2048-OAEP



print("ASYMMETRIC ENCRYPTION - RSA-2048-OAEP")


# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Get matching public key
public_key = private_key.public_key()

# Convert keys to readable PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Encrypt using the public key
encrypted_rsa = public_key.encrypt(
    MESSAGE,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Decrypt using the private key
decrypted_rsa = private_key.decrypt(
    encrypted_rsa,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Input message:")
print(MESSAGE.decode())

print("\nRSA Public Key:")
print(public_key_pem.decode())

print("RSA Private Key:")
print(private_key_pem.decode())

print("Encrypted message (Base64):")
print(b64(encrypted_rsa))

print("\nDecrypted message:")
print(decrypted_rsa.decode())