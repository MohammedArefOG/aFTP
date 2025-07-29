import base64
import hashlib
import os
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def save_key(key, path, private=False):
    if private:
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        )
    else:
        pem = key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
    with open(path, "wb") as f:
        f.write(pem)

def load_private_key(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def load_public_key(path_or_bytes):
    # Accept either a path string or bytes directly
    if isinstance(path_or_bytes, str):
        with open(path_or_bytes, "rb") as f:
            data = f.read()
    else:
        data = path_or_bytes
    return serialization.load_pem_public_key(data)

def encrypt_aes_key(aes_key, receiver_pub):
    return receiver_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def decrypt_aes_key(encrypted_key, receiver_priv):
    return receiver_priv.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def encrypt_file(file_bytes, aes_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(file_bytes) + encryptor.finalize()
    return iv + encrypted  # prepend IV

def decrypt_file(encrypted_bytes, aes_key):
    iv = encrypted_bytes[:16]
    ciphertext = encrypted_bytes[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted

def hash_file_bytes(file_bytes):
    # Return base64 encoded SHA256 hash string
    return base64.b64encode(hashlib.sha256(file_bytes).digest()).decode()

def generate_text_signature(private_key, data_bytes):
    # data_bytes is raw bytes
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature  # raw bytes, caller should base64 encode if needed

def sign_text(private_key, data_bytes):
    # Convenience function: returns base64 encoded signature string
    raw_sig = generate_text_signature(private_key, data_bytes)
    return base64.b64encode(raw_sig).decode()

def verify_text_signature(public_key, signature, original_data_b64):
    original_data = base64.b64decode(original_data_b64)
    try:
        public_key.verify(
            signature,
            original_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
