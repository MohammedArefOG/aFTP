import argparse
import base64
import time
import os
import requests
from cryptography.hazmat.primitives import serialization
from crypto_utils import (
    load_public_key,
    load_private_key,
    encrypt_aes_key,
    encrypt_file,
    generate_text_signature,
    hash_file_bytes
)

def send_file(file_path, receiver_pubkey_path, sender_privkey_path, url, username, token_path):
    # Load keys
    receiver_pub = load_public_key(receiver_pubkey_path)
    sender_priv = load_private_key(sender_privkey_path)

    # Read file bytes
    with open(file_path, "rb") as f:
        file_bytes = f.read()

    # Hash the file bytes (base64 encoded)
    file_hash = hash_file_bytes(file_bytes)

    # Generate random AES key and encrypt the file
    aes_key = os.urandom(32)
    encrypted_file = encrypt_file(file_bytes, aes_key)

    # Encrypt AES key with receiver's RSA public key
    encrypted_key = encrypt_aes_key(aes_key, receiver_pub)

    # Sign the original file hash (decode base64 first)
    signature_bytes = generate_text_signature(sender_priv, base64.b64decode(file_hash))
    signature_b64 = base64.b64encode(signature_bytes).decode()

    # Load and hash the user token, then sign the token hash
    with open(token_path, "r") as f:
        token = f.read().strip()
    token_hash = hash_file_bytes(token.encode())
    token_proof_bytes = generate_text_signature(sender_priv, base64.b64decode(token_hash))
    token_proof_b64 = base64.b64encode(token_proof_bytes).decode()

    # Prepare payload for sending
    payload = {
        "filename": os.path.basename(file_path),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
        "encrypted_file": base64.b64encode(encrypted_file).decode(),
        "sender_public_key": sender_priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
        "text_signature": signature_b64,
        "timestamp": int(time.time()),
        "original_hash": file_hash,
        "token_hash": token_hash,
        "user_token_proof": token_proof_b64,
        "username": username
    }

    print(f"Sending file '{file_path}' with authentication...")
    response = requests.post(url, json=payload)
    print("Server response:", response.text)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure file transfer sender")
    parser.add_argument("--file", required=True, help="Path to file to send")
    parser.add_argument("--to", required=True, help="Destination URL (e.g., http://localhost:8000/upload)")
    parser.add_argument("--receiver-key", required=True, help="Receiver's RSA public key file path")
    parser.add_argument("--sender-key", required=True, help="Sender's RSA private key file path")
    parser.add_argument("--username", required=True, help="Sender's username")
    parser.add_argument("--user-token", required=True, help="Path to user's token file")

    args = parser.parse_args()

    send_file(
        file_path=args.file,
        receiver_pubkey_path=args.receiver_key,
        sender_privkey_path=args.sender_key,
        url=args.to,
        username=args.username,
        token_path=args.user_token
    )
