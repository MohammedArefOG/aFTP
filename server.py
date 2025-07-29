from flask import Flask, request, jsonify
import base64
import time
import os
import logging
from crypto_utils import (
    load_public_key,
    load_private_key,
    verify_text_signature,
    decrypt_aes_key,
    decrypt_file,
    hash_file_bytes
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Directory to save received decrypted files
RECEIVED_FOLDER = "received_files"
os.makedirs(RECEIVED_FOLDER, exist_ok=True)

# Simulated in-memory user DB: username -> {token_hash: ..., public_key: ...}
REGISTERED_USERS = {}

# Load server's private key for decrypting AES keys
server_private_key = load_private_key("keys/receiver_private.pem")

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    token = data.get("token")
    pubkey_str = data.get("public_key")
    if not username or not token or not pubkey_str:
        return jsonify({"status": "error", "message": "Missing registration data"}), 400

    token_hash = hash_file_bytes(token.encode())
    try:
        public_key = load_public_key(pubkey_str.encode())
    except Exception as e:
        return jsonify({"status": "error", "message": f"Invalid public key: {e}"}), 400

    REGISTERED_USERS[username] = {
        "token_hash": token_hash,
        "public_key": public_key
    }
    logging.info(f"Registered user: {username}")
    return jsonify({"status": "success", "message": f"User {username} registered."})

@app.route("/upload", methods=["POST"])
def upload():
    data = request.json

    try:
        username = data.get("username")
        if username not in REGISTERED_USERS:
            return jsonify({"status": "error", "message": "Unknown user"}), 403

        user_record = REGISTERED_USERS[username]

        sender_public_key = load_public_key(data['sender_public_key'].encode())
        encrypted_key = base64.b64decode(data['encrypted_key'])
        encrypted_file = base64.b64decode(data['encrypted_file'])
        signature = base64.b64decode(data['text_signature'])
        file_hash_b64 = data['original_hash']
        timestamp = int(data['timestamp'])
        token_proof = base64.b64decode(data['user_token_proof'])
        token_hash_b64 = data['token_hash']

        # Replay protection: timestamp must be within 5 minutes
        now = int(time.time())
        if abs(now - timestamp) > 300:
            logging.warning(f"Replay attack suspected: timestamp {timestamp} too old/new (now {now})")
            return jsonify({"status": "error", "message": "Timestamp out of acceptable range"}), 403

        # Verify file hash signature using sender public key
        if not verify_text_signature(sender_public_key, signature, file_hash_b64):
            logging.warning("Invalid file signature")
            return jsonify({"status": "error", "message": "Invalid file signature"}), 403

        # Authenticate user by verifying token proof against stored token hash and public key
        stored_token_hash = user_record['token_hash']
        if stored_token_hash != token_hash_b64:
            logging.warning("Token hash mismatch")
            return jsonify({"status": "error", "message": "Token hash mismatch"}), 403

        if not verify_text_signature(user_record['public_key'], token_proof, token_hash_b64):
            logging.warning("User token proof verification failed")
            return jsonify({"status": "error", "message": "User authentication failed"}), 403

        # Decrypt AES key using server's private key
        aes_key = decrypt_aes_key(encrypted_key, server_private_key)
        # Decrypt file content
        decrypted_file = decrypt_file(encrypted_file, aes_key)

        # Save decrypted file
        filename = f"{int(time.time())}_{data['filename']}"
        filepath = os.path.join(RECEIVED_FOLDER, filename)
        with open(filepath, "wb") as f:
            f.write(decrypted_file)

        logging.info(f"Received and decrypted file saved as: {filepath}")

        return jsonify({"status": "success", "message": "File received, signature verified, and decrypted."})

    except Exception as e:
        logging.error(f"Error processing upload: {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
