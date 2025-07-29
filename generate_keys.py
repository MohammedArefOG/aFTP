# generate_keys.py

from crypto_utils import generate_rsa_keypair, save_key
import os

os.makedirs("keys", exist_ok=True)

# Sender key pair
sender_priv, sender_pub = generate_rsa_keypair()
save_key(sender_priv, "keys/sender_private.pem", is_private=True)
save_key(sender_pub, "keys/sender_public.pem")

# Receiver key pair
receiver_priv, receiver_pub = generate_rsa_keypair()
save_key(receiver_priv, "keys/receiver_private.pem", is_private=True)
save_key(receiver_pub, "keys/receiver_public.pem")

print("✅ RSA key pairs created in the 'keys/' directory.")
