# cli.py

import argparse
from send import send_file
from register import register_user

def main():
    parser = argparse.ArgumentParser(description="Secure File Transfer CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Register command
    reg_parser = subparsers.add_parser("register", help="Register a user")
    reg_parser.add_argument("--username", required=True, help="Username")
    reg_parser.add_argument("--token", required=True, help="User token")
    reg_parser.add_argument("--public-key", required=True, help="Path to your public key")
    reg_parser.add_argument("--url", required=True, help="Server register URL")

    # Send file command
    send_parser = subparsers.add_parser("send", help="Send a file securely")
    send_parser.add_argument("--file", required=True, help="File to send")
    send_parser.add_argument("--receiver-key", required=True, help="Receiver public key path")
    send_parser.add_argument("--sender-key", required=True, help="Sender private key path")
    send_parser.add_argument("--token-path", required=True, help="Path to your token file")
    send_parser.add_argument("--username", required=True, help="Your username")
    send_parser.add_argument("--url", required=True, help="Server upload URL")

    args = parser.parse_args()

    if args.command == "register":
        register_user(
            username=args.username,
            token=args.token,
            public_key_path=args.public_key,
            url=args.url
        )
    elif args.command == "send":
        send_file(
            file_path=args.file,
            receiver_pubkey_path=args.receiver_key,
            sender_privkey_path=args.sender_key,
            token_path=args.token_path,
            username=args.username,
            url=args.url
        )

if __name__ == "__main__":
    main()
