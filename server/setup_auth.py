import json
import secrets
import getpass
from pathlib import Path

from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent.parent
AUTH_CONFIG_PATH = BASE_DIR / "data" / "auth_config.json"


def setup_auth():
    print("Tracker Beta Admin Setup")
    print("------------------------")

    username = input("Admin username: ").strip()

    if not username:
        print("Username cannot be empty.")
        return

    password = getpass.getpass("Admin password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if password != confirm_password:
        print("Passwords do not match.")
        return

    if len(password) < 10:
        print("Password must be at least 10 characters.")
        return

    config = {
        "username": username,
        "password_hash": generate_password_hash(password),
        "secret_key": secrets.token_hex(32)
    }

    AUTH_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(AUTH_CONFIG_PATH, "w") as file:
        json.dump(config, file, indent=4)

    AUTH_CONFIG_PATH.chmod(0o600)

    print()
    print("Admin account created successfully.")
    print(f"Configuration saved to: {AUTH_CONFIG_PATH}")


if __name__ == "__main__":
    setup_auth()
