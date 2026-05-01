import os
from cryptography.fernet import Fernet

KEY_FILE = ".secret.key"

def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

KEY    = load_or_create_key()
cipher = Fernet(KEY)

def encrypt_file(input_path, output_path):
    with open(input_path, "rb") as f:
        data = f.read()
    encrypted = cipher.encrypt(data)
    with open(output_path, "wb") as f:
        f.write(encrypted)
    print(f"[+] Encrypted: {output_path}")

def decrypt_file(input_path, output_path):
    with open(input_path, "rb") as f:
        data = f.read()
    decrypted = cipher.decrypt(data)
    with open(output_path, "wb") as f:
        f.write(decrypted)
    print(f"[+] Decrypted: {output_path}")
