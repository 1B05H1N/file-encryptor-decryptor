"""
This Python program provides secure file encryption and decryption functionalities using symmetric cryptography. 
It employs the Fernet scheme from the cryptography library, which is built on top of AES in CBC mode with a 128-bit key 
for encryption, and uses HMAC with SHA256 for authentication. The program generates a secure, cryptographically strong key 
from a user-provided password and a randomly generated salt, using the PBKDF2HMAC key derivation function. This ensures 
that the encryption key is both secure and unique for each encryption operation.

The program allows users to encrypt a file, appending '.enc' to the encrypted file's name, and to decrypt an encrypted file, 
restoring it to its original state. The salt used for key derivation is stored alongside the encrypted content, ensuring that 
the same key can be regenerated for decryption. It's designed with a simple command-line interface for easy operation, 
prompting users to input their password and choose between encrypting or decrypting a file. The encryption and decryption 
processes are designed to be secure against various cryptographic attacks, making the program suitable for protecting 
sensitive information stored in files.
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key(password: str, salt: bytes = None) -> bytes:
    """Generate a secure key from the password using PBKDF2 HMAC and a secure PRNG for the salt."""
    if salt is None:
        salt = os.urandom(16)  # Generate a secure random salt
    # Key derivation function (KDF) setup using PBKDF2 HMAC SHA-256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # Fernet keys are 32 bytes
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())  # Directly use the derived key for Fernet
    return key, salt

def encrypt_file(file_path: str, password: str) -> None:
    """Encrypt the file using a password-derived key and a securely generated salt."""
    key, salt = generate_key(password)  # Generate a secure key and salt
    fernet = Fernet(base64.urlsafe_b64encode(key))  # Fernet requires a base64-encoded key
    with open(file_path, 'rb') as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(file_path + '.enc', 'wb') as encrypted_file:
        encrypted_file.write(salt + encrypted)  # Store the salt with the encrypted content
    print(f"File '{file_path}' encrypted successfully.")

def decrypt_file(file_path: str, password: str) -> None:
    """Decrypt the file using the password and the salt stored with the encrypted content."""
    with open(file_path, 'rb') as file:
        file_contents = file.read()
    salt = file_contents[:16]  # Retrieve the salt used during encryption
    key, _ = generate_key(password, salt)  # Derive the same key using the stored salt
    fernet = Fernet(base64.urlsafe_b64encode(key))  # Fernet requires a base64-encoded key
    try:
        decrypted = fernet.decrypt(file_contents[16:])
        with open(file_path.replace('.enc', ''), 'wb') as decrypted_file:
            decrypted_file.write(decrypted)
        print(f"File '{file_path}' decrypted successfully.")
    except Exception as e:
        print(f"Decryption failed: {e}")

# User interface for encryption/decryption
password = input("Enter your encryption/decryption password: ")
action = input("Do you want to (E)ncrypt or (D)ecrypt a file? ").upper()

if action not in ['E', 'D']:
    print("Invalid action.")
else:
    file_path = input("Enter the full path to the file: ")
    if action == 'E':
        encrypt_file(file_path, password)
    else:
        decrypt_file(file_path, password)
