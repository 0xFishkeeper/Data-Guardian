import hashlib
import json
import os
import bcrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def generate_asymmetric_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Get the corresponding public key
    public_key = private_key.public_key()

    return private_key, public_key


def asymmetric_encrypt(message, public_key):
    encrypted_message = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


# Function to decrypt a message using the private key
def asymmetric_decrypt(encrypted_message, private_key):
    try:
        original_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return original_message
    except Exception as e:
        print(f"Error during asymmetric decryption: {e}")
        return None


def generate_symmetric_key():
    return os.urandom(32)  # 32 bytes = 256 bits


def symmetric_encrypt(data, key):
    # Generate a random IV
    iv = os.urandom(16)  # AES block size is 16 bytes

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the data
    padder = sym_padding.PKCS7(128).padder()  # 128-bit padding for AES
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Return IV and encrypted data (IV is needed for decryption)
    print(f'Symmetric_encrypt_success')
    return iv + encrypted_data


def symmetric_decrypt(encrypted_data, key):
    # Extract the IV (first 16 bytes)
    iv = encrypted_data[:16]

    # Extract the actual encrypted data
    encrypted_data = encrypted_data[16:]

    # Create a Cipher object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding
    unpadder = sym_padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()
    print(f'Symmetric_decrypt_success')
    return unpadded_data


def decrypt_credentials(decrypted_symmetric_key):
    try:
        # Read the encrypted data from the file
        with open('shadow.txt', 'rb') as file:
            encrypted_data = file.read()

        # Decrypt the data using the symmetric key
        decrypted_data = symmetric_decrypt(encrypted_data, decrypted_symmetric_key)

        # Deserialize the decrypted data
        credential_data = json.loads(decrypted_data.decode('utf-8'))
        print(f'Credential Decryption Success')
        return credential_data
    except Exception as e:
        print(f"Error during decryption: {e}")
        return None


def hash_username(username):
    hashed_username = hashlib.sha256(username.encode('utf-8'))
    return hashed_username.digest()


def save_to_file(data, filename):
    with open(filename, 'wb') as file:
        file.write(data)


def verify_password(pw, hpw):
    return bcrypt.checkpw(pw.encode(), hpw)


# stores a hashed version of password
def hash_password(pw):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pw.encode('utf-8'), salt)


