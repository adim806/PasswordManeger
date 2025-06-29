"""
Encryption module for the password manager application.
Handles all encryption/decryption operations using AES-GCM.
"""

import os
import base64
import logging
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets
import ctypes

from password_manager.config.config import (
    KEY_LENGTH, SALT_LENGTH, NONCE_LENGTH, TAG_LENGTH, PBKDF2_ITERATIONS,
    ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_PARALLELISM
)

logger = logging.getLogger(__name__)

# Initialize Argon2 hasher
ph = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_COST,
    parallelism=ARGON2_PARALLELISM
)

def generate_salt(length=SALT_LENGTH):
    """
    Generate a cryptographically secure random salt.
    
    Args:
        length (int): Length of salt in bytes
        
    Returns:
        bytes: Random salt
    """
    return os.urandom(length)

def generate_nonce(length=NONCE_LENGTH):
    """
    Generate a cryptographically secure random nonce.
    
    Args:
        length (int): Length of nonce in bytes
        
    Returns:
        bytes: Random nonce
    """
    return os.urandom(length)

def generate_key(length=KEY_LENGTH):
    """
    Generate a random encryption key.
    
    Args:
        length (int): Length of key in bytes
        
    Returns:
        bytes: Random key
    """
    return os.urandom(length)

def derive_key_from_password(password, salt, length=KEY_LENGTH):
    """
    Derive an encryption key from a password using PBKDF2.
    
    Args:
        password (str): The password to derive the key from
        salt (bytes): Salt for key derivation
        length (int): Length of the derived key in bytes
        
    Returns:
        bytes: Derived key
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    
    key = kdf.derive(password)
    return key

def derive_key_from_password_argon2(password, salt, length=KEY_LENGTH):
    """
    Alternative key derivation using Argon2.
    
    Args:
        password (str): The password to derive the key from
        salt (bytes): Salt for key derivation
        length (int): Length of the derived key in bytes
        
    Returns:
        bytes: Derived key
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Using Scrypt as an alternative to Argon2 from cryptography library
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=2**14,  # CPU/memory cost parameter
        r=8,      # Block size parameter
        p=1,      # Parallelization parameter
        backend=default_backend()
    )
    
    key = kdf.derive(password)
    return key

def encrypt_password(password, key):
    """
    Encrypt a password using AES-GCM.
    
    Args:
        password (str): Password to encrypt
        key (bytes): Encryption key
        
    Returns:
        tuple: (encrypted_password, nonce, tag) - all base64 encoded
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    try:
        # Generate a random nonce (never reuse a nonce with the same key)
        nonce = generate_nonce()
        
        # Create an encryptor
        aesgcm = AESGCM(key)
        
        # Encrypt the password
        encrypted_data = aesgcm.encrypt(nonce, password, None)
        
        # In AES-GCM, the tag is appended to the ciphertext
        ciphertext = encrypted_data[:-TAG_LENGTH]
        tag = encrypted_data[-TAG_LENGTH:]
        
        # Encode binary data to base64 for storage
        encrypted_password_b64 = base64.b64encode(ciphertext).decode('utf-8')
        nonce_b64 = base64.b64encode(nonce).decode('utf-8')
        tag_b64 = base64.b64encode(tag).decode('utf-8')
        
        return encrypted_password_b64, nonce_b64, tag_b64
    except Exception as e:
        logger.error(f"Encryption error: {e}")
        raise

def decrypt_password(encrypted_password, nonce, tag, key):
    """
    Decrypt a password using AES-GCM.
    
    Args:
        encrypted_password (str): Base64 encoded encrypted password
        nonce (str): Base64 encoded nonce
        tag (str): Base64 encoded authentication tag
        key (bytes): Decryption key
        
    Returns:
        str: Decrypted password
    """
    try:
        # Decode base64 data
        ciphertext = base64.b64decode(encrypted_password)
        nonce_bytes = base64.b64decode(nonce)
        tag_bytes = base64.b64decode(tag)
        
        # Combine ciphertext and tag for AESGCM
        encrypted_data = ciphertext + tag_bytes
        
        # Create decryptor
        aesgcm = AESGCM(key)
        
        # Decrypt the data
        decrypted_data = aesgcm.decrypt(nonce_bytes, encrypted_data, None)
        
        # Convert bytes to string
        decrypted_password = decrypted_data.decode('utf-8')
        
        return decrypted_password
    except Exception as e:
        logger.error(f"Decryption error: {e}")
        raise

def secure_string_compare(a, b):
    """
    Compare two strings in constant time to prevent timing attacks.
    
    Args:
        a (str): First string
        b (str): Second string
        
    Returns:
        bool: True if strings are equal, False otherwise
    """
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

def clear_sensitive_data(data):
    """
    Securely clear sensitive data from memory.
    
    Args:
        data: Variable containing sensitive data
    """
    if isinstance(data, str):
        location = id(data)
        size = len(data) * 2  # Size in bytes for a Python string (approximate)
        ctypes.memset(location, 0, size)
    elif isinstance(data, bytes):
        location = id(data)
        size = len(data)
        ctypes.memset(location, 0, size)
    elif isinstance(data, bytearray):
        data[:] = b'\x00' * len(data)

def hash_master_password(password):
    """
    Hash a master password using Argon2id.
    
    Args:
        password (str): Password to hash
        
    Returns:
        tuple: (hash, salt) - both base64 encoded
    """
    try:
        # Generate a random salt
        salt = generate_salt()
        salt_b64 = base64.b64encode(salt).decode('utf-8')
        
        # Hash the password with Argon2
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Use the passwordhasher to create a hash
        hashed = ph.hash(password)
        
        return hashed, salt_b64
    except Exception as e:
        logger.error(f"Password hashing error: {e}")
        raise

def verify_master_password(stored_hash, password):
    """
    Verify a master password against its stored hash using Argon2id.
    
    Args:
        stored_hash (str): Stored password hash
        password (str): Password to verify
        
    Returns:
        bool: True if password matches, False otherwise
    """
    try:
        if isinstance(password, str):
            password = password.encode('utf-8')
            
        ph.verify(stored_hash, password)
        return True
    except VerifyMismatchError:
        return False
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False 