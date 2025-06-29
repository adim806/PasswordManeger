"""
Unit tests for the encryption module.
"""

import unittest
import base64
import os
import sys

# Add the parent directory to sys.path to import the application modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from password_manager.crypto.encryption import (
    generate_salt, generate_key, derive_key_from_password,
    encrypt_password, decrypt_password, hash_master_password,
    verify_master_password, secure_string_compare
)

class TestEncryption(unittest.TestCase):
    """Test case for encryption module functions."""
    
    def test_salt_generation(self):
        """Test salt generation."""
        salt1 = generate_salt()
        salt2 = generate_salt()
        
        # Check that salts are of the correct length
        self.assertEqual(len(salt1), 16)
        self.assertEqual(len(salt2), 16)
        
        # Check that two generated salts are different
        self.assertNotEqual(salt1, salt2)
        
    def test_key_generation(self):
        """Test encryption key generation."""
        key1 = generate_key()
        key2 = generate_key()
        
        # Check that keys are of the correct length
        self.assertEqual(len(key1), 32)  # 256 bits
        self.assertEqual(len(key2), 32)
        
        # Check that two generated keys are different
        self.assertNotEqual(key1, key2)
        
    def test_key_derivation(self):
        """Test key derivation from password."""
        password = "TestPassword123"
        salt = generate_salt()
        
        key1 = derive_key_from_password(password, salt)
        key2 = derive_key_from_password(password, salt)
        
        # Check that keys are of the correct length
        self.assertEqual(len(key1), 32)  # 256 bits
        
        # Check that the same password and salt produce the same key
        self.assertEqual(key1, key2)
        
        # Check that different salts produce different keys
        key3 = derive_key_from_password(password, generate_salt())
        self.assertNotEqual(key1, key3)
        
        # Check that different passwords produce different keys
        key4 = derive_key_from_password("DifferentPassword", salt)
        self.assertNotEqual(key1, key4)
        
    def test_password_encryption_decryption(self):
        """Test password encryption and decryption."""
        original_password = "MySecurePassword123!"
        key = generate_key()
        
        # Encrypt the password
        encrypted, nonce, tag = encrypt_password(original_password, key)
        
        # Check that all components are base64 strings
        self.assertTrue(isinstance(encrypted, str))
        self.assertTrue(isinstance(nonce, str))
        self.assertTrue(isinstance(tag, str))
        
        # Decrypt the password
        decrypted = decrypt_password(encrypted, nonce, tag, key)
        
        # Check that the decrypted password matches the original
        self.assertEqual(decrypted, original_password)
        
        # Try with a wrong key
        wrong_key = generate_key()
        with self.assertRaises(Exception):
            decrypt_password(encrypted, nonce, tag, wrong_key)
            
    def test_master_password_hashing(self):
        """Test master password hashing and verification."""
        password = "MasterPassword123"
        
        # Hash the password
        hashed, salt = hash_master_password(password)
        
        # Check that hash and salt are strings
        self.assertTrue(isinstance(hashed, str))
        self.assertTrue(isinstance(salt, str))
        
        # Verify the password
        self.assertTrue(verify_master_password(hashed, password))
        
        # Try with wrong password
        self.assertFalse(verify_master_password(hashed, "WrongPassword"))
        
    def test_secure_string_compare(self):
        """Test secure string comparison."""
        string1 = "TestString"
        string2 = "TestString"
        string3 = "DifferentString"
        
        # Equal strings should return True
        self.assertTrue(secure_string_compare(string1, string2))
        
        # Different strings should return False
        self.assertFalse(secure_string_compare(string1, string3))
        
        # Strings of different lengths should return False
        self.assertFalse(secure_string_compare(string1, string1 + "Extra"))
        
if __name__ == '__main__':
    unittest.main() 