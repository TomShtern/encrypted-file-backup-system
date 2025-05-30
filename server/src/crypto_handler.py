"""
Cryptographic operations for the server
RSA and AES encryption/decryption handling
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
from typing import Tuple, bytes

class CryptoHandler:
    """Handles all cryptographic operations"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.generate_rsa_keypair()
    
    def generate_rsa_keypair(self, key_size: int = 1024):
        """Generate RSA key pair"""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
    
    def get_public_key_pem(self) -> bytes:
        """Get public key in PEM format"""
        return self.public_key.serialize(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def rsa_decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data using RSA private key"""
        return self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def aes_encrypt(self, data: bytes, key: bytes, iv: bytes) -> bytes:
        """Encrypt data using AES-CBC"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad data to block size
        padded_data = self._pad_data(data)
        
        return encryptor.update(padded_data) + encryptor.finalize()
    
    def aes_decrypt(self, encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:
        """Decrypt data using AES-CBC"""
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove padding
        return self._unpad_data(padded_data)
    
    def generate_aes_key(self) -> bytes:
        """Generate 256-bit AES key"""
        return os.urandom(32)
    
    def generate_iv(self) -> bytes:
        """Generate 128-bit IV for AES"""
        return os.urandom(16)
    
    def _pad_data(self, data: bytes) -> bytes:
        """Apply PKCS7 padding"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, padded_data: bytes) -> bytes:
        """Remove PKCS7 padding"""
        padding_length = padded_data[-1]
        return padded_data[:-padding_length]
