import hmac
import hashlib
import base64
import os
import re
from typing import Tuple, Optional
import pyotp
from datetime import datetime
from config import PasswordPolicy

class PasswordManager:
    SALT_SIZE = 16
    HASH_SIZE = 64 
    @staticmethod
    def validate_password_complexity(password: str) -> Tuple[bool, str]:
        """
        Validate password complexity requirements
        Returns: (is_valid, error_message)
        """
        if len(password) < PasswordPolicy.MIN_LENGTH:
            return False, f"Password must be at least {PasswordPolicy.MIN_LENGTH} characters long"
        
        if PasswordPolicy.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
            
        if PasswordPolicy.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
            
        if PasswordPolicy.REQUIRE_NUMBERS and not re.search(r'\d', password):
            return False, "Password must contain at least one number"
            
        if PasswordPolicy.REQUIRE_SPECIAL and not any(c in PasswordPolicy.SPECIAL_CHARS for c in password):
            return False, "Password must contain at least one special character"
            
        return True, "Password meets complexity requirements"

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password using BLAKE2b with salt
        """
        salt = os.urandom(PasswordManager.SALT_SIZE)
        h = hashlib.blake2b(digest_size=PasswordManager.HASH_SIZE)
        h.update(salt)
        h.update(password.encode('utf-8'))
        return f"{base64.b64encode(salt).decode('utf-8')}${h.hexdigest()}"

    @staticmethod
    def verify_password(password: str, stored_hash: str) -> bool:
        """
        Verify password against stored hash
        """
        try:
            salt_b64, hash_value = stored_hash.split('$')
            salt = base64.b64decode(salt_b64)
            h = hashlib.blake2b(digest_size=PasswordManager.HASH_SIZE)
            h.update(salt)
            h.update(password.encode('utf-8'))
            return h.hexdigest() == hash_value
        except Exception as e:
            print(f"Error in password verification: {e}")
            return False

    @staticmethod
    def debug_password_verification(password: str, stored_hash: str) -> None:
        """Debug password verification process"""
        try:
            salt_b64, hash_value = stored_hash.split('$')
            salt = base64.b64decode(salt_b64)
            h = hashlib.blake2b(digest_size=PasswordManager.HASH_SIZE)
            h.update(salt)
            h.update(password.encode('utf-8'))
            calculated_hash = h.hexdigest()
            print(f"Debug: Stored hash: {hash_value}")
            print(f"Debug: Calculated hash: {calculated_hash}")
            print(f"Debug: Match: {calculated_hash == hash_value}")
        except Exception as e:
            print(f"Debug: Error in verification: {e}")

class TOTPManager:
    @staticmethod
    def generate_totp_secret() -> str:
        """
        Generate a new TOTP secret
        """
        return pyotp.random_base32()

    @staticmethod
    def generate_totp_uri(secret: str, username: str) -> str:
        """
        Generate TOTP URI for QR code generation
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(username, issuer_name="NTLM Auth System")

    @staticmethod
    def verify_totp(secret: str, token: str) -> bool:
        """
        Verify TOTP token
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(token)
    
def print_crypto_operation(operation: str, input_data: bytes, output_data: bytes):
    """Print cryptographic operation details"""
    print(f"\n{operation}:")
    print(f"Input:  {input_data.hex()}")
    print(f"Output: {output_data.hex()}")

class NTLMCrypto:
    @staticmethod
    def generate_nonce(size: int = 16) -> bytes:
        """Generate a random nonce"""
        nonce = os.urandom(size)
        print("\nGenerated Nonce:")
        print(f"Size: {size} bytes")
        print(f"Value: {nonce.hex()}")
        return nonce

    @staticmethod
    def create_ntlm_hash(password: str) -> bytes:
        """Create NTLM hash using BLAKE2b"""
        print("\nCreating NTLM Hash:")
        print(f"Password: {password}")
        
        h = hashlib.blake2b(digest_size=16)
        h.update(password.encode('utf-16le'))
        hash_value = h.digest()
        
        print(f"Hash: {hash_value.hex()}")
        return hash_value

    @staticmethod
    def create_ntlm_response(password_hash: bytes, server_challenge: bytes) -> bytes:
        """Create NTLM response"""
        print("\nCreating NTLM Response:")
        print(f"Password Hash: {password_hash.hex()}")
        print(f"Server Challenge: {server_challenge.hex()}")
        
        response = hmac.new(password_hash, server_challenge, hashlib.blake2b).digest()
        print(f"Response: {response.hex()}")
        return response

class SessionCrypto:
    @staticmethod
    def generate_session_id() -> str:
        """
        Generate a secure session ID
        """
        return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')

    @staticmethod
    def create_session_token(user_id: int, session_id: str) -> str:
        """
        Create a session token containing user ID and session ID
        """
        data = f"{user_id}:{session_id}:{datetime.utcnow().timestamp()}"
        h = hmac.new(os.urandom(32), data.encode(), hashlib.blake2b)
        return f"{data}${h.hexdigest()}"

    @staticmethod
    def verify_session_token(token: str) -> Optional[Tuple[int, str]]:
        """
        Verify and extract information from session token
        Returns: (user_id, session_id) or None if invalid
        """
        try:
            data, signature = token.split('$')
            user_id, session_id, timestamp = data.split(':')
            return int(user_id), session_id
        except Exception:
            return None