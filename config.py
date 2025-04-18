import os
from enum import Enum
from datetime import datetime

class MessageType(Enum):
    NEGOTIATE = 1
    CHALLENGE = 2
    AUTHENTICATE = 3
    VIEW_LOGS = 4
    VIEW_USERS = 5
    CHANGE_USERNAME = 6
    ADD_USER = 7
    REMOVE_USER = 8
    UPDATE_USER = 9
    CHANGE_PASSWORD = 10

class UserRole(str, Enum):
    SYSTEM_ADMIN = "system_admin"
    ADMIN = "admin"
    USER = "user"

class LogType(str, Enum):
    LOGIN_ATTEMPT = "login_attempt"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    PASSWORD_CHANGE = "password_change"
    USER_CREATED = "user_created"
    USER_DELETED = "user_deleted"
    USER_UPDATED = "user_updated"
    PERMISSION_CHANGE = "permission_change"
    PROFILE_VIEW = "profile_view"
    SYSTEM_ACCESS = "system_access"

# Server Configuration
SERVER_HOST = 'localhost'
SERVER_PORT = 5555

# Password Policy
class PasswordPolicy:
    MIN_LENGTH = 8
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_NUMBERS = True
    REQUIRE_SPECIAL = True
    SPECIAL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# Default Admin
DEFAULT_ADMIN = {
    'username': 'Moaz',
    'password': 'Moaz@123',
    'role': UserRole.SYSTEM_ADMIN.value,  # Use .value here
    'created_by': 'SYSTEM',
    'created_at': datetime.utcnow()
}

# Session Configuration
SESSION_SECRET_KEY = os.urandom(32)