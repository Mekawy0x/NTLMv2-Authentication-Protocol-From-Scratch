from typing import Optional, List, Dict, Tuple
from datetime import datetime, timedelta
import mysql.connector
from mysql.connector import Error
from db_setup import DatabaseManager
from config import UserRole, LogType, DEFAULT_ADMIN
from crypto_utils import PasswordManager, TOTPManager

class DatabaseError(Exception):
    """Custom exception for database operations"""
    pass

class Database:
    @staticmethod
    def _get_cursor():
        """Get database cursor"""
        return DatabaseManager.get_connection().cursor(dictionary=True)

    @staticmethod
    def _commit():
        """Commit transaction"""
        DatabaseManager.get_connection().commit()

    class Users:
        @staticmethod
        def create_user(username: str, password: str, role: str, created_by: str) -> bool:
            """Create a new user"""
            try:
                cursor = Database._get_cursor()
        
                # Check if username exists
                cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
                if cursor.fetchone():
                    return False

                # Hash password and generate TOTP secret
                password_hash = PasswordManager.hash_password(password)
                totp_secret = TOTPManager.generate_totp_secret()

                # Insert new user
                cursor.execute("""
                    INSERT INTO users 
                    (username, password_hash, role, totp_secret, created_at, created_by)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (
                    username,
                    password_hash,
                    role,  # role is already a string value
                    totp_secret,
                    datetime.utcnow(),
                    created_by
                ))
        
                Database._commit()
                return True
            except Error as e:
                print(f"Error creating user: {e}")
                return False

        @staticmethod
        def get_user(username: str) -> Optional[Dict]:
            """Get user by username"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    SELECT id, username, password_hash, role, totp_secret, created_at, created_by, last_login
                    FROM users WHERE username = %s
                """, (username,))
                return cursor.fetchone()
            except Error as e:
                raise DatabaseError(f"Error fetching user: {str(e)}")

        @staticmethod
        def get_user_by_id(user_id: int) -> Optional[Dict]:
            """Get user by ID"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    SELECT id, username, password_hash, role, totp_secret, created_at, created_by, last_login
                    FROM users WHERE id = %s
                """, (user_id,))
                return cursor.fetchone()
            except Error as e:
                raise DatabaseError(f"Error fetching user: {str(e)}")

        @staticmethod
        def get_all_users() -> List[Dict]:
            """Get all users"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    SELECT id, username, role, created_at, created_by, last_login
                    FROM users
                """)
                return cursor.fetchall()
            except Error as e:
                raise DatabaseError(f"Error fetching users: {str(e)}")

        @staticmethod
        def update_password(user_id: int, new_password: str) -> bool:
            """Update user password"""
            try:
                cursor = Database._get_cursor()
                password_hash = PasswordManager.hash_password(new_password)
                cursor.execute("""
                    UPDATE users SET password_hash = %s
                    WHERE id = %s
                """, (password_hash, user_id))
                Database._commit()
                return True
            except Error as e:
                print(f"Error updating password: {e}")
                return False

        @staticmethod
        def update_username(user_id: int, new_username: str) -> bool:
            """Update username"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    UPDATE users SET username = %s
                    WHERE id = %s
                """, (new_username, user_id))
                Database._commit()
                return True
            except Error as e:
                print(f"Error updating username: {e}")
                return False

        @staticmethod
        def update_role(user_id: int, new_role: str) -> bool:
            """Update user role"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    UPDATE users SET role = %s
                    WHERE id = %s
                """, (new_role, user_id))
                Database._commit()
                return True
            except Error as e:
                print(f"Error updating role: {e}")
                return False

        @staticmethod
        def delete_user(user_id: int) -> bool:
            """Delete user"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                Database._commit()
                return True
            except Error as e:
                print(f"Error deleting user: {e}")
                return False

        @staticmethod
        def update_last_login(user_id: int) -> None:
            """Update user's last login time"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    UPDATE users SET last_login = %s
                    WHERE id = %s
                """, (datetime.utcnow(), user_id))
                Database._commit()
            except Error as e:
                print(f"Error updating last login: {e}")

    class Sessions:
        @staticmethod
        def create_session(user_id: int, session_id: str, ip_address: str) -> bool:
            """Create new session"""
            try:
                cursor = Database._get_cursor()
                expires_at = datetime.utcnow() + timedelta(hours=1)
                cursor.execute("""
                    INSERT INTO sessions (id, user_id, created_at, expires_at, ip_address)
                    VALUES (%s, %s, %s, %s, %s)
                """, (session_id, user_id, datetime.utcnow(), expires_at, ip_address))
                Database._commit()
                return True
            except Error as e:
                raise DatabaseError(f"Error creating session: {str(e)}")

        @staticmethod
        def get_session(session_id: str) -> Optional[Dict]:
            """Get session by ID"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    SELECT * FROM sessions 
                    WHERE id = %s AND expires_at > %s
                """, (session_id, datetime.utcnow()))
                return cursor.fetchone()
            except Error as e:
                raise DatabaseError(f"Error fetching session: {str(e)}")

        @staticmethod
        def delete_session(session_id: str) -> bool:
            """Delete session"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("DELETE FROM sessions WHERE id = %s", (session_id,))
                Database._commit()
                return True
            except Error as e:
                raise DatabaseError(f"Error deleting session: {str(e)}")

        @staticmethod
        def cleanup_expired_sessions() -> None:
            """Clean up expired sessions"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("DELETE FROM sessions WHERE expires_at < %s", (datetime.utcnow(),))
                Database._commit()
            except Error as e:
                raise DatabaseError(f"Error cleaning up sessions: {str(e)}")
        @staticmethod
        def get_user_by_id(user_id: int) -> Optional[Dict]:
            """Get user by ID"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    SELECT id, username, password_hash, role, totp_secret, created_at, created_by, last_login
                    FROM users WHERE id = %s
                """, (user_id,))
                return cursor.fetchone()
            except Error as e:
                raise DatabaseError(f"Error fetching user: {str(e)}")

    class Logs:
        @staticmethod
        def add_log(log_type: LogType, user_id: Optional[int], ip_address: str, details: str) -> bool:
            """Add new log entry"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    INSERT INTO logs (timestamp, log_type, user_id, ip_address, details)
                    VALUES (%s, %s, %s, %s, %s)
                """, (datetime.utcnow(), log_type.value, user_id, ip_address, details))
                Database._commit()
                return True
            except Error as e:
                raise DatabaseError(f"Error adding log: {str(e)}")

        @staticmethod
        def get_logs(limit: int = 100, offset: int = 0) -> List[Dict]:
            """Get logs with pagination"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    SELECT l.*, u.username 
                    FROM logs l
                    LEFT JOIN users u ON l.user_id = u.id
                    ORDER BY timestamp DESC
                    LIMIT %s OFFSET %s
                """, (limit, offset))
                return cursor.fetchall()
            except Error as e:
                raise DatabaseError(f"Error fetching logs: {str(e)}")

        @staticmethod
        def get_user_logs(user_id: int, limit: int = 100) -> List[Dict]:
            """Get logs for specific user"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    SELECT * FROM logs 
                    WHERE user_id = %s 
                    ORDER BY timestamp DESC 
                    LIMIT %s
                """, (user_id, limit))
                return cursor.fetchall()
            except Error as e:
                raise DatabaseError(f"Error fetching user logs: {str(e)}")

        @staticmethod
        def get_login_attempts(ip_address: str, timeframe_minutes: int = 30) -> int:
            """Get number of failed login attempts from an IP"""
            try:
                cursor = Database._get_cursor()
                cursor.execute("""
                    SELECT COUNT(*) as count 
                    FROM logs 
                    WHERE ip_address = %s 
                    AND log_type = %s 
                    AND timestamp > %s
                """, (ip_address, LogType.LOGIN_FAILURE.value, 
                     datetime.utcnow() - timedelta(minutes=timeframe_minutes)))
                result = cursor.fetchone()
                return result['count'] if result else 0
            except Error as e:
                raise DatabaseError(f"Error counting login attempts: {str(e)}")