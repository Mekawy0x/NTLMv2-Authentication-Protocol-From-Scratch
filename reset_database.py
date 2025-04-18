from db_setup import DatabaseManager
from config import DEFAULT_ADMIN
from crypto_utils import PasswordManager
import mysql.connector

def reset_database():
    try:
        # Connect to MySQL
        print("Connecting to MySQL...")
        connection = mysql.connector.connect(
            host='localhost',
            user='root',
            password=input("Enter MySQL root password: ")
        )
        cursor = connection.cursor()

        # Drop and recreate database
        print("Resetting database...")
        cursor.execute("DROP DATABASE IF EXISTS ntlm_auth_db")
        cursor.execute("CREATE DATABASE ntlm_auth_db")
        cursor.execute("USE ntlm_auth_db")

        # Create tables
        print("Creating tables...")
        cursor.execute("""
            CREATE TABLE users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                role ENUM('system_admin', 'admin', 'user') NOT NULL,
                totp_secret VARCHAR(255) NOT NULL,
                created_at DATETIME NOT NULL,
                created_by VARCHAR(255) NOT NULL,
                last_login DATETIME
            )
        """)

        # Create default admin
        print("Creating default admin...")
        password_hash = PasswordManager.hash_password(DEFAULT_ADMIN['password'])
        cursor.execute("""
            INSERT INTO users (username, password_hash, role, totp_secret, created_at, created_by)
            VALUES (%s, %s, %s, %s, NOW(), 'SYSTEM')
        """, (DEFAULT_ADMIN['username'], password_hash, DEFAULT_ADMIN['role'].value, 'TOTP_SECRET'))

        connection.commit()
        print("\nDatabase reset successful!")
        print(f"Default admin username: {DEFAULT_ADMIN['username']}")
        print(f"Default admin password: {DEFAULT_ADMIN['password']}")

        # Verify admin creation
        cursor.execute("SELECT * FROM users WHERE username = %s", (DEFAULT_ADMIN['username'],))
        admin = cursor.fetchone()
        if admin:
            print("\nAdmin user verified in database")
            print(f"Stored password hash: {admin[2]}")

    except Exception as e:
        print(f"Error resetting database: {e}")
    finally:
        if 'connection' in locals():
            connection.close()

if __name__ == "__main__":
    reset_database()