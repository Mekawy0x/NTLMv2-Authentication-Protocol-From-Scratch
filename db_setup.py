import mysql.connector
from getpass import getpass
import sys
from typing import Dict, Optional
from mysql.connector import Error

class DatabaseManager:
    _instance = None
    _connection = None
    _db_config = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
        return cls._instance

    @classmethod
    def initialize_connection(cls) -> None:
        """Initialize database connection with user input"""
        print("\n=== Database Connection Setup ===")
        
        # Get database credentials
        host = input("Enter database host (default 'localhost'): ").strip() or 'localhost'
        user = input("Enter database username: ").strip()
        password = getpass("Enter database password: ")
        database = input("Enter database name (default 'ntlm_auth_db'): ").strip() or 'ntlm_auth_db'
        
        cls._db_config = {
            'host': host,
            'user': user,
            'password': password,
            'database': database,
            'auth_plugin': 'mysql_native_password'  # Explicitly set auth plugin
        }

        try:
            # First try to connect to MySQL server
            temp_conn = mysql.connector.connect(
                host=host,
                user=user,
                password=password,
                auth_plugin='mysql_native_password'  # Added for initial connection
            )
            cursor = temp_conn.cursor()

            # Create database if it doesn't exist
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database}")
            temp_conn.close()

            # Connect to the specific database with auth plugin specified
            cls._connection = mysql.connector.connect(**cls._db_config)
            print("\nDatabase connection successful!")
            
            # Create tables
            cls._create_tables()

        except Error as err:
            print(f"\nError: {err}")
            print("\nPossible solutions:")
            print("1. Try updating your mysql-connector-python: pip install --upgrade mysql-connector-python")
            print("2. Ask your database admin to change your user's authentication method:")
            print("   ALTER USER 'your_user'@'host' IDENTIFIED WITH mysql_native_password BY 'password';")
            sys.exit(1)

    @classmethod
    def _create_tables(cls) -> None:
        """Create necessary tables if they don't exist"""
        cursor = cls._connection.cursor()

        # Users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
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

        # Sessions table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id VARCHAR(255) PRIMARY KEY,
                user_id INT NOT NULL,
                created_at DATETIME NOT NULL,
                expires_at DATETIME NOT NULL,
                ip_address VARCHAR(45) NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        # Logs table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                log_type VARCHAR(50) NOT NULL,
                user_id INT,
                ip_address VARCHAR(45),
                details TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

        cls._connection.commit()
        cursor.close()

    @classmethod
    def get_connection(cls):
        """Get the database connection"""
        if cls._connection is None or not cls._connection.is_connected():
            cls.initialize_connection()
        return cls._connection

    @classmethod
    def close_connection(cls):
        """Close the database connection"""
        if cls._connection and cls._connection.is_connected():
            cls._connection.close()