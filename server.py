import socket
import threading
import json
import logging
from typing import Dict, Optional, Tuple, Any
from datetime import datetime
import ipaddress
from utils import serialize_response

from config import (
    SERVER_HOST, 
    SERVER_PORT, 
    UserRole, 
    LogType,
    DEFAULT_ADMIN
)
from message_types import MessageType
from messages import NegotiateMessage, ChallengeMessage, AuthenticateMessage
from admin_messages import (
    AddUserMessage, ChangePasswordMessage, RemoveUserMessage,
    UpdateUserMessage, ViewLogsMessage, ViewUsersMessage,
    ChangeUsernameMessage
)
from crypto_utils import (
    NTLMCrypto, 
    PasswordManager, 
    TOTPManager, 
    SessionCrypto
)
from database import Database, DatabaseError
from db_setup import DatabaseManager

# Configure logging
logging.basicConfig(
    filename='server.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class AuthenticationState:
    """Class to track authentication state for each client"""
    def __init__(self):
        self.challenge: Optional[bytes] = None
        self.username: Optional[str] = None
        self.attempts: int = 0
        self.last_attempt: Optional[datetime] = None

class NTLMServer:
    def __init__(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.running = False
        self.clients: Dict[str, AuthenticationState] = {}
        self.setup_database()

    def setup_database(self):
        """Initialize database and create default admin if not exists"""
        try:
            # Check if default admin exists
            admin = Database.Users.get_user(DEFAULT_ADMIN['username'])
            if not admin:
                # Create default admin
                success = Database.Users.create_user(
                    username=DEFAULT_ADMIN['username'],
                    password=DEFAULT_ADMIN['password'],
                    role=DEFAULT_ADMIN['role'],  # This is now a string
                    created_by='SYSTEM'
                )
                if success:
                    logging.info("Default admin account created")
                    print("Default admin account created successfully")
                else:
                    logging.error("Failed to create default admin account")
                    print("Failed to create default admin account")
            else:
                logging.info("Default admin account already exists")
                print("Default admin account already exists")
        except DatabaseError as e:
            logging.error(f"Database setup error: {e}")
            raise

    def start(self):
        """Start the NTLM authentication server"""
        try:
            self.server_socket.bind((SERVER_HOST, SERVER_PORT))
            self.server_socket.listen(5)
            self.running = True
            logging.info(f"Server started on {SERVER_HOST}:{SERVER_PORT}")

            while self.running:
                client_socket, address = self.server_socket.accept()
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, address)
                )
                client_thread.start()

        except Exception as e:
            logging.error(f"Server error: {e}")
            self.stop()

    def stop(self):
        """Stop the server"""
        self.running = False
        self.server_socket.close()
        logging.info("Server stopped")

    def print_message_header(self, title: str):
        """Print formatted message header"""
        print("\n" + "="*50)
        print(f" {title} ")
        print("="*50)

    def print_message_details(self, details: dict):
        """Print message details"""
        for key, value in details.items():
            if isinstance(value, bytes):
                print(f"{key}: {value.hex()}")
            else:
                print(f"{key}: {value}")
        print("-"*50)

    def print_auth_step(self, step: str, details: Dict[str, Any] = None):
        """Print authentication step details"""
        print(f"\n--- {step} ---")
        if details:
            for key, value in details.items():
                print(f"{key}: {value}")

    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle client connection"""
        ip_address = address[0]
        client_id = f"{ip_address}:{address[1]}"
        self.clients[client_id] = AuthenticationState()

        self.print_message_header(f"New Client Connection from {ip_address}")
        print(f"Client ID: {client_id}")

        try:
            while True:
                length_data = client_socket.recv(4)
                if not length_data:
                    break

                message_length = int.from_bytes(length_data, 'big')
                message_data = client_socket.recv(message_length).decode('utf-8')
                
                if not message_data:
                    break

                # Process the message
                message = json.loads(message_data)
                msg_type = MessageType(message['message_type'])

                self.print_message_header(f"Received {msg_type.name} Message")
                self.print_message_details(message.get('data', {}))

                response = self.process_message(message, client_id, ip_address)
                
                # Print response details
                response_data = json.loads(response.decode('utf-8'))
                self.print_message_header("Sending Response")
                self.print_message_details(response_data)

                # Send response
                response_length = len(response).to_bytes(4, 'big')
                client_socket.send(response_length + response)

        except Exception as e:
            logging.error(f"Error handling client {client_id}: {e}")
            print(f"\nError handling client: {e}")
        finally:
            if client_id in self.clients:
                del self.clients[client_id]
            client_socket.close()
            print(f"\nClient {client_id} disconnected")

    def handle_authenticate(self, data: dict, state: AuthenticationState, ip_address: str) -> bytes:
        """Handle authentication request"""
        try:
            username = data.get('username')
            password = data.get('password')

            self.print_message_header("Processing Authentication")
            self.print_auth_step("Authentication Request", {
                "Username": username,
                "Client IP": ip_address
            })

            # Generate challenge
            challenge = NTLMCrypto.generate_nonce()
            self.print_auth_step("Challenge Generation", {
                "Challenge (Nonce)": challenge.hex()
            })

            user = Database.Users.get_user(username)
            if not user:
                self.print_auth_step("Authentication Failed", {
                    "Reason": "User not found"
                })
                return self.create_error_response("Invalid username or password")

            self.print_auth_step("User Information", {
                "Role": user['role'],
                "Created by": user['created_by'],
                "Last login": user['last_login']
            })

            # Create NTLM hash and verify
            password_hash = NTLMCrypto.create_ntlm_hash(password)
            self.print_auth_step("NTLM Hash Generation", {
                "Hash": password_hash.hex()
            })

            # Create and verify NTLM response
            server_challenge = NTLMCrypto.create_ntlm_response(password_hash, challenge)
            self.print_auth_step("Server Challenge Response", {
                "Response": server_challenge.hex()
            })

            if not PasswordManager.verify_password(password, user['password_hash']):
                self.print_auth_step("Authentication Failed", {
                    "Reason": "Invalid password"
                })
                Database.Logs.add_log(
                    LogType.LOGIN_FAILURE,
                    user['id'],
                    ip_address,
                    "Invalid password"
                )
                return self.create_error_response("Invalid username or password")

            self.print_auth_step("Password Verification", {
                "Status": "Success"
            })

            # Create session
            session_id = SessionCrypto.generate_session_id()
            self.print_auth_step("Session Creation", {
                "Session ID": session_id
            })

            Database.Sessions.create_session(user['id'], session_id, ip_address)
            Database.Users.update_last_login(user['id'])

            self.print_auth_step("Database Update", {
                "Status": "Session created and last login updated"
            })

            Database.Logs.add_log(
                LogType.LOGIN_SUCCESS,
                user['id'],
                ip_address,
                "Successful login"
            )

            self.print_auth_step("Authentication Complete", {
                "Status": "Success",
                "Username": user['username'],
                "Role": user['role']
            })

            return json.dumps({
                'status': 'success',
                'session_id': session_id,
                'user': {
                    'username': user['username'],
                    'role': user['role'],
                    'totp_secret': user['totp_secret']
                }
            }).encode('utf-8')

        except Exception as e:
            logging.error(f"Authentication error: {e}")
            self.print_auth_step("Authentication Error", {
                "Error": str(e)
            })
            return self.create_error_response(str(e))

    def process_message(self, message_data: dict, client_id: str, ip_address: str) -> bytes:
        """Process incoming messages"""
        try:
            msg_type = MessageType(message_data['message_type'])
            data = message_data.get('data', {})

            handlers = {
                MessageType.AUTHENTICATE: self.handle_authenticate,
                MessageType.VIEW_LOGS: self.handle_view_logs,
                MessageType.VIEW_USERS: self.handle_view_users,
                MessageType.CHANGE_USERNAME: self.handle_change_username,
                MessageType.ADD_USER: self.handle_add_user,
                MessageType.REMOVE_USER: self.handle_remove_user,
                MessageType.UPDATE_USER: self.handle_update_user,
                MessageType.CHANGE_PASSWORD: self.handle_change_password
            }

            handler = handlers.get(msg_type)
            if handler:
                return handler(data, self.clients[client_id], ip_address)
            else:
                raise ValueError(f"Invalid message type: {msg_type}")

        except Exception as e:
            logging.error(f"Error processing message: {e}")
            return self.create_error_response(str(e))


    def handle_view_logs(self, data: dict, state: AuthenticationState, ip_address: str) -> bytes:
        """Handle view logs request"""
        try:
            session = Database.Sessions.get_session(data['session_id'])
            if not session:
                return self.create_error_response("Invalid session")

            logs = Database.Logs.get_logs(
                limit=data.get('limit', 10),
                offset=(data.get('page', 1) - 1) * 10
            )

            return serialize_response({
                'status': 'success',
                'logs': logs
            })  

        except Exception as e:
            return self.create_error_response(str(e))

    def handle_view_users(self, data: dict, state: AuthenticationState, ip_address: str) -> bytes:
        """Handle view users request"""
        try:
            session = Database.Sessions.get_session(data['session_id'])
            if not session:
                return self.create_error_response("Invalid session")

            users = Database.Users.get_all_users()
            return serialize_response({
                'status': 'success',
                'users': users
            })

        except Exception as e:
            return self.create_error_response(str(e))

    def handle_change_username(self, data: dict, state: AuthenticationState, ip_address: str) -> bytes:
        """Handle username change request"""
        try:
            session = Database.Sessions.get_session(data['session_id'])
            if not session:
                return self.create_error_response("Invalid session")

            success = Database.Users.update_username(
                session['user_id'],
                data['new_username']
            )

            if success:
                Database.Logs.add_log(
                    LogType.USER_UPDATED,
                    session['user_id'],
                    ip_address,
                    f"Username changed to {data['new_username']}"
                )
                return json.dumps({'status': 'success'}).encode('utf-8')
            else:
                return self.create_error_response("Failed to update username")

        except Exception as e:
            return self.create_error_response(str(e))

    def handle_add_user(self, data: dict, state: AuthenticationState, ip_address: str) -> bytes:
        """Handle add user request"""
        try:
            session = Database.Sessions.get_session(data['session_id'])
            if not session:
                return self.create_error_response("Invalid session")

            # Get the admin user
            admin = Database.Users.get_user_by_id(session['user_id'])
            if not admin or admin['role'] not in ['admin', 'system_admin']:
                return self.create_error_response("Permission denied")

            # Create new user
            totp_secret = TOTPManager.generate_totp_secret()
            success = Database.Users.create_user(
                username=data['username'],
                password=data['password'],
                role=data['role'],
                created_by=admin['username']
            )

            if success:
                Database.Logs.add_log(
                    LogType.USER_CREATED,
                    session['user_id'],
                    ip_address,
                    f"Created user {data['username']}"
                )
                return serialize_response({
                    'status': 'success',
                    'totp_secret': totp_secret
                })
            else:
                return self.create_error_response("Failed to create user")

        except Exception as e:
            return self.create_error_response(str(e))

    def handle_remove_user(self, data: dict, state: AuthenticationState, ip_address: str) -> bytes:
        """Handle remove user request"""
        try:
            session = Database.Sessions.get_session(data['session_id'])
            if not session:
                return self.create_error_response("Invalid session")

            admin = Database.Users.get_user_by_id(session['user_id'])
            if not admin or admin['role'] not in ['admin', 'system_admin']:
                return self.create_error_response("Permission denied")

            user = Database.Users.get_user(data['username'])
            if not user:
                return self.create_error_response("User not found")

            if user['role'] == 'admin' and admin['role'] != 'system_admin':
                return self.create_error_response("Cannot remove admin user")

            success = Database.Users.delete_user(user['id'])
            if success:
                Database.Logs.add_log(
                    LogType.USER_DELETED,
                    session['user_id'],
                    ip_address,
                    f"Removed user {data['username']}"
                )
                return json.dumps({'status': 'success'}).encode('utf-8')
            else:
                return self.create_error_response("Failed to remove user")

        except Exception as e:
            return self.create_error_response(str(e))

    def handle_update_user(self, data: dict, state: AuthenticationState, ip_address: str) -> bytes:
        """Handle update user request"""
        try:
            session = Database.Sessions.get_session(data['session_id'])
            if not session:
                return self.create_error_response("Invalid session")

            admin = Database.Users.get_user_by_id(session['user_id'])
            if not admin or admin['role'] not in ['admin', 'system_admin']:
                return self.create_error_response("Permission denied")

            user = Database.Users.get_user(data['username'])
            if not user:
                return self.create_error_response("User not found")

            update_type = data['update_type']
            new_value = data['new_value']

            if update_type == 'password':
                success = Database.Users.update_password(user['id'], new_value)
            elif update_type == 'role':
                if admin['role'] != 'system_admin':
                    return self.create_error_response("Only system admin can change roles")
                success = Database.Users.update_role(user['id'], new_value)
            else:
                return self.create_error_response("Invalid update type")

            if success:
                Database.Logs.add_log(
                    LogType.USER_UPDATED,
                    session['user_id'],
                    ip_address,
                    f"Updated user {data['username']}: {update_type}"
                )
                return json.dumps({'status': 'success'}).encode('utf-8')
            else:
                return self.create_error_response("Failed to update user")

        except Exception as e:
            return self.create_error_response(str(e))

    def handle_change_password(self, data: dict, state: AuthenticationState, ip_address: str) -> bytes:
        """Handle password change request"""
        try:
            session = Database.Sessions.get_session(data['session_id'])
            if not session:
                return self.create_error_response("Invalid session")

            user = Database.Users.get_user_by_id(session['user_id'])
            if not user:
                return self.create_error_response("User not found")

            if not PasswordManager.verify_password(data['current_password'], user['password_hash']):
                return self.create_error_response("Current password is incorrect")

            success = Database.Users.update_password(user['id'], data['new_password'])
            if success:
                Database.Logs.add_log(
                    LogType.PASSWORD_CHANGE,
                    session['user_id'],
                    ip_address,
                    "Password changed"
                )
                return json.dumps({'status': 'success'}).encode('utf-8')
            else:
                return self.create_error_response("Failed to update password")

        except Exception as e:
            return self.create_error_response(str(e))

    @staticmethod
    def create_error_response(message: str) -> bytes:
        """Create error response"""
        return json.dumps({
            'status': 'error',
            'message': message
        }).encode('utf-8')

def main():
    try:
        server = NTLMServer()
        print(f"Starting NTLM Authentication Server on {SERVER_HOST}:{SERVER_PORT}")
        print("\nDefault admin credentials:")
        print(f"Username: {DEFAULT_ADMIN['username']}")
        print(f"Password: {DEFAULT_ADMIN['password']}")
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.stop()
    except Exception as e:
        print(f"Error starting server: {e}")
        logging.error(f"Server startup error: {e}")

if __name__ == "__main__":
    main()