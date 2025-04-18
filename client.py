import socket
import json
import getpass
import sys
import os
from typing import Optional, Dict
import pyotp
from datetime import datetime
from message_types import MessageType
from crypto_utils import PasswordManager, NTLMCrypto
from config import SERVER_HOST, SERVER_PORT, UserRole
from utils import format_datetime

class NTLMClient:
    def __init__(self):
        self.socket = None
        self.session = None
        self.current_user = None
        self.connected = False  # Track connection state

    def connect(self) -> bool:
        """Establish connection to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((SERVER_HOST, SERVER_PORT))
            self.connected = True
            return True
        except Exception as e:
            self.connected = False
            return False

    def disconnect(self):
        """Close connection to server"""
        if self.socket:
            self.socket.close()
            self.socket = None
        self.connected = False
        self.session = None
        self.current_user = None
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

    def print_auth_step(self, step: str, details: Dict = None):
        """Print authentication step details"""
        print(f"\n--- {step} ---")
        if details:
            for key, value in details.items():
                print(f"{key}: {value}")

    def connect(self) -> bool:
        """Establish connection to the server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((SERVER_HOST, SERVER_PORT))
            self.print_auth_step("Connection Established", {
                "Server": f"{SERVER_HOST}:{SERVER_PORT}",
                "Local Address": self.socket.getsockname()
            })
            return True
        except Exception as e:
            self.print_auth_step("Connection Failed", {
                "Error": str(e)
            })
            return False

    def disconnect(self):
        """Close connection to server"""
        if self.socket:
            self.socket.close()
            self.socket = None
            self.print_auth_step("Connection Closed")

    def send_message(self, message: dict) -> Optional[Dict]:
        """Send message to server and receive response"""
        try:
            # Convert message to JSON and encode
            message_json = json.dumps(message)
            message_bytes = message_json.encode('utf-8')
            
            # Send message length followed by message
            message_length = len(message_bytes).to_bytes(4, 'big')
            self.socket.send(message_length + message_bytes)

            self.print_auth_step("Message Sent", {
                "Type": MessageType(message['message_type']).name,
                "Length": len(message_bytes),
                "Content": message.get('data', {})
            })

            # Receive response length
            length_data = self.socket.recv(4)
            if not length_data:
                self.print_auth_step("No Response", {
                    "Status": "Connection closed by server"
                })
                return None

            # Receive response
            message_length = int.from_bytes(length_data, 'big')
            response_data = self.socket.recv(message_length)
            response = json.loads(response_data.decode('utf-8'))

            self.print_auth_step("Response Received", {
                "Length": message_length,
                "Content": response
            })

            return response

        except Exception as e:
            self.print_auth_step("Communication Error", {
                "Error": str(e)
            })
            return None

   
    
    def authenticate(self, username: str, password: str) -> bool:
        """Perform NTLM authentication"""
        try:
            self.print_message_header("Starting NTLM Authentication Process")
            
            # Generate client nonce
            client_nonce = NTLMCrypto.generate_nonce()
            self.print_auth_step("Client Nonce Generation", {
                "Nonce": client_nonce.hex()
            })

            # Create NTLM Type 1 message (Negotiate)
            workstation = socket.gethostname()
            domain = ""
            
            self.print_auth_step("NTLM Negotiate (Type 1)", {
                "Username": username,
                "Workstation": workstation,
                "Domain": domain or "NULL",
                "Flags": "NEGOTIATE_UNICODE | NEGOTIATE_NTLM | REQUEST_TARGET"
            })

            # Create authentication message
            message = {
                'message_type': MessageType.AUTHENTICATE.value,
                'data': {
                    'username': username,
                    'password': password,
                    'workstation': workstation,
                    'domain': domain,
                    'client_nonce': client_nonce.hex()
                }
            }

            # Send authentication request
            self.print_message_header("Sending Authentication Request")
            response = self.send_message(message)
            
            if not response:
                self.print_auth_step("Authentication Failed", {
                    "Reason": "No response from server"
                })
                return False

            # Process server response
            self.print_message_header("Processing Server Response")
            
            if response.get('status') == 'success':
                self.session = response
                self.current_user = response['user']
                
                self.print_auth_step("Authentication Successful", {
                    "Username": self.current_user['username'],
                    "Role": self.current_user['role'],
                    "Session ID": self.session['session_id']
                })

                # TOTP Verification
                if self.current_user['totp_secret']:
                    self.print_auth_step("2FA Required", {
                        "Type": "TOTP",
                        "Secret Length": len(self.current_user['totp_secret'])
                    })
                
                return True
            else:
                error_msg = response.get('message', 'Unknown error')
                self.print_auth_step("Authentication Failed", {
                    "Error": error_msg
                })
                return False

        except Exception as e:
            self.print_auth_step("Authentication Error", {
                "Error": str(e)
            })
            return False
        
        
    

class ClientCLI:
    def __init__(self):
        self.client = NTLMClient()
        self.commands = {
            'help': self.show_help,
            'login': self.login,
            'logout': self.logout,
            'profile': self.view_profile,
            'change_password': self.change_password,
            'change_name': self.change_name,
            'users': self.view_users,
            'logs': self.view_logs,
            'add_user': self.add_user,
            'remove_user': self.remove_user,
            'update_user': self.update_user,
            'clear': self.clear_screen,
            'exit': self.exit_program
        }

    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_help(self):
        """Show available commands"""
        print("\nAvailable commands:")
        print("  login           - Login to the system")
        print("  logout          - Logout from the system")
        print("  profile         - View your profile")
        print("  change_password - Change your password")
        print("  change_name     - Change your username")
        if self.client.current_user and self.client.current_user['role'] in ['admin', 'system_admin']:
            print("  users           - View all users")
            print("  logs            - View system logs")
            print("  add_user        - Add new user")
            print("  remove_user     - Remove user")
            print("  update_user     - Update user")
        print("  clear           - Clear screen")
        print("  help            - Show this help")
        print("  exit            - Exit program")

    def print_header(self, title: str):
        """Print formatted header"""
        print("\n" + "="*50)
        print(f" {title} ")
        print("="*50)


    def login(self):
        """Handle user login"""
        self.print_header("NTLM Authentication Login")
        if not self.client.connect():
            print("Failed to connect to server")
            return

        username = input("Username: ")
        password = getpass.getpass("Password: ")

        if self.client.authenticate(username, password):
            if self.client.current_user['totp_secret']:
                self.print_header("Two-Factor Authentication")
                totp = pyotp.TOTP(self.client.current_user['totp_secret'])
                code = input("Enter 2FA code: ")
                if not totp.verify(code):
                    self.print_header("2FA Verification Failed")
                    self.client.disconnect()
                    return
            self.print_header("Login Successful")
            self.show_help()
        else:
            self.print_header("Login Failed")
            self.client.disconnect()

    def logout(self):
        """Handle user logout"""
        if self.client.current_user:
            self.client.current_user = None
            self.client.session = None
            self.client.disconnect()
            print("Logged out successfully")
        else:
            print("Not logged in")

    def view_profile(self):
        """View user profile"""
        if not self.client.current_user:
            print("Please login first")
            return

        print("\nProfile Information:")
        print(f"Username: {self.client.current_user['username']}")
        print(f"Role: {self.client.current_user['role']}")

    def view_logs(self):
        """View system logs (admin only)"""
        if not self.client.current_user or self.client.current_user['role'] not in ['admin', 'system_admin']:
            print("Permission denied")
            return

        try:
            message = {
                'message_type': MessageType.VIEW_LOGS.value,
                'data': {
                    'session_id': self.client.session['session_id'],
                    'page': 1,
                    'limit': 10
                }
            }
        
            response = self.client.send_message(message)
        
            if response and response.get('status') == 'success':
                logs = response.get('logs', [])
                if not logs:
                    print("No logs found")
                    return

                print("\nSystem Logs:")
                print("-" * 100)
                print(f"{'Timestamp':<20} {'Type':<15} {'User':<15} {'IP Address':<15} {'Details':<30}")
                print("-" * 100)
            
                for log in logs:
                    timestamp = format_datetime(datetime.fromisoformat(log['timestamp']))
                    print(f"{timestamp:<20} {log['log_type']:<15} {log['username']:<15} "
                          f"{log['ip_address']:<15} {log['details']:<30}")
            else:
                print(f"Failed to retrieve logs: {response.get('message', 'Unknown error')}")

        except Exception as e:
            print(f"Error viewing logs: {e}")

    def view_users(self):
        """View all users (admin only)"""
        if not self.client.current_user or self.client.current_user['role'] not in ['admin', 'system_admin']:
            print("Permission denied")
            return

        try:
            message = {
                'message_type': MessageType.VIEW_USERS.value,
                'data': {
                    'session_id': self.client.session['session_id']
                }
            }
        
            response = self.client.send_message(message)
        
            if response and response.get('status') == 'success':
                users = response.get('users', [])
                if not users:
                    print("No users found")
                    return

                print("\nUser List:")
                print("-" * 80)
                print(f"{'Username':<20} {'Role':<15} {'Created By':<20} {'Last Login':<20}")
                print("-" * 80)
            
                for user in users:
                    last_login = format_datetime(datetime.fromisoformat(user['last_login']) if user['last_login'] else None)
                    print(f"{user['username']:<20} {user['role']:<15} {user['created_by']:<20} {last_login:<20}")
            else:
                print(f"Failed to retrieve users: {response.get('message', 'Unknown error')}")

        except Exception as e:
            print(f"Error viewing users: {e}")

    def change_name(self):
        """Change username"""
        if not self.client.current_user:
            print("Please login first")
            return

        try:
            new_username = input("Enter new username: ")
            confirm = input(f"Confirm changing username to '{new_username}' (yes/no): ")

            if confirm.lower() != 'yes':
                print("Username change cancelled")
                return

            message = {
                'message_type': MessageType.CHANGE_USERNAME.value,
                'data': {
                    'session_id': self.client.session['session_id'],
                    'new_username': new_username
                }
            }
            
            response = self.client.send_message(message)
            
            if response and response.get('status') == 'success':
                self.client.current_user['username'] = new_username
                print("Username changed successfully")
            else:
                print(f"Failed to change username: {response.get('message', 'Unknown error')}")

        except Exception as e:
            print(f"Error changing username: {e}")

    def change_password(self):
        """Change user password"""
        if not self.client.current_user:
            print("Please login first")
            return

        try:
            current_password = getpass.getpass("Current password: ")
            new_password = getpass.getpass("New password: ")
            confirm_password = getpass.getpass("Confirm new password: ")

            if new_password != confirm_password:
                print("Passwords do not match")
                return

            # Validate password complexity
            is_valid, message = PasswordManager.validate_password_complexity(new_password)
            if not is_valid:
                print(f"Password validation failed: {message}")
                return

            message = {
                'message_type': MessageType.CHANGE_PASSWORD.value,
                'data': {
                    'session_id': self.client.session['session_id'],
                    'current_password': current_password,
                    'new_password': new_password
                }
            }
            
            response = self.client.send_message(message)
            
            if response and response.get('status') == 'success':
                print("Password changed successfully")
                self.logout()  # Force re-login after password change
            else:
                print(f"Failed to change password: {response.get('message', 'Unknown error')}")

        except Exception as e:
            print(f"Error changing password: {e}")

    def add_user(self):
        """Add new user (admin only)"""
        if not self.client.current_user or self.client.current_user['role'] not in ['admin', 'system_admin']:
            print("Permission denied")
            return

        try:
            print("\nAdd New User")
            print("-" * 30)
            
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            confirm_password = getpass.getpass("Confirm password: ")

            if password != confirm_password:
                print("Passwords do not match")
                return

            is_valid, validation_message = PasswordManager.validate_password_complexity(password)
            if not is_valid:
                print(f"Password validation failed: {validation_message}")
                return

            print("\nSelect role:")
            print("1. User")
            if self.client.current_user['role'] == 'system_admin':
                print("2. Admin")
            
            role_choice = input("Enter choice (1-2): ")
            role = "user" if role_choice == "1" else "admin"

            message = {
                'message_type': MessageType.ADD_USER.value,
                'data': {
                    'session_id': self.client.session['session_id'],
                    'username': username,
                    'password': password,
                    'role': role
                }
            }
            
            response = self.client.send_message(message)
            
            if response and response.get('status') == 'success':
                print(f"\nUser '{username}' created successfully")
                print(f"TOTP Secret: {response['totp_secret']}")
                print("Please save this TOTP secret and provide it to the user securely")
            else:
                print(f"Failed to create user: {response.get('message', 'Unknown error')}")

        except Exception as e:
            print(f"Error adding user: {e}")

    def remove_user(self):
        """Remove user (admin only)"""
        if not self.client.current_user or self.client.current_user['role'] not in ['admin', 'system_admin']:
            print("Permission denied")
            return

        try:
            # First show current users
            self.view_users()

            username = input("\nEnter username to remove: ")
            
            if username == self.client.current_user['username']:
                print("Cannot remove your own account")
                return

            confirm = input(f"Are you sure you want to remove user '{username}'? This action cannot be undone (yes/no): ")
            if confirm.lower() != 'yes':
                print("User removal cancelled")
                return

            message = {
                'message_type': MessageType.REMOVE_USER.value,
                'data': {
                    'session_id': self.client.session['session_id'],
                    'username': username
                }
            }
            
            response = self.client.send_message(message)
            
            if response and response.get('status') == 'success':
                print(f"User '{username}' removed successfully")
            else:
                print(f"Failed to remove user: {response.get('message', 'Unknown error')}")

        except Exception as e:
            print(f"Error removing user: {e}")

    def update_user(self):
        """Update user information (admin only)"""
        if not self.client.current_user or self.client.current_user['role'] not in ['admin', 'system_admin']:
            print("Permission denied")
            return

        try:
            # First show current users
            self.view_users()

            username = input("\nEnter username to update: ")
            
            print("\nUpdate options:")
            print("1. Reset password")
            print("2. Change username")
            if self.client.current_user['role'] == 'system_admin':
                print("3. Change role")
            
            choice = input("Enter choice: ")

            update_type = None
            new_value = None

            if choice == '1':
                update_type = 'password'
                new_password = getpass.getpass("Enter new password: ")
                confirm_password = getpass.getpass("Confirm new password: ")

                if new_password != confirm_password:
                    print("Passwords do not match")
                    return

                is_valid, validation_message = PasswordManager.validate_password_complexity(new_password)
                if not is_valid:
                    print(f"Password validation failed: {validation_message}")
                    return

                new_value = new_password

            elif choice == '2':
                update_type = 'username'
                new_value = input("Enter new username: ")

            elif choice == '3' and self.client.current_user['role'] == 'system_admin':
                update_type = 'role'
                print("\nSelect new role:")
                print("1. User")
                print("2. Admin")
                role_choice = input("Enter choice (1-2): ")
                new_value = "user" if role_choice == "1" else "admin"

            else:
                print("Invalid choice")
                return

            message = {
                'message_type': MessageType.UPDATE_USER.value,
                'data': {
                    'session_id': self.client.session['session_id'],
                    'username': username,
                    'update_type': update_type,
                    'new_value': new_value
                }
            }
            
            response = self.client.send_message(message)
            
            if response and response.get('status') == 'success':
                print(f"User '{username}' updated successfully")
            else:
                print(f"Failed to update user: {response.get('message', 'Unknown error')}")

        except Exception as e:
            print(f"Error updating user: {e}")

    def exit_program(self):
        """Exit the program"""
        if self.client.socket:
            self.client.disconnect()
        print("Goodbye!")
        sys.exit(0)

    def run(self):
        """Main CLI loop"""
        self.clear_screen()
        self.print_header("Welcome to NTLM Authentication System")
        print("Type 'help' for available commands")

        while True:
            try:
                command = input("\n> ").strip().lower()
                if command in self.commands:
                    self.commands[command]()
                else:
                    print("Unknown command. Type 'help' for available commands")
            except KeyboardInterrupt:
                print("\nUse 'exit' command to quit")
            except Exception as e:
                print(f"Error: {e}")

def main():
    """Main function"""
    cli = ClientCLI()
    cli.run()

if __name__ == "__main__":
    main()