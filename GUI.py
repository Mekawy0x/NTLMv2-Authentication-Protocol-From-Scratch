# gui.py
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QLabel, QLineEdit, QPushButton, QTabWidget, QTableWidget, 
                            QTableWidgetItem, QMessageBox, QFormLayout, QGroupBox, 
                            QHeaderView, QComboBox, QMenuBar, QMenu, QAction)
from PyQt5.QtCore import Qt
from client import NTLMClient
from config import SERVER_HOST, SERVER_PORT, UserRole
import pyotp
from datetime import datetime

class LoginWindow(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.client = NTLMClient()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Server Connection Group
        server_group = QGroupBox("Server Connection")
        server_layout = QFormLayout()
        self.host_input = QLineEdit(SERVER_HOST)
        self.port_input = QLineEdit(str(SERVER_PORT))
        server_layout.addRow("Host:", self.host_input)
        server_layout.addRow("Port:", self.port_input)
        server_group.setLayout(server_layout)
        
        # Login Group
        login_group = QGroupBox("Authentication")
        login_layout = QFormLayout()
        self.username_input = QLineEdit()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.totp_input = QLineEdit()
        login_layout.addRow("Username:", self.username_input)
        login_layout.addRow("Password:", self.password_input)
        login_layout.addRow("TOTP Code:", self.totp_input)
        login_group.setLayout(login_layout)
        
        # Buttons
        self.connect_btn = QPushButton("Connect")
        self.login_btn = QPushButton("Login")
        self.login_btn.setEnabled(False)
        
        # Layout
        layout.addWidget(server_group)
        layout.addWidget(login_group)
        layout.addWidget(self.connect_btn)
        layout.addWidget(self.login_btn)
        
        self.setLayout(layout)
        
        # Signals
        self.connect_btn.clicked.connect(self.connect_to_server)
        self.login_btn.clicked.connect(self.authenticate)

    def connect_to_server(self):
        host = self.host_input.text()
        port = int(self.port_input.text())
        
        if self.client.connect():
            self.login_btn.setEnabled(True)
            self.connect_btn.setEnabled(False)
            QMessageBox.information(self, "Success", "Connected to server successfully!")
        else:
            QMessageBox.critical(self, "Error", "Failed to connect to server")

    def authenticate(self):
        username = self.username_input.text()
        password = self.password_input.text()
        totp_code = self.totp_input.text()
        
        if self.client.authenticate(username, password):
            if self.client.current_user['totp_secret']:
                if not pyotp.TOTP(self.client.current_user['totp_secret']).verify(totp_code):
                    QMessageBox.critical(self, "Error", "Invalid TOTP code")
                    return
            
            QMessageBox.information(self, "Success", "Login successful!")
            self.parent().show_main_interface()
        else:
            QMessageBox.critical(self, "Error", "Authentication failed")

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_menu()
        self.login_window = LoginWindow(self)
        self.setCentralWidget(self.login_window)
        self.setWindowTitle("NTLM Authentication System")
        self.resize(800, 600)
        
    def init_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu('File')
        
        logout_action = QAction('Logout', self)
        logout_action.triggered.connect(self.logout)
        file_menu.addAction(logout_action)
        
        exit_action = QAction('Exit', self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
    def create_profile_tab(self):
        profile_tab = QWidget()
        layout = QFormLayout()
        
        # Display user information
        user = self.login_window.client.current_user
        layout.addRow(QLabel("<b>Username:</b>"), QLabel(user['username']))
        layout.addRow(QLabel("<b>Role:</b>"), QLabel(user['role']))
        layout.addRow(QLabel("<b>TOTP Secret:</b>"), QLabel(user['totp_secret']))
        
        profile_tab.setLayout(layout)
        self.tabs.addTab(profile_tab, "Profile")
    
    def create_password_change_tab(self):
        password_tab = QWidget()
        layout = QFormLayout()
        
        self.current_password_input = QLineEdit()
        self.current_password_input.setEchoMode(QLineEdit.Password)
        self.new_password_input = QLineEdit()
        self.new_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        
        change_btn = QPushButton("Change Password")
        change_btn.clicked.connect(self.change_password)
        
        layout.addRow(QLabel("Current Password:"), self.current_password_input)
        layout.addRow(QLabel("New Password:"), self.new_password_input)
        layout.addRow(QLabel("Confirm Password:"), self.confirm_password_input)
        layout.addRow(change_btn)
        
        password_tab.setLayout(layout)
        self.tabs.addTab(password_tab, "Change Password")
    
    def create_users_tab(self):
        users_tab = QWidget()
        layout = QVBoxLayout()
        
        self.users_table = QTableWidget()
        self.users_table.setColumnCount(4)
        self.users_table.setHorizontalHeaderLabels(["Username", "Role", "Created By", "Last Login"])
        self.users_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        refresh_btn = QPushButton("Refresh Users")
        refresh_btn.clicked.connect(self.load_users)
        
        layout.addWidget(self.users_table)
        layout.addWidget(refresh_btn)
        
        users_tab.setLayout(layout)
        self.tabs.addTab(users_tab, "View Users")
        self.load_users()
    
    def create_logs_tab(self):
        logs_tab = QWidget()
        layout = QVBoxLayout()
        
        self.logs_table = QTableWidget()
        self.logs_table.setColumnCount(5)
        self.logs_table.setHorizontalHeaderLabels(["Timestamp", "Type", "User", "IP", "Details"])
        self.logs_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        refresh_btn = QPushButton("Refresh Logs")
        refresh_btn.clicked.connect(self.load_logs)
        
        layout.addWidget(self.logs_table)
        layout.addWidget(refresh_btn)
        
        logs_tab.setLayout(layout)
        self.tabs.addTab(logs_tab, "View Logs")
        self.load_logs()
    
    def create_user_management_tab(self):
        management_tab = QWidget()
        layout = QVBoxLayout()
        
        # Add User Group
        add_group = QGroupBox("Add User")
        add_layout = QFormLayout()
        
        self.new_username = QLineEdit()
        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        self.new_role = QComboBox()
        self.new_role.addItems([role.value for role in UserRole])
        
        add_btn = QPushButton("Add User")
        add_btn.clicked.connect(self.add_user)
        
        add_layout.addRow("Username:", self.new_username)
        add_layout.addRow("Password:", self.new_password)
        add_layout.addRow("Role:", self.new_role)
        add_layout.addRow(add_btn)
        add_group.setLayout(add_layout)
        
        # Remove User Group
        remove_group = QGroupBox("Remove User")
        remove_layout = QFormLayout()
        
        self.remove_username = QLineEdit()
        remove_btn = QPushButton("Remove User")
        remove_btn.clicked.connect(self.remove_user)
        
        remove_layout.addRow("Username:", self.remove_username)
        remove_layout.addRow(remove_btn)
        remove_group.setLayout(remove_layout)
        
        layout.addWidget(add_group)
        layout.addWidget(remove_group)
        management_tab.setLayout(layout)
        self.tabs.addTab(management_tab, "User Management")
    
    def load_users(self):
        try:
            message = {
                'message_type': 5,  # VIEW_USERS
                'data': {
                    'session_id': self.login_window.client.session['session_id']
                }
            }
            
            response = self.login_window.client.send_message(message)
            
            if response and response.get('status') == 'success':
                users = response.get('users', [])
                self.users_table.setRowCount(len(users))
                
                for row, user in enumerate(users):
                    self.users_table.setItem(row, 0, QTableWidgetItem(user['username']))
                    self.users_table.setItem(row, 1, QTableWidgetItem(user['role']))
                    self.users_table.setItem(row, 2, QTableWidgetItem(user['created_by']))
                    last_login = user['last_login'] if user['last_login'] else "Never"
                    self.users_table.setItem(row, 3, QTableWidgetItem(last_login))
            else:
                QMessageBox.critical(self, "Error", "Failed to load users")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading users: {str(e)}")
    
    def load_logs(self):
        try:
            message = {
                'message_type': 4,  # VIEW_LOGS
                'data': {
                    'session_id': self.login_window.client.session['session_id'],
                    'limit': 100
                }
            }
            
            response = self.login_window.client.send_message(message)
            
            if response and response.get('status') == 'success':
                logs = response.get('logs', [])
                self.logs_table.setRowCount(len(logs))
                
                for row, log in enumerate(logs):
                    self.logs_table.setItem(row, 0, QTableWidgetItem(log['timestamp']))
                    self.logs_table.setItem(row, 1, QTableWidgetItem(log['log_type']))
                    self.logs_table.setItem(row, 2, QTableWidgetItem(log.get('username', 'SYSTEM')))
                    self.logs_table.setItem(row, 3, QTableWidgetItem(log['ip_address']))
                    self.logs_table.setItem(row, 4, QTableWidgetItem(log['details']))
            else:
                QMessageBox.critical(self, "Error", "Failed to load logs")
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error loading logs: {str(e)}")
    
    def change_password(self):
        current = self.current_password_input.text()
        new = self.new_password_input.text()
        confirm = self.confirm_password_input.text()
        
        if new != confirm:
            QMessageBox.critical(self, "Error", "New passwords don't match")
            return
        
        try:
            message = {
                'message_type': 10,  # CHANGE_PASSWORD
                'data': {
                    'session_id': self.login_window.client.session['session_id'],
                    'current_password': current,
                    'new_password': new
                }
            }
            
            response = self.login_window.client.send_message(message)
            
            if response and response.get('status') == 'success':
                QMessageBox.information(self, "Success", "Password changed successfully")
                self.current_password_input.clear()
                self.new_password_input.clear()
                self.confirm_password_input.clear()
            else:
                QMessageBox.critical(self, "Error", response.get('message', 'Failed to change password'))
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error changing password: {str(e)}")
    
    def add_user(self):
        username = self.new_username.text()
        password = self.new_password.text()
        role = self.new_role.currentText()
        
        if not username or not password:
            QMessageBox.critical(self, "Error", "Username and password are required")
            return
        
        try:
            message = {
                'message_type': 7,  # ADD_USER
                'data': {
                    'session_id': self.login_window.client.session['session_id'],
                    'username': username,
                    'password': password,
                    'role': role
                }
            }
            
            response = self.login_window.client.send_message(message)
            
            if response and response.get('status') == 'success':
                QMessageBox.information(self, "Success", f"User {username} created successfully")
                self.new_username.clear()
                self.new_password.clear()
                self.load_users()
            else:
                QMessageBox.critical(self, "Error", response.get('message', 'Failed to add user'))
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error adding user: {str(e)}")
    
    def remove_user(self):
        username = self.remove_username.text()
        
        if not username:
            QMessageBox.critical(self, "Error", "Username is required")
            return
        
        reply = QMessageBox.question(
            self, 'Confirm Removal',
            f"Are you sure you want to remove user {username}?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        
        if reply == QMessageBox.No:
            return
        
        try:
            message = {
                'message_type': 8,  # REMOVE_USER
                'data': {
                    'session_id': self.login_window.client.session['session_id'],
                    'username': username
                }
            }
            
            response = self.login_window.client.send_message(message)
            
            if response and response.get('status') == 'success':
                QMessageBox.information(self, "Success", f"User {username} removed successfully")
                self.remove_username.clear()
                self.load_users()
            else:
                QMessageBox.critical(self, "Error", response.get('message', 'Failed to remove user'))
        
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error removing user: {str(e)}")
    
    def show_main_interface(self):
        self.tabs = QTabWidget()
        
        # Profile Tab
        self.create_profile_tab()
        
        # Password Change Tab (for all users)
        self.create_password_change_tab()
        
        # Admin-only tabs
        if self.login_window.client.current_user['role'] in ['admin', 'system_admin']:
            self.create_users_tab()
            self.create_logs_tab()
            self.create_user_management_tab()
        
        self.setCentralWidget(self.tabs)
    
    def logout(self):
        """Safe logout that handles widget deletion properly"""
        try:
            # 1. Send logout message if connected
            client = getattr(self.login_window, 'client', None)
            if client and getattr(client, 'session', None):
                try:
                    message = {
                        'message_type': 11,  # LOGOUT
                        'data': {
                            'session_id': client.session['session_id']
                        }
                    }
                    client.send_message(message)
                except Exception as e:
                    print(f"Logout message failed: {e}")

            # 2. Disconnect and reset client
            if client:
                client.disconnect()
            
            # 3. Completely recreate the login window
            self.login_window = LoginWindow(self)
            
            # 4. Reset UI state
            self.login_window.login_btn.setEnabled(False)
            self.login_window.connect_btn.setEnabled(True)
            
            # 5. Show the new login window
            self.setCentralWidget(self.login_window)
            
            QMessageBox.information(self, "Logged Out", "You have been successfully logged out.")
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Logout error: {str(e)}")
def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()