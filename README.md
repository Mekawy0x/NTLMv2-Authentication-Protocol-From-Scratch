# NTLM-Authentication-Protocol-From-Scratch
A secure client-server authentication system implementing NTLM (NT LAN Manager) protocol with Two-Factor Authentication (TOTP) support, built with Python and PyQt5.

## Programming Language
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)

## Databases
![MySQL](https://img.shields.io/badge/mysql-4479A1.svg?style=for-the-badge&logo=mysql&logoColor=white)

## Authentication Protocol
![NTLM v2](https://img.shields.io/badge/NTLMv2-F57C00.svg?style=for-the-badge&logo=NTLM&logoColor=Black)


## Features
- Secure Authentication: NTLM protocol implementation for secure credential exchange
- Two-Factor Authentication: Time-based One-Time Password (TOTP) support
- Role-Based Access Control: Different user roles with varying privileges
- User Management: Add/remove users, change passwords
- Activity Logging: Comprehensive logging of all system activities
- GUI Interface: User-friendly PyQt5 interface for both clients and administrators

### Prerequisites
- Python 3.7+
- pip3

### Setup 
1. Clone the repository:
`git clone https://github.com/AhmedAdel82/NTLM.git` 
> cd NTLM

2. Install dependencies:
> pip install -r requirements.txt

3. Configure the server (edit config.py):
SERVER_HOST = 'localhost'  # Server IP address
SERVER_PORT = 5000         # Server port

4. Run The Server:
> python server.py
5. Run The Client Application:
> python client.py
> help
> login
> Enter Username
> Enter Password
Then Go to Server Terminal You will see the TOTP Secret For The System User Admin
To GET TOTP Code Consists of 6 digits
Open Another Terminal
> python totp_generator -w [TOTP Secret]
> python GUI.py


## Usage
### 1. Login Screen:
- Enter server connection details
- Provide username and password
- Enter TOTP code if configured

### 2. Main Interface:
- Profile: View your account details
- Change Password: Update your password
- View Users: Admin-only user listing (for admin/system_admin roles)
- View Logs: Admin-only activity logs
- User Management: Admin-only user management tools

## User Roles:
- regular_user: Basic access (profile and password change)
- admin: Can view users/logs and manage users
- system_admin: Full system access (all admin privileges)

## Security Features
- Secure password storage (hashed passwords)
- Session management with expiration
- TOTP two-factor authentication
- Encrypted client-server communication
- Comprehensive activity logging
   

