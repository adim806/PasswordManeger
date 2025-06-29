# Secure Password Manager

A secure, offline password manager desktop application built with Python and Tkinter.

## Features

- Master password authentication with bcrypt hashing
- AES-256 encryption for all stored password entries
- Completely offline operation (no cloud storage or external servers)
- Password generator with customizable options
- Search and filter functionality
- Copy passwords to clipboard with auto-clear timer
- Password strength indicator
- Auto-lock after inactivity

## Installation

1. Ensure you have Python 3.8+ installed
2. Clone this repository
3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Run the application:
   ```
   python password_manager/main.py
   ```

## Security Features

- AES-256 encryption for password data storage
- Bcrypt for master password hashing
- Secure key derivation using PBKDF2
- Salt generation for each encrypted entry
- Memory-safe password handling
- Protection against common attacks

## Usage

1. Create an account with a strong master password
2. Add your password entries
3. Use the search functionality to find entries
4. Generate strong passwords using the built-in generator
5. Backup your database regularly

## Security Best Practices

- Use a strong, unique master password
- Enable auto-lock feature
- Regularly backup your encrypted database
- Keep your system and the application updated
