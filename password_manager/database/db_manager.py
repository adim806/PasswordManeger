"""
Database manager for the password manager application.
Handles all database operations including schema creation and CRUD operations.
"""

import os
import sqlite3
import logging
from datetime import datetime
from password_manager.config.config import DATABASE_PATH, PASSWORD_HISTORY_COUNT

logger = logging.getLogger(__name__)

class DatabaseManager:
    """
    Handles all database operations for the password manager.
    Uses SQLite for local, secure storage.
    """
    
    def __init__(self, db_path=None):
        """
        Initialize the database connection.
        
        Args:
            db_path (str, optional): Path to the SQLite database file.
        """
        self.db_path = db_path or DATABASE_PATH
        self.connection = None
        self.cursor = None
        
    def connect(self):
        """
        Establish a connection to the SQLite database.
        Create the database file if it doesn't exist.
        """
        try:
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row  # Return rows as dictionaries
            self.cursor = self.connection.cursor()
            logger.info("Database connection established")
            return True
        except sqlite3.Error as e:
            logger.error(f"Database connection error: {e}")
            return False
            
    def close(self):
        """Close the database connection."""
        if self.connection:
            self.connection.close()
            self.connection = None
            self.cursor = None
            logger.info("Database connection closed")
            
    def initialize_database(self):
        """
        Initialize the database schema if it doesn't exist.
        Creates all necessary tables for the password manager.
        """
        if not self.connection:
            if not self.connect():
                return False
                
        try:
            # Create users table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    master_password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_date TEXT NOT NULL,
                    last_login TEXT
                )
            ''')
            
            # Create passwords table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS passwords (
                    entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    service_name TEXT NOT NULL,
                    username TEXT,
                    encrypted_password TEXT NOT NULL,
                    encrypted_notes TEXT,
                    salt TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    created_date TEXT NOT NULL,
                    modified_date TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            ''')
            
            # Create password history table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_history (
                    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id INTEGER NOT NULL,
                    encrypted_password TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    modified_date TEXT NOT NULL,
                    FOREIGN KEY (entry_id) REFERENCES passwords(entry_id)
                )
            ''')
            
            # Create settings table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    setting_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    setting_key TEXT NOT NULL,
                    setting_value TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(user_id),
                    UNIQUE(user_id, setting_key)
                )
            ''')
            
            self.connection.commit()
            logger.info("Database schema initialized")
            return True
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            return False
    
    # User-related operations
    
    def create_user(self, username, password_hash, salt):
        """
        Create a new user in the database.
        
        Args:
            username (str): The username for the new user
            password_hash (str): Bcrypt hash of the master password
            salt (str): Salt used for master password hashing
            
        Returns:
            int: The user_id of the created user, or None if error
        """
        if not self.connection:
            if not self.connect():
                return None
                
        try:
            current_time = datetime.now().isoformat()
            self.cursor.execute(
                "INSERT INTO users (username, master_password_hash, salt, created_date) VALUES (?, ?, ?, ?)",
                (username, password_hash, salt, current_time)
            )
            self.connection.commit()
            user_id = self.cursor.lastrowid
            logger.info(f"User created with ID: {user_id}")
            return user_id
        except sqlite3.Error as e:
            logger.error(f"Error creating user: {e}")
            return None
    
    def get_user_by_username(self, username):
        """
        Get a user by username.
        
        Args:
            username (str): The username to search for
            
        Returns:
            dict: User information or None if not found
        """
        if not self.connection:
            if not self.connect():
                return None
                
        try:
            self.cursor.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,)
            )
            user = self.cursor.fetchone()
            return dict(user) if user else None
        except sqlite3.Error as e:
            logger.error(f"Error getting user: {e}")
            return None
    
    def update_last_login(self, user_id):
        """
        Update the last login timestamp for a user.
        
        Args:
            user_id (int): The ID of the user
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.connection:
            if not self.connect():
                return False
                
        try:
            current_time = datetime.now().isoformat()
            self.cursor.execute(
                "UPDATE users SET last_login = ? WHERE user_id = ?",
                (current_time, user_id)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating last login: {e}")
            return False
    
    # Password entry operations
    
    def create_password_entry(self, user_id, service_name, username, encrypted_password, 
                             encrypted_notes, salt, nonce, tag):
        """
        Create a new password entry.
        
        Args:
            user_id (int): The ID of the user who owns this entry
            service_name (str): Name of the service (e.g. "Gmail")
            username (str): Username for the service
            encrypted_password (str): Encrypted password data
            encrypted_notes (str): Encrypted notes (optional)
            salt (str): Salt used for encryption
            nonce (str): Nonce used for AES-GCM
            tag (str): Authentication tag from AES-GCM
            
        Returns:
            int: The entry_id of the created entry, or None if error
        """
        if not self.connection:
            if not self.connect():
                return None
                
        try:
            current_time = datetime.now().isoformat()
            self.cursor.execute(
                """INSERT INTO passwords (user_id, service_name, username, encrypted_password, 
                   encrypted_notes, salt, nonce, tag, created_date, modified_date)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, service_name, username, encrypted_password, encrypted_notes, 
                 salt, nonce, tag, current_time, current_time)
            )
            self.connection.commit()
            entry_id = self.cursor.lastrowid
            logger.info(f"Password entry created with ID: {entry_id}")
            return entry_id
        except sqlite3.Error as e:
            logger.error(f"Error creating password entry: {e}")
            return None
    
    def get_password_entries(self, user_id):
        """
        Get all password entries for a user.
        
        Args:
            user_id (int): The ID of the user
            
        Returns:
            list: List of password entries as dictionaries
        """
        if not self.connection:
            if not self.connect():
                return []
                
        try:
            self.cursor.execute(
                "SELECT * FROM passwords WHERE user_id = ? ORDER BY service_name",
                (user_id,)
            )
            entries = self.cursor.fetchall()
            return [dict(entry) for entry in entries]
        except sqlite3.Error as e:
            logger.error(f"Error getting password entries: {e}")
            return []
    
    def get_password_entry(self, entry_id):
        """
        Get a specific password entry.
        
        Args:
            entry_id (int): The ID of the password entry
            
        Returns:
            dict: Password entry as dictionary or None if not found
        """
        if not self.connection:
            if not self.connect():
                return None
                
        try:
            self.cursor.execute(
                "SELECT * FROM passwords WHERE entry_id = ?",
                (entry_id,)
            )
            entry = self.cursor.fetchone()
            return dict(entry) if entry else None
        except sqlite3.Error as e:
            logger.error(f"Error getting password entry: {e}")
            return None
    
    def update_password_entry(self, entry_id, service_name, username, encrypted_password, 
                             encrypted_notes, salt, nonce, tag):
        """
        Update a password entry.
        
        Args:
            entry_id (int): The ID of the password entry to update
            service_name (str): Name of the service
            username (str): Username for the service
            encrypted_password (str): Encrypted password data
            encrypted_notes (str): Encrypted notes (optional)
            salt (str): Salt used for encryption
            nonce (str): Nonce used for AES-GCM
            tag (str): Authentication tag from AES-GCM
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.connection:
            if not self.connect():
                return False
                
        try:
            # First add current password to history
            old_entry = self.get_password_entry(entry_id)
            if old_entry and old_entry["encrypted_password"] != encrypted_password:
                self.add_to_password_history(entry_id, old_entry["encrypted_password"], 
                                           old_entry["salt"], old_entry["nonce"], 
                                           old_entry["tag"])
            
            # Update the entry
            current_time = datetime.now().isoformat()
            self.cursor.execute(
                """UPDATE passwords SET service_name = ?, username = ?, 
                   encrypted_password = ?, encrypted_notes = ?, 
                   salt = ?, nonce = ?, tag = ?, modified_date = ?
                   WHERE entry_id = ?""",
                (service_name, username, encrypted_password, encrypted_notes, 
                 salt, nonce, tag, current_time, entry_id)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error updating password entry: {e}")
            return False
    
    def delete_password_entry(self, entry_id):
        """
        Delete a password entry.
        
        Args:
            entry_id (int): The ID of the password entry to delete
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.connection:
            if not self.connect():
                return False
                
        try:
            # First delete password history
            self.cursor.execute(
                "DELETE FROM password_history WHERE entry_id = ?",
                (entry_id,)
            )
            
            # Then delete the entry
            self.cursor.execute(
                "DELETE FROM passwords WHERE entry_id = ?",
                (entry_id,)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error deleting password entry: {e}")
            return False
    
    def search_password_entries(self, user_id, search_term):
        """
        Search for password entries by service name or username.
        
        Args:
            user_id (int): The ID of the user
            search_term (str): Term to search for
            
        Returns:
            list: List of matching password entries
        """
        if not self.connection:
            if not self.connect():
                return []
                
        try:
            search_pattern = f"%{search_term}%"
            self.cursor.execute(
                """SELECT * FROM passwords 
                   WHERE user_id = ? AND (service_name LIKE ? OR username LIKE ?)
                   ORDER BY service_name""",
                (user_id, search_pattern, search_pattern)
            )
            entries = self.cursor.fetchall()
            return [dict(entry) for entry in entries]
        except sqlite3.Error as e:
            logger.error(f"Error searching password entries: {e}")
            return []
    
    # Password history operations
    
    def add_to_password_history(self, entry_id, encrypted_password, salt, nonce, tag):
        """
        Add a password to the history.
        
        Args:
            entry_id (int): The ID of the password entry
            encrypted_password (str): Encrypted password data
            salt (str): Salt used for encryption
            nonce (str): Nonce used for AES-GCM
            tag (str): Authentication tag from AES-GCM
            
        Returns:
            int: The history_id of the created history entry, or None if error
        """
        if not self.connection:
            if not self.connect():
                return None
                
        try:
            current_time = datetime.now().isoformat()
            self.cursor.execute(
                """INSERT INTO password_history (entry_id, encrypted_password, salt, nonce, tag, modified_date)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (entry_id, encrypted_password, salt, nonce, tag, current_time)
            )
            self.connection.commit()
            history_id = self.cursor.lastrowid
            
            # Limit history size
            from password_manager.config.config import PASSWORD_HISTORY_COUNT
            self.cursor.execute(
                """DELETE FROM password_history 
                   WHERE history_id IN (
                       SELECT history_id FROM password_history
                       WHERE entry_id = ?
                       ORDER BY modified_date DESC
                       LIMIT -1 OFFSET ?
                   )""",
                (entry_id, PASSWORD_HISTORY_COUNT)
            )
            self.connection.commit()
            
            return history_id
        except sqlite3.Error as e:
            logger.error(f"Error adding to password history: {e}")
            return None
    
    def get_password_history(self, entry_id):
        """
        Get the password history for an entry.
        
        Args:
            entry_id (int): The ID of the password entry
            
        Returns:
            list: List of password history entries
        """
        if not self.connection:
            if not self.connect():
                return []
                
        try:
            self.cursor.execute(
                """SELECT * FROM password_history 
                   WHERE entry_id = ? 
                   ORDER BY modified_date DESC""",
                (entry_id,)
            )
            history = self.cursor.fetchall()
            return [dict(entry) for entry in history]
        except sqlite3.Error as e:
            logger.error(f"Error getting password history: {e}")
            return []
    
    # Settings operations
    
    def set_setting(self, user_id, key, value):
        """
        Set a user setting.
        
        Args:
            user_id (int): The ID of the user
            key (str): Setting key
            value (str): Setting value
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.connection:
            if not self.connect():
                return False
                
        try:
            self.cursor.execute(
                """INSERT OR REPLACE INTO settings (user_id, setting_key, setting_value)
                   VALUES (?, ?, ?)""",
                (user_id, key, value)
            )
            self.connection.commit()
            return True
        except sqlite3.Error as e:
            logger.error(f"Error setting user setting: {e}")
            return False
    
    def get_setting(self, user_id, key, default=None):
        """
        Get a user setting.
        
        Args:
            user_id (int): The ID of the user
            key (str): Setting key
            default: Default value if setting not found
            
        Returns:
            str: Setting value or default if not found
        """
        if not self.connection:
            if not self.connect():
                return default
                
        try:
            self.cursor.execute(
                "SELECT setting_value FROM settings WHERE user_id = ? AND setting_key = ?",
                (user_id, key)
            )
            result = self.cursor.fetchone()
            return result["setting_value"] if result else default
        except sqlite3.Error as e:
            logger.error(f"Error getting user setting: {e}")
            return default
    
    def get_all_settings(self, user_id):
        """
        Get all settings for a user.
        
        Args:
            user_id (int): The ID of the user
            
        Returns:
            dict: Dictionary of settings
        """
        if not self.connection:
            if not self.connect():
                return {}
                
        try:
            self.cursor.execute(
                "SELECT setting_key, setting_value FROM settings WHERE user_id = ?",
                (user_id,)
            )
            settings = self.cursor.fetchall()
            return {row["setting_key"]: row["setting_value"] for row in settings}
        except sqlite3.Error as e:
            logger.error(f"Error getting all user settings: {e}")
            return {} 