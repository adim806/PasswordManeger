"""
Authentication manager for the password manager application.
Handles user login, registration, and session management.
"""

import bcrypt
import logging
import time
import sqlite3
from typing import Tuple, Optional

from password_manager.database.db_manager import DatabaseManager
from password_manager.config.config import MIN_MASTER_PASSWORD_LENGTH

logger = logging.getLogger(__name__)

class AuthManager:
    """Manages user authentication and session state."""
    
    def __init__(self):
        """Initialize the authentication manager."""
        self.db_manager = DatabaseManager()
        self._ensure_database_initialized()
        self.current_user_id = None
        self.current_username = None
        self.login_time = None
        
    def _ensure_database_initialized(self):
        """Ensure the database is initialized with required tables."""
        # Initialize the database schema
        self.db_manager.initialize_database()
        
        # Connect directly to create the users table
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        
        # Drop all tables to ensure correct schema
        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS passwords")
        
        # Create users table with the correct schema
        cursor.execute("""
            CREATE TABLE users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        """)
        
        conn.commit()
        conn.close()
        
        logger.info("Database schema initialized successfully")
        
    def has_users(self) -> bool:
        """
        Check if any users exist in the database.
        
        Returns:
            bool: True if at least one user exists, False otherwise
        """
        conn = sqlite3.connect(self.db_manager.db_path)
        cursor = conn.cursor()
        
        result = cursor.execute("SELECT COUNT(*) FROM users").fetchone()
        
        conn.close()
        
        # The first element of the result tuple is the count
        return result[0] > 0
        
    def register_user(self, username: str, master_password: str) -> Tuple[bool, str]:
        """
        Register a new user.
        
        Args:
            username: The username for the new account
            master_password: The master password for the new account
            
        Returns:
            tuple: (success, message)
        """
        # Validate inputs
        if not username or not master_password:
            return False, "Username and password are required."
            
        if len(master_password) < MIN_MASTER_PASSWORD_LENGTH:
            return False, f"Master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters."
            
        try:
            # Hash the password
            password_hash = bcrypt.hashpw(
                master_password.encode('utf-8'), 
                bcrypt.gensalt()
            ).decode('utf-8')
            
            # Connect to the database
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            
            # Check if username already exists
            existing_user = cursor.execute(
                "SELECT user_id FROM users WHERE username = ?", 
                (username,)
            ).fetchone()
            
            if existing_user:
                conn.close()
                return False, "Username already exists."
                
            # Insert the new user
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
            conn.close()
            
            logger.info(f"User '{username}' registered successfully")
            return True, "Registration successful! You can now log in."
            
        except Exception as e:
            logger.error(f"Error registering user: {e}")
            return False, f"Registration failed: {str(e)}"
            
    def login(self, username: str, master_password: str) -> Tuple[bool, str]:
        """
        Authenticate a user.
        
        Args:
            username: The username to authenticate
            master_password: The master password to verify
            
        Returns:
            tuple: (success, message)
        """
        try:
            # Connect to the database
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            
            # Get the user record
            user = cursor.execute(
                "SELECT user_id, password_hash FROM users WHERE username = ?", 
                (username,)
            ).fetchone()
            
            if not user:
                conn.close()
                return False, "Invalid username or password."
                
            user_id, password_hash = user
            
            # Verify the password
            if not bcrypt.checkpw(
                master_password.encode('utf-8'), 
                password_hash.encode('utf-8')
            ):
                conn.close()
                return False, "Invalid username or password."
                
            # Update last login time
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?",
                (user_id,)
            )
            conn.commit()
            
            # Set session state
            self.current_user_id = user_id
            self.current_username = username
            self.login_time = time.time()
            
            logger.info(f"User '{username}' logged in successfully")
            conn.close()
            return True, "Login successful!"
            
        except Exception as e:
            logger.error(f"Error during login: {e}")
            return False, f"Login failed: {str(e)}"
            
    def logout(self) -> None:
        """Log out the current user."""
        if self.current_user_id:
            logger.info(f"User '{self.current_username}' logged out")
            self.current_user_id = None
            self.current_username = None
            self.login_time = None
            
    def is_authenticated(self) -> bool:
        """Check if a user is currently authenticated."""
        return self.current_user_id is not None
        
    def get_current_user_id(self) -> Optional[int]:
        """Get the current user ID."""
        return self.current_user_id
        
    def get_current_username(self) -> Optional[str]:
        """Get the current username."""
        return self.current_username
        
    def get_session_duration(self) -> Optional[float]:
        """Get the current session duration in seconds."""
        if self.login_time:
            return time.time() - self.login_time
        return None 