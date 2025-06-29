"""
Configuration settings for the password manager application.
"""

# Database configuration
DATABASE_PATH = "password_vault.db"

# Encryption settings
AES_MODE = "GCM"  # GCM mode provides authentication
KEY_LENGTH = 32  # 256 bits
SALT_LENGTH = 16  # 128 bits
NONCE_LENGTH = 12  # 96 bits for GCM mode
TAG_LENGTH = 16  # 128 bits for GCM mode

# Key derivation settings
PBKDF2_ITERATIONS = 600000  # High iteration count for security
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4

# Authentication settings
BCRYPT_ROUNDS = 12  # Higher rounds = more secure but slower

# Application settings
AUTO_LOCK_MINUTES = 5  # Auto-lock after inactivity
CLIPBOARD_CLEAR_SECONDS = 20  # Clear clipboard after copying
MIN_MASTER_PASSWORD_LENGTH = 8
PASSWORD_HISTORY_COUNT = 5  # Number of password history entries to keep

# Password generation defaults
DEFAULT_PASSWORD_LENGTH = 16
DEFAULT_USE_UPPERCASE = True
DEFAULT_USE_LOWERCASE = True
DEFAULT_USE_DIGITS = True
DEFAULT_USE_SYMBOLS = True

# Logging configuration
LOG_LEVEL = "INFO"
LOG_FILE = "password_manager.log" 