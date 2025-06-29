"""
Password generator module for the password manager application.
Provides functions for generating secure random passwords and evaluating password strength.
"""

import string
import secrets
import re
import logging
import math
from password_manager.config.config import (
    DEFAULT_PASSWORD_LENGTH, DEFAULT_USE_UPPERCASE,
    DEFAULT_USE_LOWERCASE, DEFAULT_USE_DIGITS, DEFAULT_USE_SYMBOLS
)
import random

logger = logging.getLogger(__name__)

# Character sets for password generation
LOWERCASE_CHARS = string.ascii_lowercase
UPPERCASE_CHARS = string.ascii_uppercase
DIGIT_CHARS = string.digits
SYMBOL_CHARS = "!@#$%^&*()_+-=[]{}|;:,.<>?~"

def generate_password(
    length=16,
    use_uppercase=True,
    use_lowercase=True,
    use_digits=True,
    use_symbols=True
):
    """
    Generate a secure random password.
    
    Args:
        length: Length of password to generate
        use_uppercase: Include uppercase letters
        use_lowercase: Include lowercase letters
        use_digits: Include digits
        use_symbols: Include special symbols
        
    Returns:
        str: Generated password
    """
    # Define character sets
    chars = ""
    
    if use_lowercase:
        chars += string.ascii_lowercase
    if use_uppercase:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_symbols:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/"
        
    # Ensure we have at least some characters
    if not chars:
        chars = string.ascii_letters + string.digits
        
    # Generate password
    password = ""
    for _ in range(length):
        password += random.choice(chars)
        
    # Ensure the password has at least one character from each selected set
    if length >= 4:
        has_lower = any(c in string.ascii_lowercase for c in password) if use_lowercase else True
        has_upper = any(c in string.ascii_uppercase for c in password) if use_uppercase else True
        has_digit = any(c in string.digits for c in password) if use_digits else True
        has_symbol = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/" for c in password) if use_symbols else True
        
        # Regenerate if requirements not met
        if not (has_lower and has_upper and has_digit and has_symbol):
            return generate_password(length, use_uppercase, use_lowercase, use_digits, use_symbols)
            
    return password

def calculate_password_strength(password):
    """
    Calculate password strength score.
    
    Args:
        password: Password to analyze
        
    Returns:
        tuple: (score, feedback) where score is 0.0-1.0 and feedback is a string
    """
    if not password:
        return 0.0, "No password"
        
    score = 0.0
    feedback = ""
    
    # Length score (up to 0.4)
    length = len(password)
    if length >= 16:
        length_score = 0.4
        length_feedback = "Excellent length"
    elif length >= 12:
        length_score = 0.3
        length_feedback = "Good length"
    elif length >= 8:
        length_score = 0.2
        length_feedback = "Acceptable length"
    else:
        length_score = 0.1
        length_feedback = "Too short"
        
    score += length_score
    
    # Character variety score (up to 0.4)
    variety_score = 0.0
    
    if re.search(r'[a-z]', password):
        variety_score += 0.1
    if re.search(r'[A-Z]', password):
        variety_score += 0.1
    if re.search(r'[0-9]', password):
        variety_score += 0.1
    if re.search(r'[^a-zA-Z0-9]', password):
        variety_score += 0.1
        
    score += variety_score
    
    # Complexity score (up to 0.2)
    complexity_score = 0.0
    
    # Check for sequences
    has_sequence = False
    for i in range(len(password) - 2):
        if (ord(password[i+1]) == ord(password[i]) + 1 and 
            ord(password[i+2]) == ord(password[i]) + 2):
            has_sequence = True
            break
            
    # Check for repeated characters
    has_repeats = False
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            has_repeats = True
            break
            
    if not has_sequence and not has_repeats:
        complexity_score += 0.1
        
    # Check for common patterns
    common_patterns = [
        r'password', r'123456', r'qwerty', r'admin', r'welcome',
        r'abc123', r'letmein', r'monkey', r'111111', r'iloveyou'
    ]
    
    has_common_pattern = False
    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            has_common_pattern = True
            break
            
    if not has_common_pattern:
        complexity_score += 0.1
        
    score += complexity_score
    
    # Generate feedback
    if score >= 0.8:
        feedback = "Very strong. Excellent password!"
    elif score >= 0.6:
        feedback = "Strong. Good password."
    elif score >= 0.4:
        feedback = "Medium. Consider improving."
    else:
        feedback = "Weak. Please use a stronger password."
        
    return score, feedback 