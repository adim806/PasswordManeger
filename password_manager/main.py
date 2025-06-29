#!/usr/bin/env python3
"""
Secure Password Manager - Main entry point.
A secure, offline password manager desktop application.

This application allows users to securely store and manage passwords
using strong encryption (AES-256) and bcrypt authentication.
"""

import os
import sys
import logging
import argparse
from logging.handlers import RotatingFileHandler

# Add the parent directory to sys.path to allow absolute imports
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))

from password_manager.gui.app import PasswordManagerApp
from password_manager.config.config import LOG_LEVEL, LOG_FILE

# Set up logging
def setup_logging():
    """Configure the application logging."""
    log_level = getattr(logging, LOG_LEVEL.upper(), logging.INFO)
    
    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    log_file = os.path.join(logs_dir, LOG_FILE)
    
    # Set up root logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Console handler for DEBUG level
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_format = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)
    
    # File handler for INFO level and above
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(logging.INFO)
    file_format = logging.Formatter('%(asctime)s - %(levelname)s - %(name)s - %(message)s')
    file_handler.setFormatter(file_format)
    logger.addHandler(file_handler)
    
    return logger

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Secure Password Manager - A secure, offline password manager'
    )
    
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    return parser.parse_args()

def main():
    """Main entry point for the application."""
    # Parse arguments
    args = parse_arguments()
    
    # Set up logging
    if args.debug:
        os.environ['LOG_LEVEL'] = 'DEBUG'
        
    logger = setup_logging()
    logger.info("Starting Secure Password Manager")
    
    try:
        # Start the application
        app = PasswordManagerApp()
        app.run()
    except Exception as e:
        logger.critical(f"Unhandled exception: {e}", exc_info=True)
        return 1
    
    logger.info("Secure Password Manager closed normally")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 