"""
Clipboard utilities for copying and pasting text.
"""

import tkinter as tk
import logging
import platform

logger = logging.getLogger(__name__)

def copy_to_clipboard(text):
    """
    Copy text to the system clipboard.
    
    Args:
        text (str): Text to copy to clipboard
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Create a temporary Tkinter window to access clipboard
        root = tk.Tk()
        root.withdraw()  # Hide the window
        
        # Clear clipboard
        root.clipboard_clear()
        
        # Set clipboard content
        root.clipboard_append(text)
        
        # Update clipboard
        root.update()
        
        # Destroy the temporary window
        root.destroy()
        
        logger.debug("Text copied to clipboard successfully")
        return True
        
    except Exception as e:
        logger.error(f"Error copying to clipboard: {e}")
        return False
        
def get_from_clipboard():
    """
    Get text from the system clipboard.
    
    Returns:
        str: Text from clipboard or empty string if failed
    """
    try:
        # Create a temporary Tkinter window to access clipboard
        root = tk.Tk()
        root.withdraw()  # Hide the window
        
        # Get clipboard content
        clipboard_text = root.clipboard_get()
        
        # Destroy the temporary window
        root.destroy()
        
        return clipboard_text
        
    except Exception as e:
        logger.error(f"Error getting text from clipboard: {e}")
        return "" 