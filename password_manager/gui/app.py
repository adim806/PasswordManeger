"""
Main application class for the Password Manager.
Handles the application lifecycle and window management.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import logging
import os

from password_manager.gui.login_window import LoginWindow
from password_manager.gui.main_window import MainWindow
from password_manager.auth.auth_manager import AuthManager
from password_manager.database.db_manager import DatabaseManager

logger = logging.getLogger(__name__)

class PasswordManagerApp:
    """Main application class for the Password Manager."""
    
    def __init__(self, master=None):
        """
        Initialize the application.
        
        Args:
            master: The root Tkinter window
        """
        # Set up the main window if not provided
        if master is None:
            self.master = tk.Tk()
            self.owns_master = True
        else:
            self.master = master
            self.owns_master = False
            
        # Set window title and size
        self.master.title("Secure Password Manager")
        self.master.geometry("500x350")
        self.master.minsize(500, 350)
        
        # Center the window on screen
        self._center_window()
        
        # Set application icon
        try:
            # TODO: Add application icon
            pass
        except Exception as e:
            logger.warning(f"Failed to set application icon: {e}")
        
        # Set up styles
        self._setup_styles()
        
        # Initialize database
        self._initialize_database()
        
        # Create authentication manager
        self.auth_manager = AuthManager()
        
        # Current active frame
        self.current_frame = None
        
        # Start with login window
        self.show_login_window()
        
    def _center_window(self):
        """Center the window on the screen."""
        # Get screen width and height
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        
        # Calculate position
        width = 500
        height = 350
        x = (screen_width - width) // 2
        y = (screen_height - height) // 2
        
        # Set the position
        self.master.geometry(f"{width}x{height}+{x}+{y}")
        
    def _initialize_database(self):
        """Initialize the database if it doesn't exist."""
        db_manager = DatabaseManager()
        db_manager.initialize_database()
        db_manager.close()
        
    def _setup_styles(self):
        """Set up the application styles."""
        # Create a style object
        style = ttk.Style()
        
        # Configure general styles
        style.configure("TButton", padding=6, relief="flat", font=("Helvetica", 10))
        style.configure("TLabel", padding=2, font=("Helvetica", 10))
        style.configure("TEntry", padding=2, font=("Helvetica", 10))
        
        # Configure accent button style
        style.configure("Accent.TButton", 
                       background="#007bff",
                       foreground="white",
                       padding=6,
                       relief="flat")
        style.map("Accent.TButton",
                 background=[('active', '#0069d9'), ('disabled', '#6c757d')])
        
        # Configure progress bar styles for password strength
        style.configure("red.Horizontal.TProgressbar", foreground="red", background="red")
        style.configure("yellow.Horizontal.TProgressbar", foreground="orange", background="orange")
        style.configure("green.Horizontal.TProgressbar", foreground="green", background="green")
        
    def show_login_window(self):
        """Show the login window."""
        # Clear any existing frame
        if self.current_frame:
            self.current_frame.destroy()
        
        # Adjust window size for login
        self.master.geometry("500x350")
        
        # Create the login window
        self.current_frame = LoginWindow(
            self.master,
            self.auth_manager,
            on_login_success=self.show_main_window
        )
        self.current_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Check if this is first run (no users exist)
        is_first_run = not self.auth_manager.has_users()
        if is_first_run:
            # Show welcome message and prompt to register
            self.master.after(500, self._show_first_run_message)
        
    def _show_first_run_message(self):
        """Show welcome message for first-time users."""
        messagebox.showinfo(
            "Welcome to Secure Password Manager",
            "Welcome to Secure Password Manager!\n\n"
            "This appears to be your first time using the application. "
            "Please register a new account to get started.\n\n"
            "Click the 'Register New Account' button to create your account."
        )
        
    def show_main_window(self):
        """Show the main application window."""
        # Clear any existing frame
        if self.current_frame:
            self.current_frame.destroy()
        
        # Restore window size
        self.master.geometry("900x600")
        
        # Center the window
        screen_width = self.master.winfo_screenwidth()
        screen_height = self.master.winfo_screenheight()
        x = (screen_width - 900) // 2
        y = (screen_height - 600) // 2
        self.master.geometry(f"900x600+{x}+{y}")
            
        # Reset the window title
        username = self.auth_manager.get_current_username()
        self.master.title(f"Secure Password Manager - {username}" if username else "Secure Password Manager")
            
        # Create the main window
        self.current_frame = MainWindow(
            self.master,
            self.auth_manager,
            on_logout=self.handle_logout
        )
        self.current_frame.pack(fill=tk.BOTH, expand=True)
        
    def handle_logout(self, lock=False):
        """
        Handle user logout or application lock.
        
        Args:
            lock (bool): If True, just lock the session; otherwise full logout
        """
        # If just locking, we'll keep the authentication
        if not lock:
            self.auth_manager.logout()
            
        # Show login window
        self.show_login_window()
        
    def run(self):
        """Run the application main loop."""
        self.master.mainloop()
        
    def exit(self):
        """Exit the application."""
        # Clean up resources
        if self.auth_manager:
            self.auth_manager.logout()
            
        # Exit the application
        if self.owns_master:
            self.master.quit()
            self.master.destroy() 