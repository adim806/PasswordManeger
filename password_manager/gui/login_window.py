"""
Login window for the password manager application.
Handles user authentication and registration.
"""

import tkinter as tk
from tkinter import ttk, messagebox, font
import logging

from password_manager.config.config import MIN_MASTER_PASSWORD_LENGTH

logger = logging.getLogger(__name__)

class LoginWindow(ttk.Frame):
    """Login window frame for user authentication."""
    
    def __init__(self, parent, auth_manager, on_login_success):
        """
        Initialize the login window.
        
        Args:
            parent: The parent tkinter container
            auth_manager: AuthManager instance for authentication
            on_login_success: Callback function to call on successful login
        """
        super().__init__(parent)
        self.parent = parent
        self.auth_manager = auth_manager
        self.on_login_success = on_login_success
        
        # Set up the UI
        self._create_widgets()
        self._setup_layout()
        self._setup_bindings()
        
    def _create_widgets(self):
        """Create the UI widgets."""
        # Title label
        self.title_label = ttk.Label(
            self, 
            text="Secure Password Manager", 
            font=("Helvetica", 16, "bold")
        )
        
        # Username field
        self.username_label = ttk.Label(self, text="Username:")
        self.username_entry = ttk.Entry(self, width=30)
        
        # Password field
        self.password_label = ttk.Label(self, text="Master Password:")
        self.password_entry = ttk.Entry(self, width=30, show="•")
        
        # Login button - create directly in the parent frame
        self.login_button = ttk.Button(
            self,
            text="Login",
            command=self._handle_login,
            width=15
        )
        
        # Register button - create directly in the parent frame
        self.register_button = ttk.Button(
            self,
            text="Register New Account",
            command=self._show_register_dialog,
            width=20
        )
        
        # Mode selection
        self.mode_var = tk.StringVar(value="login")
        
        # Forget password link
        self.forgot_label = ttk.Label(
            self, 
            text="Forgot your password?",
            foreground="blue", 
            cursor="hand2"
        )
        self.forgot_label.bind("<Button-1>", self._handle_forgot_password)

    def _setup_layout(self):
        """Set up the widget layout."""
        # Configure grid weights
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=2)
        self.rowconfigure(6, weight=1)  # Push everything up
        
        # Position widgets with proper padding
        self.title_label.grid(row=0, column=0, columnspan=2, pady=(20, 30), sticky="n")
        
        # Username row
        self.username_label.grid(row=1, column=0, sticky="e", padx=(20, 10), pady=5)
        self.username_entry.grid(row=1, column=1, sticky="w", padx=(0, 20), pady=5)
        
        # Password row
        self.password_label.grid(row=2, column=0, sticky="e", padx=(20, 10), pady=5)
        self.password_entry.grid(row=2, column=1, sticky="w", padx=(0, 20), pady=5)
        
        # Buttons - place directly in the grid
        self.login_button.grid(row=3, column=0, columnspan=1, pady=20, padx=10, sticky="e")
        self.register_button.grid(row=3, column=1, columnspan=1, pady=20, padx=10, sticky="w")
        
        # Note label
        note_label = ttk.Label(
            self, 
            text="Note: All data is stored locally and encrypted.",
            font=("Helvetica", 9, "italic")
        )
        note_label.grid(row=4, column=0, columnspan=2, pady=5)
        
        # Forgot password link
        self.forgot_label.grid(row=5, column=0, columnspan=2, pady=5)
        
    def _setup_bindings(self):
        """Set up event bindings."""
        # Enter key to login
        self.username_entry.bind("<Return>", lambda event: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda event: self._handle_login())
        
        # Set initial focus
        self.username_entry.focus_set()
        
    def _handle_login(self):
        """Handle the login button click."""
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        if not username or not password:
            messagebox.showwarning(
                "Login Failed",
                "Please enter both username and master password."
            )
            return
        
        # Show loading indicator
        self.parent.config(cursor="wait")
        self.update()
        
        try:
            # Attempt login
            success, message = self.auth_manager.login(username, password)
            
            if success:
                # Clear the password from the entry field
                self.password_entry.delete(0, tk.END)
                
                # Invoke the success callback
                if self.on_login_success:
                    self.on_login_success()
            else:
                messagebox.showerror("Login Failed", message)
        finally:
            # Reset cursor
            self.parent.config(cursor="")
        
    def _show_register_dialog(self):
        """Show the registration dialog."""
        # Create a modal dialog
        register_dialog = tk.Toplevel(self)
        register_dialog.title("Register New User")
        register_dialog.transient(self.parent)
        register_dialog.grab_set()
        register_dialog.resizable(False, False)
        
        # Center the dialog on parent
        register_dialog.geometry("+%d+%d" % (
            self.parent.winfo_rootx() + 50,
            self.parent.winfo_rooty() + 50
        ))
        
        # Configure dialog grid
        register_dialog.columnconfigure(0, weight=1)
        register_dialog.columnconfigure(1, weight=2)
        
        # Create registration form
        ttk.Label(register_dialog, text="Create a New Account", font=("Helvetica", 12, "bold")).grid(
            row=0, column=0, columnspan=2, pady=10, padx=20
        )
        
        ttk.Label(register_dialog, text="Username:").grid(row=1, column=0, sticky="e", padx=10, pady=5)
        username_entry = ttk.Entry(register_dialog, width=30)
        username_entry.grid(row=1, column=1, sticky="w", padx=10, pady=5)
        
        ttk.Label(register_dialog, text="Master Password:").grid(row=2, column=0, sticky="e", padx=10, pady=5)
        password_entry = ttk.Entry(register_dialog, width=30, show="•")
        password_entry.grid(row=2, column=1, sticky="w", padx=10, pady=5)
        
        ttk.Label(register_dialog, text="Confirm Password:").grid(row=3, column=0, sticky="e", padx=10, pady=5)
        confirm_entry = ttk.Entry(register_dialog, width=30, show="•")
        confirm_entry.grid(row=3, column=1, sticky="w", padx=10, pady=5)
        
        ttk.Label(
            register_dialog, 
            text=f"Note: Master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters long.",
            font=("Helvetica", 9, "italic")
        ).grid(row=4, column=0, columnspan=2, pady=10, padx=20)
        
        ttk.Label(
            register_dialog, 
            text="Warning: If you forget your master password, your data cannot be recovered!",
            foreground="red",
            font=("Helvetica", 9, "italic")
        ).grid(row=5, column=0, columnspan=2, pady=10, padx=20)
        
        # Create buttons
        button_frame = ttk.Frame(register_dialog)
        button_frame.grid(row=6, column=0, columnspan=2, pady=10)
        
        def handle_register():
            """Handle the register button click."""
            username = username_entry.get().strip()
            password = password_entry.get()
            confirm = confirm_entry.get()
            
            if not username:
                messagebox.showwarning("Registration Error", "Please enter a username.")
                return
                
            if not password:
                messagebox.showwarning("Registration Error", "Please enter a master password.")
                return
                
            if password != confirm:
                messagebox.showwarning("Registration Error", "Passwords do not match.")
                return
                
            if len(password) < MIN_MASTER_PASSWORD_LENGTH:
                messagebox.showwarning(
                    "Registration Error", 
                    f"Master password must be at least {MIN_MASTER_PASSWORD_LENGTH} characters long."
                )
                return
                
            # Show loading indicator
            register_dialog.config(cursor="wait")
            register_dialog.update()
            
            try:
                # Attempt registration
                success, message = self.auth_manager.register_user(username, password)
                
                if success:
                    messagebox.showinfo("Registration Successful", message)
                    
                    # Pre-fill the login form
                    self.username_entry.delete(0, tk.END)
                    self.username_entry.insert(0, username)
                    self.password_entry.delete(0, tk.END)
                    self.password_entry.focus_set()
                    
                    # Close the dialog
                    register_dialog.destroy()
                else:
                    messagebox.showerror("Registration Failed", message)
            except Exception as e:
                messagebox.showerror("Registration Error", str(e))
            finally:
                # Reset cursor only if dialog still exists
                try:
                    if register_dialog.winfo_exists():
                        register_dialog.config(cursor="")
                except:
                    pass
        
        register_btn = ttk.Button(button_frame, text="Register", command=handle_register, width=10)
        register_btn.grid(row=0, column=0, padx=10)
        
        cancel_btn = ttk.Button(button_frame, text="Cancel", command=register_dialog.destroy, width=10)
        cancel_btn.grid(row=0, column=1, padx=10)
        
        # Set initial focus
        username_entry.focus_set()
        
        # Set up key bindings
        username_entry.bind("<Return>", lambda event: password_entry.focus())
        password_entry.bind("<Return>", lambda event: confirm_entry.focus())
        confirm_entry.bind("<Return>", lambda event: handle_register())
    
    def _handle_forgot_password(self, event):
        """Handle the forgot password link click."""
        messagebox.showinfo(
            "Master Password Recovery",
            "For security reasons, master passwords cannot be recovered.\n\n"
            "If you've forgotten your master password, you'll need to create "
            "a new account and manually recreate your password entries."
        ) 