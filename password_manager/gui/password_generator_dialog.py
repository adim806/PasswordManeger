"""
Password generator dialog for creating secure random passwords.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import logging

from password_manager.utils.password_generator import generate_password, calculate_password_strength
from password_manager.utils.clipboard import copy_to_clipboard
from password_manager.config.config import (
    DEFAULT_PASSWORD_LENGTH, DEFAULT_USE_UPPERCASE,
    DEFAULT_USE_LOWERCASE, DEFAULT_USE_DIGITS, DEFAULT_USE_SYMBOLS
)

logger = logging.getLogger(__name__)

class PasswordGeneratorDialog:
    """Dialog for generating secure random passwords."""
    
    def __init__(self, parent):
        """
        Initialize the password generator dialog.
        
        Args:
            parent: The parent window
        """
        self.parent = parent
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Password Generator")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.resizable(False, False)
        
        # Center the dialog on parent
        self.dialog.geometry("+%d+%d" % (
            parent.winfo_rootx() + 50,
            parent.winfo_rooty() + 50
        ))
        
        # Create form
        self._create_widgets()
        
        # Generate initial password
        self._generate_password()
        
    def _create_widgets(self):
        """Create the UI widgets."""
        # Main frame with padding
        main_frame = ttk.Frame(self.dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Generated password
        ttk.Label(main_frame, text="Generated Password:").grid(
            row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 5)
        )
        
        password_frame = ttk.Frame(main_frame)
        password_frame.grid(row=1, column=0, columnspan=3, sticky=tk.EW, pady=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(
            password_frame, 
            textvariable=self.password_var,
            width=30,
            font=("Courier", 12)
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        # Show/hide password
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_check = ttk.Checkbutton(
            password_frame,
            text="Show",
            variable=self.show_password_var,
            command=self._toggle_password_visibility
        )
        self.show_password_check.pack(side=tk.LEFT, padx=5)
        
        # Password strength meter
        ttk.Label(main_frame, text="Strength:").grid(row=2, column=0, sticky=tk.W, pady=5)
        
        strength_frame = ttk.Frame(main_frame)
        strength_frame.grid(row=2, column=1, columnspan=2, sticky=tk.EW, pady=5)
        
        self.strength_meter = ttk.Progressbar(
            strength_frame, 
            orient=tk.HORIZONTAL, 
            length=200, 
            mode='determinate'
        )
        self.strength_meter.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.strength_label = ttk.Label(strength_frame, text="", width=15)
        self.strength_label.pack(side=tk.LEFT, padx=5)
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Password Options", padding=10)
        options_frame.grid(row=3, column=0, columnspan=3, sticky=tk.NSEW, pady=10)
        
        # Password length
        ttk.Label(options_frame, text="Length:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        length_frame = ttk.Frame(options_frame)
        length_frame.grid(row=0, column=1, sticky=tk.EW, pady=5)
        
        self.length_var = tk.IntVar(value=DEFAULT_PASSWORD_LENGTH)
        self.length_scale = ttk.Scale(
            length_frame,
            from_=8,
            to=64,
            orient=tk.HORIZONTAL,
            variable=self.length_var,
            command=self._on_length_change
        )
        self.length_scale.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.length_label = ttk.Label(length_frame, text=str(self.length_var.get()), width=3)
        self.length_label.pack(side=tk.LEFT, padx=5)
        
        # Character types
        ttk.Label(options_frame, text="Character Types:").grid(
            row=1, column=0, columnspan=2, sticky=tk.W, pady=(10, 5)
        )
        
        # Uppercase
        self.uppercase_var = tk.BooleanVar(value=DEFAULT_USE_UPPERCASE)
        ttk.Checkbutton(
            options_frame, 
            text="Uppercase Letters (A-Z)", 
            variable=self.uppercase_var
        ).grid(row=2, column=0, columnspan=2, sticky=tk.W)
        
        # Lowercase
        self.lowercase_var = tk.BooleanVar(value=DEFAULT_USE_LOWERCASE)
        ttk.Checkbutton(
            options_frame, 
            text="Lowercase Letters (a-z)", 
            variable=self.lowercase_var
        ).grid(row=3, column=0, columnspan=2, sticky=tk.W)
        
        # Digits
        self.digits_var = tk.BooleanVar(value=DEFAULT_USE_DIGITS)
        ttk.Checkbutton(
            options_frame, 
            text="Numbers (0-9)", 
            variable=self.digits_var
        ).grid(row=4, column=0, columnspan=2, sticky=tk.W)
        
        # Symbols
        self.symbols_var = tk.BooleanVar(value=DEFAULT_USE_SYMBOLS)
        ttk.Checkbutton(
            options_frame, 
            text="Special Characters (!@#$...)", 
            variable=self.symbols_var
        ).grid(row=5, column=0, columnspan=2, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=4, column=0, columnspan=3, pady=10)
        
        generate_button = ttk.Button(button_frame, text="Generate New", command=self._generate_password)
        generate_button.pack(side=tk.LEFT, padx=5)
        
        copy_button = ttk.Button(button_frame, text="Copy to Clipboard", command=self._copy_to_clipboard)
        copy_button.pack(side=tk.LEFT, padx=5)
        
        close_button = ttk.Button(button_frame, text="Close", command=self.dialog.destroy)
        close_button.pack(side=tk.LEFT, padx=5)
        
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
            
    def _on_length_change(self, event):
        """Handle password length change."""
        value = int(float(self.length_scale.get()))
        self.length_label.config(text=str(value))
        
    def _generate_password(self):
        """Generate a new password with the current settings."""
        try:
            # Get options
            length = self.length_var.get()
            use_uppercase = self.uppercase_var.get()
            use_lowercase = self.lowercase_var.get()
            use_digits = self.digits_var.get()
            use_symbols = self.symbols_var.get()
            
            # Ensure at least one character type is selected
            if not any([use_uppercase, use_lowercase, use_digits, use_symbols]):
                messagebox.showwarning(
                    "Invalid Options",
                    "Please select at least one character type."
                )
                self.lowercase_var.set(True)
                use_lowercase = True
            
            # Generate password
            password = generate_password(
                length=length,
                use_uppercase=use_uppercase,
                use_lowercase=use_lowercase,
                use_digits=use_digits,
                use_symbols=use_symbols
            )
            
            # Update the password field
            self.password_var.set(password)
            
            # Update strength meter
            self._update_strength_meter(password)
        except Exception as e:
            logger.error(f"Error generating password: {e}")
            messagebox.showerror("Error", f"Failed to generate password: {str(e)}")
            
    def _update_strength_meter(self, password):
        """Update the password strength meter."""
        score, feedback = calculate_password_strength(password)
        
        # Update progress bar
        strength_percent = int(score * 100)
        self.strength_meter.config(value=strength_percent)
        
        # Update label
        self.strength_label.config(text=feedback.split(".")[0])  # Just the strength level
        
        # Color the meter based on strength
        if score < 0.3:
            self.strength_meter.config(style="red.Horizontal.TProgressbar")
        elif score < 0.6:
            self.strength_meter.config(style="yellow.Horizontal.TProgressbar")
        else:
            self.strength_meter.config(style="green.Horizontal.TProgressbar")
            
    def _copy_to_clipboard(self):
        """Copy the generated password to the clipboard."""
        password = self.password_var.get()
        if password:
            if copy_to_clipboard(password):
                messagebox.showinfo(
                    "Password Copied",
                    "Password has been copied to the clipboard.\n"
                    "It will be automatically cleared after 20 seconds."
                ) 