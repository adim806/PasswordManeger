"""
Password dialog for adding or editing password entries.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import logging
import random
import string

from password_manager.utils.password_generator import generate_password, calculate_password_strength

logger = logging.getLogger(__name__)

class PasswordDialog:
    """Dialog for adding or editing password entries."""
    
    def __init__(
        self, 
        parent, 
        title="Add Password", 
        on_save=None, 
        entry_id=None, 
        service_name="", 
        username="", 
        password="", 
        notes=""
    ):
        """
        Initialize the password dialog.
        
        Args:
            parent: The parent window
            title: Dialog title
            on_save: Callback function when saving
            entry_id: ID of entry to edit (None for new entries)
            service_name: Initial service name
            username: Initial username
            password: Initial password
            notes: Initial notes
        """
        self.parent = parent
        self.on_save = on_save
        self.entry_id = entry_id
        
        # Create dialog window
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.resizable(False, False)
        
        # Center the dialog on parent
        self.dialog.geometry("+%d+%d" % (
            parent.winfo_rootx() + 50,
            parent.winfo_rooty() + 50
        ))
        
        # Configure grid
        self.dialog.columnconfigure(0, weight=0)
        self.dialog.columnconfigure(1, weight=1)
        
        # Create form fields
        ttk.Label(self.dialog, text="Service Name:").grid(row=0, column=0, sticky="e", padx=10, pady=5)
        self.service_entry = ttk.Entry(self.dialog, width=40)
        self.service_entry.grid(row=0, column=1, columnspan=2, sticky="we", padx=10, pady=5)
        self.service_entry.insert(0, service_name)
        
        ttk.Label(self.dialog, text="Username:").grid(row=1, column=0, sticky="e", padx=10, pady=5)
        self.username_entry = ttk.Entry(self.dialog, width=40)
        self.username_entry.grid(row=1, column=1, columnspan=2, sticky="we", padx=10, pady=5)
        self.username_entry.insert(0, username)
        
        ttk.Label(self.dialog, text="Password:").grid(row=2, column=0, sticky="e", padx=10, pady=5)
        
        # Password field with show/generate buttons
        password_frame = ttk.Frame(self.dialog)
        password_frame.grid(row=2, column=1, sticky="we", padx=10, pady=5)
        
        self.password_entry = ttk.Entry(password_frame, width=30, show="•")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.password_entry.insert(0, password)
        
        # Show password checkbox
        self.show_var = tk.BooleanVar(value=False)
        self.show_check = ttk.Checkbutton(
            password_frame, 
            text="Show", 
            variable=self.show_var,
            command=self._toggle_password_visibility
        )
        self.show_check.pack(side=tk.LEFT, padx=5)
        
        # Generate password button
        generate_button = ttk.Button(
            self.dialog, 
            text="Generate", 
            command=self._generate_password,
            width=10
        )
        generate_button.grid(row=2, column=2, padx=10, pady=5)
        
        # Password strength meter
        ttk.Label(self.dialog, text="Strength:").grid(row=3, column=0, sticky="e", padx=10, pady=5)
        
        strength_frame = ttk.Frame(self.dialog)
        strength_frame.grid(row=3, column=1, columnspan=2, sticky="we", padx=10, pady=5)
        
        self.strength_meter = ttk.Progressbar(
            strength_frame, 
            orient=tk.HORIZONTAL, 
            length=200, 
            mode='determinate'
        )
        self.strength_meter.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.strength_label = ttk.Label(strength_frame, text="", width=10)
        self.strength_label.pack(side=tk.LEFT, padx=5)
        
        # Notes field
        ttk.Label(self.dialog, text="Notes:").grid(row=4, column=0, sticky="ne", padx=10, pady=5)
        
        notes_frame = ttk.Frame(self.dialog)
        notes_frame.grid(row=4, column=1, columnspan=2, sticky="we", padx=10, pady=5)
        
        self.notes_text = tk.Text(notes_frame, height=5, width=40, wrap=tk.WORD)
        notes_scrollbar = ttk.Scrollbar(notes_frame, orient=tk.VERTICAL, command=self.notes_text.yview)
        self.notes_text.configure(yscrollcommand=notes_scrollbar.set)
        
        self.notes_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        notes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        if notes:
            self.notes_text.insert("1.0", notes)
        
        # Buttons
        button_frame = ttk.Frame(self.dialog)
        button_frame.grid(row=5, column=0, columnspan=3, pady=15)
        
        save_button = ttk.Button(button_frame, text="Save", command=self._save, width=10)
        save_button.grid(row=0, column=0, padx=10)
        
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.dialog.destroy, width=10)
        cancel_button.grid(row=0, column=1, padx=10)
        
        # Set up bindings
        self.password_entry.bind("<KeyRelease>", self._update_strength_meter)
        
        # Initial strength meter update
        self._update_strength_meter()
        
        # Set initial focus
        self.service_entry.focus_set()
        
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
            
    def _generate_password(self):
        """Generate a secure password."""
        # Generate a secure password
        password = generate_password(
            length=16,
            use_uppercase=True,
            use_lowercase=True,
            use_digits=True,
            use_symbols=True
        )
        
        # Set the password in the entry field
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        
        # Update the strength meter
        self._update_strength_meter()
        
    def _update_strength_meter(self, event=None):
        """Update the password strength meter."""
        password = self.password_entry.get()
        
        if not password:
            self.strength_meter.config(value=0)
            self.strength_label.config(text="")
            return
            
        score, feedback = calculate_password_strength(password)
        
        # Update progress bar
        strength_percent = int(score * 100)
        self.strength_meter.config(value=strength_percent)
        
        # Update label
        self.strength_label.config(text=feedback.split(".")[0])
        
        # Color the meter based on strength
        if score < 0.3:
            self.strength_meter.config(style="red.Horizontal.TProgressbar")
        elif score < 0.6:
            self.strength_meter.config(style="yellow.Horizontal.TProgressbar")
        else:
            self.strength_meter.config(style="green.Horizontal.TProgressbar")
            
    def _save(self):
        """Save the password entry."""
        # Get values
        service_name = self.service_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        notes = self.notes_text.get("1.0", tk.END).strip()
        
        # Validate
        if not service_name:
            messagebox.showwarning("Validation Error", "Please enter a service name.")
            self.service_entry.focus_set()
            return
            
        if not password:
            messagebox.showwarning("Validation Error", "Please enter a password.")
            self.password_entry.focus_set()
            return
            
        # Call the save callback
        if self.on_save:
            if self.entry_id:
                # Editing existing entry
                self.on_save(service_name, username, password, notes, self.entry_id)
            else:
                # Adding new entry
                self.on_save(service_name, username, password, notes)
                
        # Close the dialog
        self.dialog.destroy() 