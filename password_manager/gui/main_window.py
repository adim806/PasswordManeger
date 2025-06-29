"""
Main window for the password manager application.
Shows the list of password entries and provides functionality for managing them.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import logging
import threading
import time
import sqlite3
from datetime import datetime

from password_manager.utils.clipboard import copy_to_clipboard
from password_manager.database.db_manager import DatabaseManager
from password_manager.utils.password_generator import calculate_password_strength
from password_manager.gui.password_dialog import PasswordDialog

logger = logging.getLogger(__name__)

class MainWindow(ttk.Frame):
    """Main window frame for the password manager."""
    
    def __init__(self, parent, auth_manager, on_logout):
        """
        Initialize the main window.
        
        Args:
            parent: The parent tkinter container
            auth_manager: AuthManager instance for authentication
            on_logout: Callback function to call on logout
        """
        super().__init__(parent)
        self.parent = parent
        self.auth_manager = auth_manager
        self.on_logout = on_logout
        self.db_manager = DatabaseManager()
        
        # Data
        self.password_entries = []
        self.current_entry = None
        self.filter_text = ""
        
        # Track last activity for auto-lock
        self.last_activity_time = time.time()
        self.activity_check_running = False
        
        # Connect to the database
        self.db_manager.connect()
        
        # Set up the UI
        self._create_widgets()
        self._setup_layout()
        self._setup_bindings()
        
        # Load passwords
        self.load_password_entries()
        
    def _create_widgets(self):
        """Create the UI widgets."""
        # Main frame
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create a PanedWindow to divide the list and detail views
        self.paned_window = ttk.PanedWindow(self.main_frame, orient=tk.HORIZONTAL)
        
        # Left side - Entry list frame
        self.list_frame = ttk.Frame(self.paned_window)
        
        # Search/filter bar
        self.search_frame = ttk.Frame(self.list_frame)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self._on_search_changed)
        
        self.search_entry = ttk.Entry(
            self.search_frame, 
            textvariable=self.search_var,
            width=20
        )
        self.search_label = ttk.Label(self.search_frame, text="Search: ")
        
        self.search_label.pack(side=tk.LEFT, padx=5)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.search_frame.pack(side=tk.TOP, fill=tk.X, pady=5)
        
        # Password list (Treeview)
        self.tree_frame = ttk.Frame(self.list_frame)
        
        self.tree = ttk.Treeview(
            self.tree_frame, 
            columns=("service", "username"),
            show="headings",
            selectmode="browse"
        )
        self.tree.heading("service", text="Service")
        self.tree.heading("username", text="Username")
        
        self.tree.column("service", width=150)
        self.tree.column("username", width=150)
        
        # Add scrollbar
        self.scrollbar = ttk.Scrollbar(self.tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.tree_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=5)
        
        # Buttons under list
        self.list_buttons_frame = ttk.Frame(self.list_frame)
        
        self.add_button = ttk.Button(
            self.list_buttons_frame, 
            text="Add", 
            command=self._show_add_dialog
        )
        self.edit_button = ttk.Button(
            self.list_buttons_frame, 
            text="Edit", 
            command=self._show_edit_dialog,
            state=tk.DISABLED
        )
        self.delete_button = ttk.Button(
            self.list_buttons_frame, 
            text="Delete", 
            command=self._delete_password,
            state=tk.DISABLED
        )
        
        self.add_button.pack(side=tk.LEFT, padx=5)
        self.edit_button.pack(side=tk.LEFT, padx=5)
        self.delete_button.pack(side=tk.LEFT, padx=5)
        self.list_buttons_frame.pack(side=tk.TOP, fill=tk.X, pady=5)
        
        # Right side - Entry detail frame
        self.detail_frame = ttk.Frame(self.paned_window)
        
        # Detail view title
        self.detail_title = ttk.Label(
            self.detail_frame, 
            text="Password Details", 
            font=("Helvetica", 12, "bold")
        )
        self.detail_title.pack(side=tk.TOP, fill=tk.X, pady=10)
        
        # Details content frame with padding
        self.detail_content = ttk.Frame(self.detail_frame, padding=10)
        self.detail_content.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        
        # Service name
        ttk.Label(self.detail_content, text="Service:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.service_label = ttk.Label(self.detail_content, text="")
        self.service_label.grid(row=0, column=1, sticky=tk.W, pady=5)
        
        # Username
        ttk.Label(self.detail_content, text="Username:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.username_label = ttk.Label(self.detail_content, text="")
        self.username_label.grid(row=1, column=1, sticky=tk.W, pady=5)
        self.copy_username_button = ttk.Button(
            self.detail_content, 
            text="Copy", 
            width=6,
            command=self._copy_username
        )
        self.copy_username_button.grid(row=1, column=2, padx=5, pady=5)
        
        # Password
        ttk.Label(self.detail_content, text="Password:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.password_frame = ttk.Frame(self.detail_content)
        self.password_frame.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        self.password_var = tk.StringVar()
        self.password_display = ttk.Entry(
            self.password_frame, 
            textvariable=self.password_var, 
            show="•", 
            state="readonly"
        )
        self.password_display.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_password_var = tk.BooleanVar(value=False)
        self.show_password_button = ttk.Checkbutton(
            self.password_frame,
            text="Show",
            variable=self.show_password_var,
            command=self._toggle_password_visibility
        )
        self.show_password_button.pack(side=tk.LEFT, padx=5)
        
        self.copy_password_button = ttk.Button(
            self.detail_content, 
            text="Copy", 
            width=6,
            command=self._copy_password
        )
        self.copy_password_button.grid(row=2, column=2, padx=5, pady=5)
        
        # Notes
        ttk.Label(self.detail_content, text="Notes:").grid(row=3, column=0, sticky=tk.NW, pady=5)
        
        self.notes_frame = ttk.Frame(self.detail_content)
        self.notes_frame.grid(row=3, column=1, columnspan=2, sticky=tk.NSEW, pady=5)
        
        self.notes_text = tk.Text(self.notes_frame, height=5, width=30, wrap=tk.WORD, state=tk.DISABLED)
        notes_scrollbar = ttk.Scrollbar(self.notes_frame, orient=tk.VERTICAL, command=self.notes_text.yview)
        self.notes_text.configure(yscrollcommand=notes_scrollbar.set)
        
        self.notes_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        notes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Created/Modified dates
        ttk.Label(self.detail_content, text="Created:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.created_label = ttk.Label(self.detail_content, text="")
        self.created_label.grid(row=4, column=1, columnspan=2, sticky=tk.W, pady=5)
        
        ttk.Label(self.detail_content, text="Modified:").grid(row=5, column=0, sticky=tk.W, pady=5)
        self.modified_label = ttk.Label(self.detail_content, text="")
        self.modified_label.grid(row=5, column=1, columnspan=2, sticky=tk.W, pady=5)
        
        # Password strength meter
        ttk.Label(self.detail_content, text="Strength:").grid(row=6, column=0, sticky=tk.W, pady=5)
        
        self.strength_frame = ttk.Frame(self.detail_content)
        self.strength_frame.grid(row=6, column=1, columnspan=2, sticky=tk.W, pady=5)
        
        self.strength_meter = ttk.Progressbar(
            self.strength_frame, 
            orient=tk.HORIZONTAL, 
            length=150, 
            mode='determinate'
        )
        self.strength_meter.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.strength_label = ttk.Label(self.strength_frame, text="")
        self.strength_label.pack(side=tk.LEFT, padx=5)
        
        # Status bar at the bottom
        self.status_bar = ttk.Label(
            self, 
            text="Ready", 
            relief=tk.SUNKEN, 
            anchor=tk.W,
            padding=(5, 2)
        )
        
        # Menu bar
        self.menubar = tk.Menu(self.parent)
        
        # File menu
        self.file_menu = tk.Menu(self.menubar, tearoff=0)
        self.file_menu.add_command(label="New Password Entry", command=self._show_add_dialog)
        self.file_menu.add_separator()
        self.file_menu.add_command(label="Exit", command=self._handle_close)
        
        # Account menu
        self.account_menu = tk.Menu(self.menubar, tearoff=0)
        self.account_menu.add_command(label="Logout", command=self._handle_logout)
        
        # Add menus to menubar
        self.menubar.add_cascade(label="File", menu=self.file_menu)
        self.menubar.add_cascade(label="Account", menu=self.account_menu)
        
        # Configure parent's menu
        self.parent.config(menu=self.menubar)
        
    def _setup_layout(self):
        """Set up the widget layout."""
        # Add panes to paned window
        self.paned_window.add(self.list_frame, weight=1)
        self.paned_window.add(self.detail_frame, weight=2)
        self.paned_window.pack(fill=tk.BOTH, expand=True)
        
        # Pack status bar
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def _setup_bindings(self):
        """Set up event bindings."""
        # Selection change
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        
        # Double click to edit
        self.tree.bind("<Double-1>", self._show_edit_dialog)
        
        # Keyboard navigation
        self.bind_all("<KeyPress>", self._update_activity_time)
        self.bind_all("<Button>", self._update_activity_time)
        
        # Window close
        self.parent.protocol("WM_DELETE_WINDOW", self._handle_close)
        
    def _update_activity_time(self, event):
        """Update the last activity time."""
        self.last_activity_time = time.time()
        
    def load_password_entries(self):
        """Load password entries from the database."""
        # Clear existing entries
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Get the current user ID
        user_id = self.auth_manager.get_current_user_id()
        if not user_id:
            self.status_bar.config(text="Error: No user authenticated")
            return
            
        try:
            # Connect to the database
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            
            # Create simple passwords table for this application
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS passwords (
                    user_id INTEGER NOT NULL,
                    service_name TEXT NOT NULL,
                    username TEXT,
                    encrypted_password TEXT NOT NULL,
                    notes TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(user_id)
                )
            """)
            conn.commit()
            
            # Get all passwords for the current user
            cursor.execute(
                "SELECT rowid as id, service_name, username, encrypted_password as password, notes, created_at, modified_at FROM passwords WHERE user_id = ? ORDER BY service_name",
                (user_id,)
            )
            
            entries = cursor.fetchall()
            self.password_entries = []
            
            for entry in entries:
                entry_id, service_name, username, password, notes, created_at, modified_at = entry
                self.password_entries.append({
                    "id": entry_id,
                    "service_name": service_name,
                    "username": username,
                    "password": password,
                    "notes": notes,
                    "created_at": created_at,
                    "modified_at": modified_at
                })
                
                # Add to tree
                self.tree.insert(
                    "", 
                    tk.END, 
                    values=(service_name, username or ""),
                    iid=str(entry_id)
                )
                
            # Update status bar
            self.status_bar.config(text=f"{len(self.password_entries)} passwords loaded")
            
            # If no entries, show a placeholder
            if not self.password_entries:
                # Add example entry to the tree
                self.tree.insert("", tk.END, values=("Example Service", "user@example.com"), iid="example")
                self.status_bar.config(text="No passwords found. Click 'Add' to create one.")
                
            conn.close()
                
        except Exception as e:
            logger.error(f"Error loading passwords: {e}")
            messagebox.showerror("Error", f"Failed to load passwords: {str(e)}")
            
            # Show a placeholder entry
            self.tree.insert("", tk.END, values=("Example Service", "user@example.com"), iid="example")
            self.status_bar.config(text="Error loading passwords")
            
    def _on_tree_select(self, event):
        """Handle tree selection event."""
        selected_items = self.tree.selection()
        if not selected_items:
            # No selection, disable edit buttons
            self.edit_button.config(state=tk.DISABLED)
            self.delete_button.config(state=tk.DISABLED)
            self._clear_details()
            return
            
        # Enable edit buttons
        self.edit_button.config(state=tk.NORMAL)
        self.delete_button.config(state=tk.NORMAL)
        
        # Get the selected entry ID
        entry_id = selected_items[0]
        
        # If it's the example entry
        if entry_id == "example":
            self._show_example_entry()
            return
            
        # Find the entry in our list
        entry_id = int(entry_id)
        selected_entry = None
        
        for entry in self.password_entries:
            if entry["id"] == entry_id:
                selected_entry = entry
                break
                
        if selected_entry:
            self._show_entry_details(selected_entry)
        else:
            self._show_example_entry()
    
    def _show_entry_details(self, entry):
        """Show the details of a password entry."""
        # Store current entry
        self.current_entry = entry
        
        # Update the UI
        self.service_label.config(text=entry["service_name"])
        self.username_label.config(text=entry["username"] or "")
        self.password_var.set(entry["password"])
        
        # Show notes
        self.notes_text.config(state=tk.NORMAL)
        self.notes_text.delete("1.0", tk.END)
        if entry["notes"]:
            self.notes_text.insert("1.0", entry["notes"])
        self.notes_text.config(state=tk.DISABLED)
        
        # Format dates
        try:
            created = datetime.fromisoformat(entry["created_at"]).strftime("%Y-%m-%d %H:%M")
            modified = datetime.fromisoformat(entry["modified_at"]).strftime("%Y-%m-%d %H:%M")
        except:
            created = entry["created_at"]
            modified = entry["modified_at"]
            
        self.created_label.config(text=created)
        self.modified_label.config(text=modified)
        
        # Calculate password strength
        self._update_strength_meter(entry["password"])
        
    def _show_example_entry(self):
        """Show example entry details."""
        # Update the UI with example data
        self.service_label.config(text="Example Service")
        self.username_label.config(text="user@example.com")
        self.password_var.set("ExamplePassword123!")
        
        # Show notes
        self.notes_text.config(state=tk.NORMAL)
        self.notes_text.delete("1.0", tk.END)
        self.notes_text.insert("1.0", "This is an example password entry.")
        self.notes_text.config(state=tk.DISABLED)
        
        # Format dates
        self.created_label.config(text="2025-06-29 13:00")
        self.modified_label.config(text="2025-06-29 13:00")
        
        # Calculate password strength
        self._update_strength_meter("ExamplePassword123!")
                
    def _clear_details(self):
        """Clear the details panel."""
        self.current_entry = None
        self.service_label.config(text="")
        self.username_label.config(text="")
        self.password_var.set("")
        self.notes_text.config(state=tk.NORMAL)
        self.notes_text.delete("1.0", tk.END)
        self.notes_text.config(state=tk.DISABLED)
        self.created_label.config(text="")
        self.modified_label.config(text="")
        self.strength_meter.config(value=0)
        self.strength_label.config(text="")
        
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
            
    def _on_search_changed(self, *args):
        """Handle search field changes."""
        self.filter_text = self.search_var.get().strip().lower()
        self.load_password_entries()
        
    def _filter_entries(self, filter_text):
        """Filter password entries by search text."""
        if not filter_text:
            return self.password_entries
            
        filtered = []
        for entry in self.password_entries:
            if (filter_text in entry["service_name"].lower() or 
                (entry["username"] and filter_text in entry["username"].lower())):
                filtered.append(entry)
                
        return filtered
        
    def _toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_display.config(show="")
        else:
            self.password_display.config(show="•")
            
    def _copy_username(self):
        """Copy username to clipboard."""
        username = self.username_label.cget("text")
        if username:
            copy_to_clipboard(username)
            self.status_bar.config(text="Username copied to clipboard")
            
    def _copy_password(self):
        """Copy password to clipboard."""
        password = self.password_var.get()
        if password:
            copy_to_clipboard(password)
            self.status_bar.config(text="Password copied to clipboard")
            
    def _show_add_dialog(self):
        """Show dialog to add a new password."""
        dialog = PasswordDialog(
            self.parent,
            title="Add Password",
            on_save=self._add_password
        )
        
    def _add_password(self, service_name, username, password, notes):
        """Add a new password entry."""
        try:
            # Get the current user ID
            user_id = self.auth_manager.get_current_user_id()
            if not user_id:
                messagebox.showerror("Error", "No user authenticated")
                return
                
            # Connect to the database
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            
            # Insert the new password
            cursor.execute(
                """
                INSERT INTO passwords 
                (user_id, service_name, username, encrypted_password, notes)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user_id, service_name, username, password, notes)
            )
            conn.commit()
            
            # Get the new entry ID
            entry_id = cursor.lastrowid
            
            # Close the connection
            conn.close()
            
            # Reload the password entries
            self.load_password_entries()
            
            # Try to select the new entry if it exists
            try:
                self.tree.selection_set(str(entry_id))
                self.tree.see(str(entry_id))
            except:
                # If we can't select it, just select the first entry
                if self.tree.get_children():
                    self.tree.selection_set(self.tree.get_children()[0])
                    self.tree.see(self.tree.get_children()[0])
            
            # Update status bar
            self.status_bar.config(text=f"Added password for {service_name}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error adding password: {e}")
            messagebox.showerror("Error", f"Failed to add password: {str(e)}")
            return False
        
    def _show_edit_dialog(self, event=None):
        """Show dialog to edit a password."""
        if not self.current_entry:
            return
            
        dialog = PasswordDialog(
            self.parent,
            title="Edit Password",
            on_save=self._update_password,
            entry_id=self.current_entry["id"],
            service_name=self.current_entry["service_name"],
            username=self.current_entry["username"] or "",
            password=self.current_entry["password"],
            notes=self.current_entry["notes"] or ""
        )
            
    def _update_password(self, service_name, username, password, notes, entry_id=None):
        """Update an existing password entry."""
        try:
            # Connect to the database
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            
            # Update the password
            cursor.execute(
                """
                UPDATE passwords 
                SET service_name = ?, username = ?, encrypted_password = ?, notes = ?, modified_at = CURRENT_TIMESTAMP
                WHERE rowid = ?
                """,
                (service_name, username, password, notes, entry_id)
            )
            conn.commit()
            
            # Close the connection
            conn.close()
            
            # Reload the password entries
            self.load_password_entries()
            
            # Select the updated entry
            self.tree.selection_set(str(entry_id))
            self.tree.see(str(entry_id))
            
            # Update status bar
            self.status_bar.config(text=f"Updated password for {service_name}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error updating password: {e}")
            messagebox.showerror("Error", f"Failed to update password: {str(e)}")
            return False
            
    def _delete_password(self):
        """Delete the selected password."""
        if not self.current_entry:
            return
            
        # Ask for confirmation
        if not messagebox.askyesno(
            "Confirm Delete",
            f"Are you sure you want to delete the password for {self.current_entry['service_name']}?"
        ):
            return
            
        try:
            # Connect to the database
            conn = sqlite3.connect(self.db_manager.db_path)
            cursor = conn.cursor()
            
            # Delete the password
            cursor.execute(
                "DELETE FROM passwords WHERE rowid = ?",
                (self.current_entry["id"],)
            )
            conn.commit()
            
            # Close the connection
            conn.close()
            
            # Update status bar
            self.status_bar.config(text=f"Deleted password for {self.current_entry['service_name']}")
            
            # Clear the current entry
            self.current_entry = None
            
            # Reload the password entries
            self.load_password_entries()
            
        except Exception as e:
            logger.error(f"Error deleting password: {e}")
            messagebox.showerror("Error", f"Failed to delete password: {str(e)}")
            
    def _lock_application(self):
        """Lock the application."""
        if self.on_logout:
            self.on_logout(lock=True)
            
    def _handle_logout(self):
        """Handle logout request."""
        if self.on_logout:
            self.on_logout(lock=False)
            
    def _handle_close(self):
        """Handle application close."""
        # Clean up resources
        self.db_manager.close()
        
        # Close the window
        self.parent.destroy() 