
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import json
import os
import random
import string
import pyperclip
from datetime import datetime
import base64
import re
import csv
import sys
import time
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv

class PasswordManager:
    DEFAULT_CONFIG = {
        "bg_fore": "#383838",
        "bg_back": "#303030",
        "white_fore": "white",
        "colorEdit": "#0b4f16",
        "colorEditHover": "#07330e",
        "fontSize": 30,
        "inactivityLimit": 300  # 5 minutes in seconds
    }

    def __init__(self, root):
        self.root = root
        self.root.title("Local Password Manager")
        self.root.geometry("1150x650")
        self.root.minsize(950, 450)
        self.load_config()
        self.root.configure(bg=self.config["bg_back"])
        ctk.set_appearance_mode("dark")
        ctk.set_widget_scaling(1.2)

        # Define variables
        self.password_length = tk.IntVar(value=16)
        self.include_lowercase = tk.BooleanVar(value=True)
        self.include_uppercase = tk.BooleanVar(value=True)
        self.include_digits = tk.BooleanVar(value=True)
        self.include_special = tk.BooleanVar(value=True)
        self.exclude_similar = tk.BooleanVar(value=True)
        self.current_password = tk.StringVar()
        self.identifier = tk.StringVar()
        self.username = tk.StringVar()
        self.email = tk.StringVar()
        self.search_term = tk.StringVar()
        self.filter_option = tk.StringVar(value="All")
        self.search_field = tk.StringVar(value="All Fields")
        self.show_passwords = tk.BooleanVar(value=False)  # Track password visibility

        # Inactivity timeout setup
        self.inactivity_limit = self.config["inactivityLimit"]
        self.last_interaction = time.time()
        self.root.bind("<Button>", self.reset_inactivity_timer)
        self.root.bind("<Key>", self.reset_inactivity_timer)
        self.root.bind("<Motion>", self.reset_inactivity_timer)
        self.check_inactivity()

        # Set up tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Generator tab
        self.generator_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.generator_frame, text="Password Generator")
        self.setup_generator_tab()

        # History tab
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="Password History")
        self.setup_history_tab()

        # Import tab
        self.import_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.import_frame, text="Import")
        self.setup_import_tab()

        # Setup database
        self.db_path = "passwords.encrypted"
        self.passwords = []
        self.key = None
        self.initialize_database()

        # Style configuration
        self.configure_styles()

        # Bind close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def load_config(self):
        self.config = self.DEFAULT_CONFIG.copy()
        config_path = "config.json"
        if not os.path.exists(config_path):
            print(f"Warning: '{config_path}' not found. Using default configuration.")
            return

        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
        except json.JSONDecodeError:
            print(f"Warning: '{config_path}' is invalid JSON. Using default configuration.")
            return
        except Exception as e:
            print(f"Warning: Failed to read '{config_path}': {str(e)}. Using default configuration.")
            return

        # Validate and update config
        hex_pattern = re.compile(r'^#[0-9A-Fa-f]{6}$')
        for key, value in user_config.items():
            if key in ["bg_fore", "bg_back", "colorEdit", "colorEditHover"]:
                if isinstance(value, str) and hex_pattern.match(value):
                    self.config[key] = value
                else:
                    print(f"Warning: Invalid hex color for '{key}' in config.json. Using default: {self.config[key]}")
            elif key == "white_fore":
                if isinstance(value, str) and (hex_pattern.match(value) or value == "white"):
                    self.config[key] = value
                else:
                    print(f"Warning: Invalid color for 'white_fore' in config.json. Using default: {self.config[key]}")
            elif key == "fontSize":
                if isinstance(value, int) and value >= 10:
                    self.config[key] = value
                else:
                    print(f"Warning: Invalid fontSize '{value}' in config.json (must be integer >= 10). Using default: {self.config[key]}")
            elif key == "inactivityLimit":
                if isinstance(value, int) and value >= 30:
                    self.config[key] = value
                else:
                    print(f"Warning: Invalid inactivityLimit '{value}' in config.json (must be integer >= 30). Using default: {self.config[key]}")
            else:
                print(f"Warning: Unknown config key '{key}' in config.json. Ignored.")

    def reset_inactivity_timer(self, event=None):
        self.last_interaction = time.time()

    def check_inactivity(self):
        if time.time() - self.last_interaction > self.inactivity_limit:
            print(f"Inactivity timeout reached ({self.inactivity_limit} seconds). Exiting for security.")
            self.on_close()
        else:
            self.root.after(1000, self.check_inactivity)  # Check every second

    def configure_styles(self):
        style = ttk.Style()
        style.theme_use('default')
        style.configure("TNotebook", background=self.config["bg_fore"], tabmargins=0)
        style.configure("TNotebook.Tab", background=self.config["bg_fore"], foreground=self.config["white_fore"], 
                        padding=[10, 5], font=("Helvetica", self.config["fontSize"]), borderwidth=0)
        style.map("TNotebook.Tab", background=[('selected', self.config["bg_back"])], 
                  foreground=[('selected', self.config["white_fore"])])
        style.configure("TFrame", background=self.config["bg_back"])
        style.configure("Treeview", rowheight=70, background=self.config["bg_back"], 
                        foreground=self.config["white_fore"], fieldbackground=self.config["bg_back"], 
                        font=("Helvetica", self.config["fontSize"]-5))
        style.configure("Treeview.Heading", background=self.config["bg_fore"], foreground=self.config["white_fore"], 
                        font=("Helvetica", self.config["fontSize"], "bold"), borderwidth=0)
        style.map("Treeview", background=[('selected', self.config["bg_fore"])], 
                  foreground=[('selected', self.config["white_fore"])])
        style.configure("TScrollbar", background=self.config["bg_fore"], troughcolor=self.config["bg_back"], 
                        arrowcolor=self.config["white_fore"], borderwidth=0)
        style.map("TScrollbar", background=[('active', self.config["bg_fore"])])
        style.configure("TCombobox", fieldbackground=self.config["bg_fore"], foreground=self.config["white_fore"], 
                        background=self.config["bg_fore"], font=("Helvetica", self.config["fontSize"]), arrowsize=14)
        style.map("TCombobox", fieldbackground=[('disabled', self.config["bg_fore"])], 
                  selectbackground=[('!focus', self.config["bg_fore"])], 
                  selectforeground=[('!focus', self.config["white_fore"])])

    def initialize_database(self):
        if os.path.exists(self.db_path):
            master_password = self.get_master_password("Enter your master password:")
            if not master_password:
                self.root.destroy()
                return
            try:
                self.key = self.generate_key(master_password)
                self.passwords = self.load_data()
                self.migrate_database_if_needed()
                self.refresh_history_view()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to decrypt database: {str(e)}")
                self.root.destroy()
        else:
            self.create_new_database()

    def migrate_database_if_needed(self):
        migration_needed = False
        for entry in self.passwords:
            if "email" not in entry:
                entry["email"] = ""
                migration_needed = True
            if "username" not in entry:
                entry["username"] = ""
                migration_needed = True
        if migration_needed:
            self.save_data()

    def create_new_database(self):
        master_password = self.get_master_password("Create a master password:")
        if not master_password:
            self.root.destroy()
            return
        confirm_password = self.get_master_password("Confirm your master password:")
        if master_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match")
            self.create_new_database()
            return
        # Generate and save random salt
        salt = base64.b64encode(os.urandom(32)).decode()
        self.save_salt_to_env(salt)
        # Load environment variables after saving .env
        load_dotenv()
        self.key = self.generate_key(master_password)
        self.passwords = []
        self.save_data()

    def save_salt_to_env(self, salt):
        env_path = ".env"
        env_content = [
            "# Encryption salt (auto-generated on first database creation)",
            f"ENCRYPTION_SALT={salt}",
        ]
        try:
            with open(env_path, 'w') as f:
                f.write("\n".join(env_content) + "\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save salt to .env: {str(e)}")
            self.root.destroy()

    def generate_key(self, password):
        load_dotenv()  # Ensure environment variables are loaded
        salt = os.getenv("ENCRYPTION_SALT")
        if not salt:
            messagebox.showerror("Error", "ENCRYPTION_SALT not found in .env file")
            self.root.destroy()
            return
        try:
            salt_bytes = base64.b64decode(salt)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid ENCRYPTION_SALT: {str(e)}")
            self.root.destroy()
            return
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt_bytes,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def load_data(self):
        try:
            with open(self.db_path, 'rb') as file:
                encrypted_data = file.read()
            if not encrypted_data:
                return []
            cipher = Fernet(self.key)
            decrypted_data = cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load database: {str(e)}")
            raise

    def save_data(self):
        try:
            data_json = json.dumps(self.passwords)
            cipher = Fernet(self.key)
            encrypted_data = cipher.encrypt(data_json.encode())
            with open(self.db_path, 'wb') as file:
                file.write(encrypted_data)
            self.refresh_history_view()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save database: {str(e)}")

    def get_master_password(self, prompt):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Master Password")
        dialog.geometry("400x200")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(fg_color=self.config["bg_back"])

        ctk.CTkLabel(dialog, text=prompt, text_color=self.config["white_fore"], font=("Helvetica", 11)).pack(pady=10)
        password_var = tk.StringVar()
        entry = ctk.CTkEntry(dialog, textvariable=password_var, show="•", width=200, font=("Helvetica", 11))
        entry.pack(pady=10)
        dialog.after(100, entry.focus_force)

        def on_ok():
            dialog.destroy()

        btn_frame = ctk.CTkFrame(dialog, fg_color=self.config["bg_back"])
        btn_frame.pack(pady=10)
        ctk.CTkButton(btn_frame, text="OK", command=on_ok, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], width=80, font=("Helvetica", 11)).pack(side='left', padx=5)
        ctk.CTkButton(btn_frame, text="Cancel", command=dialog.destroy, fg_color=self.config["bg_fore"], hover_color=self.config["bg_back"], width=80, font=("Helvetica", 11)).pack(side='left', padx=5)

        dialog.bind("<Return>", lambda e: on_ok())
        dialog.wait_window()
        # Reset inactivity timer after dialog interaction
        self.reset_inactivity_timer()
        return password_var.get()

    def setup_generator_tab(self):
        frame = self.generator_frame
        frame.configure(style="TFrame")

        options_frame = ctk.CTkFrame(frame, fg_color=self.config["bg_fore"], bg_color=self.config["bg_back"])
        options_frame.pack(fill='x', padx=10, pady=10)

        ctk.CTkLabel(options_frame, text="Length:", text_color=self.config["white_fore"], font=("Helvetica", 11)).grid(row=0, column=0, padx=10, pady=5, sticky='w')
        length_slider = ctk.CTkSlider(options_frame, from_=8, to=500, number_of_steps=56, variable=self.password_length, width=450, fg_color=self.config["bg_fore"], progress_color=self.config["colorEdit"])
        length_slider.grid(row=0, column=1, columnspan=3, padx=5, pady=5)
        length_label = ctk.CTkLabel(options_frame, textvariable=self.password_length, text_color=self.config["white_fore"], font=("Helvetica", 11))
        length_label.grid(row=0, column=4, padx=10, pady=5)

        ctk.CTkCheckBox(options_frame, text="Lowercase", variable=self.include_lowercase, text_color=self.config["white_fore"], font=("Helvetica", 11), fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"]).grid(row=1, column=0, padx=5, pady=5, sticky='w')
        ctk.CTkCheckBox(options_frame, text="Uppercase", variable=self.include_uppercase, text_color=self.config["white_fore"], font=("Helvetica", 11), fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"]).grid(row=1, column=1, padx=5, pady=5, sticky='w')
        ctk.CTkCheckBox(options_frame, text="Digits", variable=self.include_digits, text_color=self.config["white_fore"], font=("Helvetica", 11), fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"]).grid(row=1, column=2, padx=5, pady=5, sticky='w')
        ctk.CTkCheckBox(options_frame, text="Special", variable=self.include_special, text_color=self.config["white_fore"], font=("Helvetica", 11), fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"]).grid(row=1, column=3, padx=5, pady=5, sticky='w')
        ctk.CTkCheckBox(options_frame, text="Exclude Similar", variable=self.exclude_similar, text_color=self.config["white_fore"], font=("Helvetica", 11), fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"]).grid(row=1, column=4, columnspan=1, padx=5, pady=5, sticky='w')

        password_frame = ctk.CTkFrame(frame, fg_color=self.config["bg_back"], bg_color=self.config["bg_back"])
        password_frame.pack(fill='x', padx=10, pady=5)
        ctk.CTkLabel(password_frame, text="Generated Password:", text_color=self.config["white_fore"], font=("Helvetica", 11)).pack(anchor='w', padx=10, pady=2)
        password_inner_frame = ctk.CTkFrame(password_frame, fg_color=self.config["bg_back"], bg_color=self.config["bg_back"])
        password_inner_frame.pack(fill='x', padx=10, pady=5)
        password_entry = ctk.CTkEntry(password_inner_frame, textvariable=self.current_password, width=400, font=("Helvetica", 12), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"])
        password_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        generate_btn = ctk.CTkButton(password_inner_frame, text="Generate", command=self.generate_password, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11), width=100)
        generate_btn.pack(side='left')

        info_frame = ctk.CTkFrame(frame, fg_color=self.config["bg_fore"], bg_color=self.config["bg_back"])
        info_frame.pack(fill='x', padx=10, pady=10)

        ctk.CTkLabel(info_frame, text="Website/App:", text_color=self.config["white_fore"], font=("Helvetica", 11)).grid(row=0, column=0, padx=5, pady=2, sticky='w')
        identifier_entry = ctk.CTkEntry(info_frame, textvariable=self.identifier, width=200, font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"])
        identifier_entry.grid(row=1, column=0, padx=5, pady=5, sticky='ew')

        ctk.CTkLabel(info_frame, text="Username:", text_color=self.config["white_fore"], font=("Helvetica", 11)).grid(row=0, column=1, padx=5, pady=2, sticky='w')
        username_entry = ctk.CTkEntry(info_frame, textvariable=self.username, width=200, font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"])
        username_entry.grid(row=1, column=1, padx=5, pady=5, sticky='ew')

        ctk.CTkLabel(info_frame, text="Email:", text_color=self.config["white_fore"], font=("Helvetica", 11)).grid(row=0, column=2, padx=5, pady=2, sticky='w')
        email_entry = ctk.CTkEntry(info_frame, textvariable=self.email, width=200, font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"])
        email_entry.grid(row=1, column=2, padx=5, pady=5, sticky='ew')

        info_frame.columnconfigure((0, 1, 2), weight=1)

        btn_frame = ctk.CTkFrame(frame, fg_color=self.config["bg_back"], bg_color=self.config["bg_back"])
        btn_frame.pack(fill='x', padx=10, pady=10)
        ctk.CTkButton(btn_frame, text="Copy", command=self.copy_password, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11)).pack(side='left', padx=5)
        ctk.CTkButton(btn_frame, text="Save", command=self.save_password, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11)).pack(side='left', padx=5)
        ctk.CTkButton(btn_frame, text="Clear", command=self.clear_generator, fg_color=self.config["bg_fore"], hover_color=self.config["bg_back"], font=("Helvetica", 11)).pack(side='left', padx=5)

    def setup_history_tab(self):
        frame = self.history_frame
        frame.configure(style="TFrame")

        search_frame = ctk.CTkFrame(frame, fg_color=self.config["bg_back"], bg_color=self.config["bg_back"])
        search_frame.pack(fill='x', padx=10, pady=10)

        ctk.CTkLabel(search_frame, text="Search:", text_color=self.config["white_fore"], font=("Helvetica", 11)).pack(side='left', padx=10)
        search_entry = ctk.CTkEntry(search_frame, textvariable=self.search_term, width=200, font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"])
        search_entry.pack(side='left', padx=5)
        search_entry.bind("<KeyRelease>", lambda e: self.refresh_history_view())

        ctk.CTkLabel(search_frame, text="in:", text_color=self.config["white_fore"], font=("Helvetica", 11)).pack(side='left', padx=(5, 0))
        search_field_combo = ctk.CTkComboBox(search_frame, variable=self.search_field, 
                                             values=["All Fields", "Website/App", "Username", "Email"], 
                                             width=120, font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"], button_color=self.config["bg_fore"])
        search_field_combo.pack(side='left', padx=10)
        search_field_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_history_view())

        ctk.CTkLabel(search_frame, text="Filter:", text_color=self.config["white_fore"], font=("Helvetica", 11)).pack(side='left', padx=(15, 5))
        filter_combo = ctk.CTkComboBox(search_frame, variable=self.filter_option, 
                                       values=["All", "Today", "Last Week", "Last Month"], 
                                       width=120, font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"], button_color=self.config["bg_fore"])
        filter_combo.pack(side='left', padx=10)
        filter_combo.bind("<<ComboboxSelected>>", lambda e: self.refresh_history_view())

        refresh_btn = ctk.CTkButton(search_frame, text="Refresh", command=self.refresh_history_view, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11))
        refresh_btn.pack(side='right', padx=10)

        self.history_tree = ttk.Treeview(frame, columns=("id", "identifier", "username", "email", "password", "date"), 
                                         show="headings")
        self.history_tree.heading("id", text="ID")
        self.history_tree.heading("identifier", text="Website/App")
        self.history_tree.heading("username", text="Username")
        self.history_tree.heading("email", text="Email")
        self.history_tree.heading("password", text="Password")
        self.history_tree.heading("date", text="Creation Date")

        self.history_tree.column("id", width=60, minwidth=60)
        self.history_tree.column("identifier", width=200, minwidth=120)
        self.history_tree.column("username", width=160, minwidth=100)
        self.history_tree.column("email", width=200, minwidth=120)
        self.history_tree.column("password", width=240, minwidth=160)
        self.history_tree.column("date", width=200, minwidth=120)

        tree_scroll_y = ttk.Scrollbar(frame, orient="vertical", command=self.history_tree.yview)
        tree_scroll_x = ttk.Scrollbar(frame, orient="horizontal", command=self.history_tree.xview)
        self.history_tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)

        tree_scroll_y.pack(side='right', fill='y')
        tree_scroll_x.pack(side='bottom', fill='x')
        self.history_tree.pack(fill='both', expand=True, padx=(10, 0), pady=10)

        self.context_menu = tk.Menu(self.history_tree, tearoff=0, bg=self.config["bg_fore"], fg=self.config["white_fore"], 
                                    font=("Helvetica", self.config["fontSize"]), borderwidth=1)
        self.context_menu.add_command(label="Copy Password", command=self.copy_selected_password)
        self.context_menu.add_command(label="Copy Username", command=self.copy_selected_username)
        self.context_menu.add_command(label="Copy Email", command=self.copy_selected_email)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Edit Entry", command=self.edit_selected_entry)
        self.context_menu.add_command(label="Delete Entry", command=self.delete_selected_entry)

        self.history_tree.bind("<Button-3>", self.show_context_menu)
        self.history_tree.bind("<Double-1>", lambda e: self.copy_selected_password())

        btn_frame = ctk.CTkFrame(frame, fg_color=self.config["bg_back"], bg_color=self.config["bg_back"])
        btn_frame.pack(fill='x', padx=10, pady=10)

        copy_password_btn = ctk.CTkButton(btn_frame, text="Copy Password", command=self.copy_selected_password, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11))
        copy_password_btn.pack(side='left', padx=5)
        copy_username_btn = ctk.CTkButton(btn_frame, text="Copy Username", command=self.copy_selected_username, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11))
        copy_username_btn.pack(side='left', padx=5)
        copy_email_btn = ctk.CTkButton(btn_frame, text="Copy Email", command=self.copy_selected_email, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11))
        copy_email_btn.pack(side='left', padx=5)
        delete_btn = ctk.CTkButton(btn_frame, text="Delete", command=self.delete_selected_entry, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11))
        delete_btn.pack(side='left', padx=5)
        edit_btn = ctk.CTkButton(btn_frame, text="Edit", command=self.edit_selected_entry, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11))
        edit_btn.pack(side='left', padx=5)
        self.toggle_password_btn = ctk.CTkButton(btn_frame, text="Show", command=self.toggle_password_visibility, fg_color=self.config["bg_fore"], hover_color=self.config["bg_back"], font=("Helvetica", 11))
        self.toggle_password_btn.pack(side='left', padx=5)

    def toggle_password_visibility(self):
        self.show_passwords.set(not self.show_passwords.get())
        self.toggle_password_btn.configure(text="Hide" if self.show_passwords.get() else "Show")
        self.refresh_history_view()

    def setup_import_tab(self):
        frame = self.import_frame
        frame.configure(style="TFrame")

        content_frame = ctk.CTkFrame(frame, fg_color=self.config["bg_back"], bg_color=self.config["bg_back"])
        content_frame.pack(fill='both', expand=True, padx=10, pady=10)

        # CSV import section
        csv_frame = ctk.CTkFrame(content_frame, fg_color=self.config["bg_fore"], bg_color=self.config["bg_back"], corner_radius=10)
        csv_frame.pack(fill='x', padx=10, pady=10)

        csv_title = ctk.CTkLabel(csv_frame, text="Import from CSV File", text_color=self.config["white_fore"], font=("Helvetica", 12, "bold"))
        csv_title.pack(anchor='w', padx=15, pady=(15, 5))

        ctk.CTkLabel(csv_frame, text="Import passwords from a CSV file (e.g., exported from Chrome). The file must have columns: url,username,password. The email column is optional.", 
                     text_color=self.config["white_fore"], font=("Helvetica", 11), wraplength=800).pack(anchor='w', padx=15, pady=5)

        csv_btn_frame = ctk.CTkFrame(csv_frame, fg_color=self.config["bg_fore"], bg_color=self.config["bg_fore"])
        csv_btn_frame.pack(fill='x', padx=15, pady=(5, 15))

        import_csv_btn = ctk.CTkButton(csv_btn_frame, text="Import from CSV", command=self.import_from_csv, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11))
        import_csv_btn.pack(side='left', padx=5)

        # Export section
        export_frame = ctk.CTkFrame(content_frame, fg_color=self.config["bg_fore"], bg_color=self.config["bg_back"], corner_radius=10)
        export_frame.pack(fill='x', padx=10, pady=10)

        export_title = ctk.CTkLabel(export_frame, text="Export Passwords", text_color=self.config["white_fore"], font=("Helvetica", 12, "bold"))
        export_title.pack(anchor='w', padx=15, pady=(15, 5))

        ctk.CTkLabel(export_frame, text="Export your passwords to a CSV file for backup or importing into other password managers.", 
                     text_color=self.config["white_fore"], font=("Helvetica", 11), wraplength=800).pack(anchor='w', padx=15, pady=5)

        export_btn_frame = ctk.CTkFrame(export_frame, fg_color=self.config["bg_fore"], bg_color=self.config["bg_fore"])
        export_btn_frame.pack(fill='x', padx=15, pady=(5, 15))

        export_csv_btn = ctk.CTkButton(export_btn_frame, text="Export to CSV", command=self.export_to_csv, fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11))
        export_csv_btn.pack(side='left', padx=5)

    def import_from_csv(self):
        csv_file = filedialog.askopenfilename(title="Select CSV File", filetypes=[("CSV files", "*.csv")])
        if not csv_file:
            return

        try:
            imported_entries = []
            with open(csv_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                required_columns = {'url', 'username', 'password'}
                if not required_columns.issubset(reader.fieldnames):
                    messagebox.showerror("Error", "CSV must contain columns: url, username, password")
                    return

                for row in reader:
                    url = row.get('url', '')
                    identifier = re.match(r"https?://(?:www\.)?([^/]+)", url)
                    identifier = identifier.group(1) if identifier else url
                    entry = {
                        "id": len(self.passwords) + len(imported_entries) + 1,
                        "identifier": identifier,
                        "username": row.get('username', ''),
                        "email": row.get('email', ''),
                        "password": row.get('password', ''),
                        "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    }
                    imported_entries.append(entry)

            import_count = 0
            for entry in imported_entries:
                if not any(p["identifier"] == entry["identifier"] and p["username"] == entry["username"] for p in self.passwords):
                    self.passwords.append(entry)
                    import_count += 1

            self.save_data()
            messagebox.showinfo("Success", f"Imported {import_count} passwords from CSV")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to import CSV: {str(e)}")

    def export_to_csv(self):
        csv_file = filedialog.asksaveasfilename(
            title="Save CSV File",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if not csv_file:
            return

        try:
            with open(csv_file, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=['url', 'username', 'email', 'password', 'date'])
                writer.writeheader()
                for entry in self.passwords:
                    url = entry['identifier']
                    if not (url.startswith('http://') or url.startswith('https://')):
                        url = f"https://{url}"
                    writer.writerow({
                        'url': url,
                        'username': entry['username'],
                        'email': entry['email'],
                        'password': entry['password'],
                        'date': entry['date']
                    })
            messagebox.showinfo("Success", f"Exported {len(self.passwords)} passwords to CSV")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {str(e)}")

    def generate_password(self):
        length = self.password_length.get()
        if not any([self.include_lowercase.get(), self.include_uppercase.get(), 
                    self.include_digits.get(), self.include_special.get()]):
            messagebox.showerror("Error", "At least one character type must be selected")
            return
        chars = ""
        if self.include_lowercase.get():
            chars += string.ascii_lowercase
        if self.include_uppercase.get():
            chars += string.ascii_uppercase
        if self.include_digits.get():
            chars += string.digits
        if self.include_special.get():
            chars += "!@#$%^&*()-_=+[]{}|;:,.<>?/~"
        if self.exclude_similar.get():
            for c in "l1IoO0":
                chars = chars.replace(c, "")
        try:
            password = ""
            for _ in range(length):
                password += random.choice(chars)
            has_lowercase = any(c in string.ascii_lowercase for c in password) if self.include_lowercase.get() else True
            has_uppercase = any(c in string.ascii_uppercase for c in password) if self.include_uppercase.get() else True
            has_digit = any(c in string.digits for c in password) if self.include_digits.get() else True
            has_special = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?/~" for c in password) if self.include_special.get() else True
            if not all([has_lowercase, has_uppercase, has_digit, has_special]):
                return self.generate_password()
            self.current_password.set(password)
        except IndexError:
            messagebox.showerror("Error", "Cannot generate password. Character set is empty.")

    def copy_password(self):
        password = self.current_password.get()
        if password:
            pyperclip.copy(password)
            # messagebox.showinfo("Copied", "Password copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No password to copy")

    def save_password(self):
        password = self.current_password.get()
        identifier = self.identifier.get()
        username = self.username.get()
        email = self.email.get()
        if not password:
            messagebox.showwarning("Warning", "No password to save")
            return
        if not identifier:
            messagebox.showwarning("Warning", "Please enter a website or application name")
            return
        entry = {
            "id": len(self.passwords) + 1,
            "identifier": identifier,
            "username": username,
            "email": email,
            "password": password,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        self.passwords.append(entry)
        self.save_data()
        # messagebox.showinfo("Success", "Password entry saved successfully")
        self.clear_generator()

    def clear_generator(self):
        self.current_password.set("")
        self.identifier.set("")
        self.username.set("")
        self.email.set("")

    def refresh_history_view(self):
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        filtered_passwords = self.filter_passwords()
        for entry in filtered_passwords:
            password_display = entry["password"] if self.show_passwords.get() else "•" * min(len(entry["password"]), 12)
            username = entry.get("username", "")
            email = entry.get("email", "")
            self.history_tree.insert("", tk.END, values=(
                entry["id"],
                entry["identifier"],
                username,
                email,
                password_display,
                entry["date"]
            ))

    def filter_passwords(self):
        filtered = []
        search_term = self.search_term.get().lower()
        filter_option = self.filter_option.get()
        search_field = self.search_field.get()
        today = datetime.now().date()
        for entry in self.passwords:
            if search_term:
                if search_field == "Website/App" and search_term not in entry["identifier"].lower():
                    continue
                elif search_field == "Username" and (not entry.get("username") or search_term not in entry.get("username", "").lower()):
                    continue
                elif search_field == "Email" and (not entry.get("email") or search_term not in entry.get("email", "").lower()):
                    continue
                elif search_field == "All Fields":
                    if (search_term not in entry["identifier"].lower() and
                        search_term not in entry.get("username", "").lower() and
                        search_term not in entry.get("email", "").lower()):
                        continue
            entry_date = datetime.strptime(entry["date"], "%Y-%m-%d %H:%M:%S").date()
            if filter_option == "Today" and entry_date != today:
                continue
            elif filter_option == "Last Week" and (today - entry_date).days > 7:
                continue
            elif filter_option == "Last Month" and (today - entry_date).days > 30:
                continue
            filtered.append(entry)
        return filtered

    def copy_selected_password(self):
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No entry selected")
            return
        item_id = self.history_tree.item(selected[0])["values"][0]
        self.copy_entry_field(item_id, "password")

    def copy_selected_username(self):
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No entry selected")
            return
        item_id = self.history_tree.item(selected[0])["values"][0]
        self.copy_entry_field(item_id, "username")

    def copy_selected_email(self):
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No entry selected")
            return
        item_id = self.history_tree.item(selected[0])["values"][0]
        self.copy_entry_field(item_id, "email")

    def copy_entry_field(self, item_id, field):
        for entry in self.passwords:
            if entry["id"] == item_id:
                value = entry.get(field, "")
                if value:
                    pyperclip.copy(value)
                    # messagebox.showinfo("Copied", f"{field.capitalize()} for '{entry['identifier']}' copied to clipboard")
                else:
                    messagebox.showinfo("Info", f"No {field} stored for this entry")
                return
        messagebox.showerror("Error", "Entry not found in database")

    def edit_selected_entry(self):
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No entry selected")
            return
        item_id = self.history_tree.item(selected[0])["values"][0]
        for i, entry in enumerate(self.passwords):
            if entry["id"] == item_id:
                self.open_edit_dialog(i, entry)
                return
        messagebox.showerror("Error", "Entry not found in database")

    def open_edit_dialog(self, index, entry):
        dialog = ctk.CTkToplevel(self.root)
        dialog.title("Edit Entry")
        dialog.geometry("600x350")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.configure(fg_color=self.config["bg_back"])

        content_frame = ctk.CTkFrame(dialog, fg_color=self.config["bg_back"], bg_color=self.config["bg_back"])
        content_frame.pack(fill='both', expand=True, padx=15, pady=15)

        ctk.CTkLabel(content_frame, text="Website/App:", text_color=self.config["white_fore"], font=("Helvetica", 11)).grid(row=0, column=0, padx=10, pady=10, sticky='w')
        identifier_var = tk.StringVar(value=entry["identifier"])
        identifier_entry = ctk.CTkEntry(content_frame, textvariable=identifier_var, width=300, font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"])
        identifier_entry.grid(row=0, column=1, padx=10, pady=10, sticky='ew')

        ctk.CTkLabel(content_frame, text="Username:", text_color=self.config["white_fore"], font=("Helvetica", 11)).grid(row=1, column=0, padx=10, pady=10, sticky='w')
        username_var = tk.StringVar(value=entry.get("username", ""))
        username_entry = ctk.CTkEntry(content_frame, textvariable=username_var, width=300, font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"])
        username_entry.grid(row=1, column=1, padx=10, pady=10, sticky='ew')

        ctk.CTkLabel(content_frame, text="Email:", text_color=self.config["white_fore"], font=("Helvetica", 11)).grid(row=2, column=0, padx=10, pady=10, sticky='w')
        email_var = tk.StringVar(value=entry.get("email", ""))
        email_entry = ctk.CTkEntry(content_frame, textvariable=email_var, width=300, font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"])
        email_entry.grid(row=2, column=1, padx=10, pady=10, sticky='ew')

        ctk.CTkLabel(content_frame, text="Password:", text_color=self.config["white_fore"], font=("Helvetica", 11)).grid(row=3, column=0, padx=10, pady=10, sticky='w')
        password_var = tk.StringVar(value=entry["password"])
        password_frame = ctk.CTkFrame(content_frame, fg_color=self.config["bg_back"], bg_color=self.config["bg_back"])
        password_frame.grid(row=3, column=1, padx=10, pady=10, sticky='ew')

        password_entry = ctk.CTkEntry(password_frame, textvariable=password_var, width=250, show="•", font=("Helvetica", 11), fg_color=self.config["bg_fore"], text_color=self.config["white_fore"])
        password_entry.pack(side='left', fill='x', expand=True)

        def toggle_password_visibility():
            if password_entry.cget("show") == "•":
                password_entry.configure(show="")
                toggle_btn.configure(text="Hide")
            else:
                password_entry.configure(show="•")
                toggle_btn.configure(text="Show")

        toggle_btn = ctk.CTkButton(password_frame, text="Show", command=toggle_password_visibility, fg_color=self.config["bg_fore"], hover_color=self.config["bg_back"], width=80, font=("Helvetica", 11))
        toggle_btn.pack(side='right', padx=(5, 0))

        content_frame.columnconfigure(1, weight=1)

        btn_frame = ctk.CTkFrame(content_frame, fg_color=self.config["bg_back"], bg_color=self.config["bg_back"])
        btn_frame.grid(row=4, column=0, columnspan=2, pady=15)

        save_btn = ctk.CTkButton(btn_frame, text="Save", 
                                 command=lambda: self.save_edited_entry(
                                     dialog, index, identifier_var.get(), 
                                     username_var.get(), email_var.get(), password_var.get()
                                 ), fg_color=self.config["colorEdit"], hover_color=self.config["colorEditHover"], font=("Helvetica", 11))
        save_btn.pack(side='left', padx=5)
        cancel_btn = ctk.CTkButton(btn_frame, text="Cancel", command=dialog.destroy, fg_color=self.config["bg_fore"], hover_color=self.config["bg_back"], font=("Helvetica", 11))
        cancel_btn.pack(side='left', padx=5)

    def save_edited_entry(self, dialog, index, identifier, username, email, password):
        if not identifier or not password:
            messagebox.showwarning("Warning", "Website/App and password are required")
            return
        self.passwords[index]["identifier"] = identifier
        self.passwords[index]["username"] = username
        self.passwords[index]["email"] = email
        self.passwords[index]["password"] = password
        self.passwords[index]["date"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.save_data()
        dialog.destroy()
        # messagebox.showinfo("Success", "Entry updated successfully")

    def delete_selected_entry(self):
        selected = self.history_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No entry selected")
            return
        item_id = self.history_tree.item(selected[0])["values"][0]
        confirm = messagebox.askyesno("Confirm", "Are you sure you want to delete this entry?")
        if not confirm:
            return
        for i, entry in enumerate(self.passwords):
            if entry["id"] == item_id:
                del self.passwords[i]
                self.save_data()
                # messagebox.showinfo("Success", "Entry deleted successfully")
                return
        messagebox.showerror("Error", "Entry not found in database")

    def show_context_menu(self, event):
        selected = self.history_tree.selection()
        if selected:
            self.context_menu.post(event.x_root, event.y_root)

    def on_close(self):
        self.root.destroy()

def main():
    missing_modules = []
    try:
        import pyperclip
    except ImportError:
        missing_modules.append("pyperclip")
    try:
        import customtkinter
    except ImportError:
        missing_modules.append("customtkinter")
    try:
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    except ImportError:
        missing_modules.append("cryptography")
    try:
        from dotenv import load_dotenv
    except ImportError:
        missing_modules.append("python-dotenv")
    if missing_modules:
        print("Missing required modules. Please install:")
        for module in missing_modules:
            print(f"pip install {module}")
        input("Press Enter to exit...")
        return
    root = ctk.CTk()
    app = PasswordManager(root)
    root.mainloop()

if __name__ == "__main__":
    main()