# Local Password Manager

A secure, offline password manager built with Python and CustomTkinter, designed to store and manage passwords locally on your machine. It features a modern dark-themed UI inspired by PHP Switcher, strong encryption, and a configurable interface. The application auto-exits after a user-defined inactivity period to enhance security.

## Features

- **Password Generation**: Create strong, customizable passwords with options for length, character types (lowercase, uppercase, digits, special), and exclusion of similar characters.
- **Password Storage**: Store passwords locally in an encrypted file (`passwords.encrypted`) with Fernet (AES-128) encryption.
- **CSV Import/Export**: Import passwords from CSV files (e.g., Chrome exports) and export your vault for backups or other managers.
- **Search and Filter**: Search passwords by website, username, or email, and filter by creation date (today, last week, last month).
- **Modern UI**: Dark theme with PHP Switcher-inspired colors (`#383838`, `#303030`, `#0b4f16`), customizable via `config.json`.
- **Inactivity Timeout**: Automatically exits after a configurable period (default: 5 minutes) of no mouse/keyboard activity.
- **Secure Key Derivation**: Uses PBKDF2HMAC (SHA256, 100,000 iterations) with a random salt stored in `.env`.
- **Cross-Platform**: Runs on Windows (with Git Bash) and other platforms with Python 3.12.

## Prerequisites

- **Python 3.12**: Required for running the application.
- **Dependencies**:
  - `customtkinter`: Modern Tkinter widgets for the UI.
  - `pyperclip`: Clipboard functionality.
  - `cryptography`: Encryption and key derivation.
  - `python-dotenv`: Environment variable management.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone git@github.com:yourusername/password-manager.git
   cd password-manager


Install Python 3.12:

Download and install Python 3.12 from python.org.

Verify:
python3 --version

Should output Python 3.12.x.



Install Dependencies:
pip install -r requirements.txt

This installs customtkinter, pyperclip, cryptography, and python-dotenv.

Optional: Create a Desktop Shortcut (Windows):

Right-click on Desktop > New > Shortcut.

Set location:
"C:\Program Files\Git\bin\bash.exe" -c "/c/Users/Maged/Desktop/pass/run_pass.sh"


Name it Password Manager.

Adjust the path if your project is elsewhere.




Usage

Run the Application:
python mpass.py

or 

python3 mpass.py

Or double-click the desktop shortcut (Windows).

Set Up Master Password:

On first run, create a master password. This generates a random salt in .env and an encrypted vault (passwords.encrypted).
On subsequent runs, enter your master password to unlock the vault.


Key Features:

Generate Passwords: Use the "Password Generator" tab to create passwords, copy them, and save with website/username/email details.
View History: In the "Password History" tab, search, filter, copy, edit, or delete entries. Toggle password visibility with the "Show/Hide" button.
Import/Export: Use the "Import" tab to import from CSV (requires url, username, password columns) or export your vault to CSV.
Inactivity Timeout: The app exits after the configured inactivity period (default: 5 minutes, or 60 seconds in provided config.json).


Customize Configuration:

Edit config.json to tweak UI colors, font size, and inactivity timeout (see Configuration).



Configuration
The application is customizable via config.json. If missing or invalid, defaults are used. Example:
{
  "bg_fore": "#383838",
  "bg_back": "#303030",
  "white_fore": "white",
  "colorEdit": "#0b4f16",
  "colorEditHover": "#07330e",
  "fontSize": 30,
  "inactivityLimit": 60
}

Config Options

bg_fore: Background color for UI elements (hex, e.g., #383838).
bg_back: Window background color (hex, e.g., #303030).
white_fore: Text color (hex or "white").
colorEdit: Button color (hex, e.g., #0b4f16).
colorEditHover: Button hover color (hex, e.g., #07330e).
fontSize: Font size for UI (integer ≥ 10, default: 30).
inactivityLimit: Seconds of inactivity before auto-exit (integer ≥ 30, default: 300).

Validation

Colors must be valid hex (#RRGGBB) or "white" for white_fore.
fontSize must be ≥ 10 for readability.
inactivityLimit must be ≥ 30 seconds for usability.
Invalid or unknown keys trigger console warnings and fallback to defaults.


Contributing
Contributions are welcome! To contribute:

Fork the repository.
Create a branch (git checkout -b feature/your-feature).
Commit changes (git commit -m "Add your feature").
Push to branch (git push origin feature/your-feature).
Open a Pull Request.

Please include tests and update documentation for new features.
License
This project is licensed under the MIT License. See LICENSE for details.

Built with 💻 by MAGED. Star the repo if you find it useful! 🌟


