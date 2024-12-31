# Password Manager CLI (Python)

A simple command-line interface (CLI) password manager written in Python. This tool allows you to securely store, retrieve, and manage passwords for different websites. The passwords are encrypted using the `cryptography.fernet` library for secure storage, and all data is protected by a master password.

## Features

- **Master Password**: Set and change a master password to encrypt your passwords.
- **Password Storage**: Securely store website passwords using encryption.
- **Password Retrieval**: Retrieve stored passwords for different websites.
- **Master Password Change**: Change your master password securely.

## Prerequisites

- Python 3.7 or later
- `cryptography` package (for encryption)

## Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/your-username/password-manager-cli.git
    ```

2. Install the required dependencies:
    ```bash
    pip install cryptography
    ```

## Usage

### Initialize the Password Manager
The first time you run the program, it will ask you to set a master password and initialize the password storage.

```bash
python password_manager.py
