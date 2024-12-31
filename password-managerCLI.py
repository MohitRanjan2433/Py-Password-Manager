import os
import json
from cryptography.fernet import Fernet
import hashlib
import getpass

# Function to load the key
def load_key():
    return open("key.key", "rb").read()

# Function to encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

# Function to decrypt data
def decrypt_data(data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(data.encode())
    return decrypted.decode()

# Function to generate a key (run only once)
def generate_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

# Function to hash the master password
def hash_master_password(master_password):
    return hashlib.sha256(master_password.encode()).hexdigest()

# Initialize password manager
def initialize():
    if not os.path.exists("key.key"):
        print("Initializing password manager...")
        generate_key()

        # Initialize the passwords.json with an empty dictionary, encrypted
        key = load_key()
        empty_data = {}
        encrypted_data = encrypt_data(json.dumps(empty_data), key)

        with open("passwords.json", "w") as file:
            json.dump({"passwords": encrypted_data.decode()}, file)

        # Ask for a master password and store its hash in a file
        master_password = getpass.getpass("Set your master password: ").strip()
        master_password_hash = hash_master_password(master_password)

        with open("master_password.hash", "w") as file:
            file.write(master_password_hash)

        print("Password manager initialized successfully!")
    else:
        print("Password manager already initialized.")

# Check if the master password is correct
def verify_master_password(master_password):
    try:
        with open("master_password.hash", "r") as file:
            stored_hash = file.read().strip()
        return stored_hash == hash_master_password(master_password)
    except Exception as e:
        print(f"Error verifying master password: {e}")
        return False

# Example usage: save a password
def save_password(master_password, website, password):
    if not verify_master_password(master_password):
        print("Incorrect master password. Operation aborted.")
        return

    key = load_key()
    try:
        # Load existing passwords and decrypt them
        with open("passwords.json", "r") as file:
            data = json.load(file)
        decrypted_data = json.loads(decrypt_data(data["passwords"], key))

        # Add the new website and password to the decrypted data
        decrypted_data[website] = password

        # Encrypt the updated data and save it back to passwords.json
        encrypted_data = encrypt_data(json.dumps(decrypted_data), key)
        with open("passwords.json", "w") as file:
            json.dump({"passwords": encrypted_data.decode()}, file)

        print(f"Password for {website} saved successfully!")
    except Exception as e:
        print(f"Error saving password: {e}")

# Retrieve a password for a website
def get_password(master_password, website):
    if not verify_master_password(master_password):
        print("Incorrect master password. Operation aborted.")
        return

    key = load_key()
    try:
        with open("passwords.json", "r") as file:
            data = json.load(file)
        decrypted_data = json.loads(decrypt_data(data["passwords"], key))

        if website in decrypted_data:
            print(f"Password for {website}: {decrypted_data[website]}")
        else:
            print(f"No password found for {website}.")
    except Exception as e:
        print(f"Error retrieving password: {e}")

# Change the master password
def change_master_password(old_password, new_password):
    if not verify_master_password(old_password):
        print("Incorrect master password. Operation aborted.")
        return

    key = load_key()
    try:
        with open("passwords.json", "r") as file:
            data = json.load(file)
        decrypted_data = json.loads(decrypt_data(data["passwords"], key))

        # Generate new encryption key
        new_key = Fernet.generate_key()
        encrypted_data = encrypt_data(json.dumps(decrypted_data), new_key)

        with open("key.key", "wb") as key_file:
            key_file.write(new_key)

        # Save the new master password hash
        new_master_password_hash = hash_master_password(new_password)
        with open("master_password.hash", "w") as file:
            file.write(new_master_password_hash)

        with open("passwords.json", "w") as file:
            json.dump({"passwords": encrypted_data.decode()}, file)

        print("Master password changed successfully!")
    except Exception as e:
        print(f"Error changing master password: {e}")

# Main CLI loop
def main():
    initialize()
    while True:
        print("\nPassword Manager CLI")
        print("1. Save Password")
        print("2. Get Password")
        print("3. Change Master Password")
        print("4. Exit")

        choice = input("Enter your choice: ").strip()
        if choice == "1":
            website = input("Enter website: ").strip()
            password = getpass.getpass("Enter password: ").strip()
            master_password = getpass.getpass("Enter master password: ").strip()
            save_password(master_password, website, password)
        elif choice == "2":
            website = input("Enter website: ").strip()
            master_password = getpass.getpass("Enter master password: ").strip()
            get_password(master_password, website)
        elif choice == "3":
            old_password = getpass.getpass("Enter old master password: ").strip()
            new_password = getpass.getpass("Enter new master password: ").strip()
            change_master_password(old_password, new_password)
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
