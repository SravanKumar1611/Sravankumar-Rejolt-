import getpass
import hashlib
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class PasswordManager:
    def __init__(self, master_password):
        self.master_password = master_password
        self.salt = os.urandom(16)
        self.kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        self.key = base64.urlsafe_b64encode(self.kdf.derive(self.master_password.encode()))
        self.fernet = Fernet(self.key)

    def add_entry(self, username, password):
        encrypted_password = self.fernet.encrypt(password.encode())
        with open("passwords.txt", "a") as f:
            f.write(f"{username}:{encrypted_password.decode()}\n")

    def get_entries(self):
        entries = []
        with open("passwords.txt", "r") as f:
            for line in f.readlines():
                username, encrypted_password = line.strip().split(":")
                decrypted_password = self.fernet.decrypt(encrypted_password.encode()).decode()
                entries.append((username, decrypted_password))
        return entries

    def delete_entry(self, username):
        with open("passwords.txt", "r") as f:
            lines = f.readlines()
        with open("passwords.txt", "w") as f:
            for line in lines:
                if not line.startswith(username + ":"):
                    f.write(line)

    def edit_entry(self, username, new_password):
        self.delete_entry(username)
        self.add_entry(username, new_password)

    def password_strength(self, password):
        if len(password) < 8:
            return "Weak"
        elif len(password) < 12:
            return "Medium"
        else:
            return "Strong"

def main():
    master_password = getpass.getpass("Enter master password: ")
    pm = PasswordManager(master_password)

    while True:
        print("1. Add entry")
        print("2. Get entries")
        print("3. Delete entry")
        print("4. Edit entry")
        print("5. Check password strength")
        print("6. Quit")
        choice = input("Choose an option: ")

        if choice == "1":
            username = input("Enter username: ")
            password = getpass.getpass("Enter password: ")
            pm.add_entry(username, password)
        elif choice == "2":
            for username, password in pm.get_entries():
                print(f"Username: {username}, Password: {password}")
        elif choice == "3":
            username = input("Enter username: ")
            pm.delete_entry(username)
        elif choice == "4":
            username = input("Enter username: ")
            new_password = getpass.getpass("Enter new password: ")
            pm.edit_entry(username, new_password)
        elif choice == "5":
            password = getpass.getpass("Enter password: ")
            print(pm.password_strength(password))
        elif choice == "6":
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()