'''Develop a password manager with strong encryption.'''

from cryptography.fernet import Fernet
import getpass
import random
import string

# Database schema
class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.passwords = {}

# Password encryption and decryption
class PasswordManager:
    def __init__(self):
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def encrypt_password(self, password):
        return self.cipher_suite.encrypt(password.encode())

    def decrypt_password(self, encrypted_password):
        return self.cipher_suite.decrypt(encrypted_password).decode()

# Password generator
def generate_password(length=12):
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

# Password strength checker
def check_password_strength(password):
    if len(password) < 8:
        return "Weak"
    elif any(char.isdigit() for char in password) and any(char.isalpha() for char in password):
        return "Strong"
    else:
        return "Medium"

# User interaction
def main():
    password_manager = PasswordManager()
    username = input("Enter your username : ")
    password = getpass.getpass("Enter your password : ")
    user = User(username, password_manager.encrypt_password(password))

    while True:
        print("\n1. Store a password")
        print("2. Retrieve a password")
        print("3. Generate a password")
        print("4. Check password strength")
        print("5. Exit")
        choice = int(input("Enter your choice : "))

        if choice == 1:
            service = input("Enter the name of the service : ")
            service_password = getpass.getpass("Enter the password for the service : ")
            user.passwords[service] = password_manager.encrypt_password(service_password)
        elif choice == 2:
            service = input("Enter the name of the service : ")
            if service in user.passwords:
                print("Password : ", password_manager.decrypt_password(user.passwords[service]))
            else:
                print("No password stored for this service.")
        elif choice == 3:
            length = int(input("Enter the desired length of the password : "))
            print("Generated password : ", generate_password(length))
        elif choice == 4:
            password_to_check = getpass.getpass("Enter the password to check : ")
            print("Password strength : ", check_password_strength(password_to_check))
        elif choice == 5:
            break

if __name__ == "__main__":
    main()
