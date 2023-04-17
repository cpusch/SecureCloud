from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from admin import add_user, remove_user,sign_db_and_key
from connect_to_cloud import download_assets_and_verify
from user import valid_username,upload_file,download_file
import sys

def generate_key_pair() -> tuple:
    """
    Creates a simple public/private key pair for someone to store somewhere securely
    """
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return (private_key_bytes,public_key_bytes)    

def get_input() -> str:
    """
    Allows for multiple line input to command line to allow for pasting in keys
    """
    input_lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        else:
            input_lines.append(line.strip())
    return '\n'.join(input_lines)

def main():
    print("Welcome to the Secure Cloud!")
    print("Please enter the admins public key to verify files: ")

    admin_public_key = get_input()
    # validates the key containing files with the admin signatures to verify no tampering
    if download_assets_and_verify(admin_public_key):
        print("\n\nFILES VALIDATED\n")
        while True:
            print("""
Please Choose a following Option (You can type 'home' at any time to return to this prompt or 'quit' to exit): 

1. Generate a key pair
2. Upload a File
3. Download a File
4. Admin
        """)
            user_selection = input("Select 1,2,3, or 4: ")

            if user_selection == '1':
                key_pair = generate_key_pair()
                print("Here is your private/public key pair. Keep your private key safe!\n")
                print(f"{key_pair[0].decode()}\n")
                print(f"{key_pair[1].decode()}\n")

            elif user_selection == '2':
                file_path = input("\n Please Enter the full path of the file you would like to upload: ")
                username = input("Please enter your username: ")
                if valid_username(username):
                    print("Please enter your private key: ")
                    user_private_key = get_input()
                    upload_file(file_path,username,user_private_key)
                    print("\n\n FILES UPLOADED")
                else: 
                    print("Invalid Username\n")
                    

            elif user_selection == '3':
                file_name = input("\n Please enter the file name you would like to download: ")
                username = input("Please enter your username: ")
                if valid_username(username):
                    print("Please enter your private key: ")
                    user_private_key = get_input()
                    download_file(file_name, username, user_private_key)
                    print("\n\nFile Downloaded")
                else: 
                    print("Invalid Username")

            elif user_selection == '4':
                print("\nPlease enter the admin private key: ")
                admin_private_key = get_input()
                while True:
                    add_or_remove = input("\nWould you like to 'add' or 'remove' a user? ").lower()
                    if add_or_remove == 'add':
                        username = input("Username: ")
                        print("Public Key")
                        user_public_key = get_input()
                        add_user(username, user_public_key,admin_private_key)
                        sign_db_and_key(admin_private_key)
                    elif add_or_remove == 'remove':
                        username = input("Username: ")
                        remove_user(username)
                        sign_db_and_key(admin_private_key)
                        
                    elif add_or_remove == 'home':
                        break
                    else:
                        print("Please enter a valid prompt")
            elif user_selection == 'quit':
                break
    else: 
        print("Files not signed by admin. ")

if __name__ == "__main__":
    main()