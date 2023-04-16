from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def generate_key_pair() -> tuple:
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


def main():
    print("Welcome to the Secure Cloud!")
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
            upload_file()
        elif user_selection == '3':
            download_file()
        elif user_selection == '4':
            while True:
                add_or_remove = input("\nWould you like to 'add' or 'remove' a user? ").lower()
                if add_or_remove == 'add':
                    username = input("Username: ")
                    user_public_key = input("Public Key: ")
                    add_user(username, user_public_key)
                elif add_or_remove == 'remove':
                    remove_user()
                elif add_or_remove == 'home':
                    break
                else:
                    print("Please enter a valid prompt")


if __name__ == "__main__":
    main()