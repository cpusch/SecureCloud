from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding,utils
from cryptography.fernet import Fernet
import os
from admin import search_db
from CONSTANTS import *

def valid_username(username:str) -> bool:
    if search_db(f"Select * from Users WHERE USERNAME = '{username}'") == []:
        return False
    return True

def _get_encryption_key(username:str, user_private_key:str):
    user_info = search_db(f"Select * from Users WHERE USERNAME = '{username}'")
    with open(ENCRYPTED_KEY,'rb') as file:
        encrypted_key = file.read()
    
    private_key = serialization.load_pem_private_key(user_private_key.encode(),password=None)
    random_key_bytes = private_key.decrypt(
        user_info[2],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # decrypt the random key from the database and then create the actual encryption/decryption key from encrypted_key.txt
    return Fernet(Fernet(random_key_bytes).decrypt(encrypted_key))

def upload_file(file_path:str,username:str,user_private_key:str):
    encryption_key = _get_encryption_key(username,user_private_key)

    with open(file_path,'rb') as file:
        file_to_upload = file.read()
    encrypted_file = encryption_key.encrypt(file_to_upload)

    filename = file_path.split('/')[-1].split('.')[0]
    file_extension = file_path.split('/')[-1].split('.')[1]
    with open(f'./uploads/{filename}[ENCRYPTED].{file_extension}') as file:
        file.write(encrypted_file)

def download_file(filename,username:str,user_private_key:str):
    encryption_key = _get_encryption_key(username, user_private_key)

    with open(f'./uploads/{filename}','rb') as file:
        encrypted_file = file.read()
    
    decrypted_file = encryption_key.decrypt(encrypted_file)

    with open(f'./downloads/{filename}','wb') as file:
        file.write(decrypted_file)
