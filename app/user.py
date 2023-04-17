from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding,utils
from cryptography.fernet import Fernet
from admin import search_db
from CONSTANTS import *

def valid_username(username:str) -> bool:
    """
    Checks if username exists in database. Returns true if it does 
    """
    if search_db(f"Select * from Users WHERE USERNAME = '{username}'") == []:
        return False
    return True

def _get_encryption_key(username:str, user_private_key:str):
    """
    Decrypts the encrypted random key associated with the user. 
    """
    user_info = search_db(f"Select * from Users WHERE USERNAME = '{username}'")
    with open(ENCRYPTED_KEY,'rb') as file:
        encrypted_key = file.read()
    
    # using inputed private key, decrypts the random key which will then be used to obtain the encryption key
    private_key = serialization.load_pem_private_key(user_private_key.encode(),password=None)
    random_key_bytes = private_key.decrypt(
        user_info[0][2],
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # decrypt the random key from the database and then create the actual encryption/decryption key from encrypted_key.txt
    return Fernet(random_key_bytes).decrypt(encrypted_key)

def upload_file(file_path:str,username:str,user_private_key:str):
    """
    Given a file path takes that file and encrypts it to be uploaded to secure cloud. 
    """
    encryption_key = _get_encryption_key(username,user_private_key)

    # encrypts file with symmetric encryption key
    with open(file_path,'rb') as file:
        file_to_upload = file.read()
    encrypted_file = Fernet(encryption_key).encrypt(file_to_upload)

    # extracts file name then 'uploads'
    filename = file_path.split("\\")[-1].split('.')[0]
    file_extension = file_path.split('\\')[-1].split('.')[1]
    with open(f'./uploads/{filename}[ENCRYPTED].{file_extension}','wb') as file:
        file.write(encrypted_file)

def download_file(filename,username:str,user_private_key:str):
    """
    Given a file name and user private key downloads file and decrypts it
    """
    encryption_key = _get_encryption_key(username, user_private_key)

    with open(f'./uploads/{filename}','rb') as file:
        encrypted_file = file.read()
    
    decrypted_file = Fernet(encryption_key).decrypt(encrypted_file)

    with open(f"./downloads/{filename.replace('[ENCRYPTED]','')}",'wb') as file:
        file.write(decrypted_file)
