import sqlite3
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding,utils
from cryptography.fernet import Fernet
from CONSTANTS import *


def search_db(query):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    result = cursor.execute(query).fetchall()
    cursor.close()
    connection.close()
    return result


def add_user(username:str,user_public_key:str): 
    user_public_key = serialization.load_pem_public_key(user_public_key.encode())
    
    # encrypts the symmetric decryption key with the new users public key
    ENCRYPTED_SYMMETRIC_DECRYPTION_KEY = user_public_key.encrypt(
        RANDOM_KEY,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    to_insert = (username,user_public_key,ENCRYPTED_SYMMETRIC_DECRYPTION_KEY)

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute(f'INSERT INTO Users (USERNAME,PUBLIC_KEY,ENCRYPTED_SYMETRIC_DYCRYPTION_KEY) VALUES (?,?,?)',to_insert)
    connection.commit()



def remove_user(username:str):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute(f'DELETE FROM Users WHERE USERNAME = {username};')
    connection.commit()
    connection.close()
    _reset_keys()

def _reset_keys() -> None:
    # encrypts the random key with users public key
    def encrypt_random_key(user_public_key:bytes, random_key) -> bytes:
        user_public_key = serialization.load_pem_public_key(user_public_key.encode())
        return user_public_key.encrypt(
            random_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # generate new keys and write them to encrypted key file
    new_encryption_key = Fernet.generate_key()
    new_random_encryption_key = Fernet.generate_key()
    encrypted_encryption_key = Fernet(new_random_encryption_key).encrypt(new_encryption_key)
    with open(ENCRYPTED_KEY,'wb') as file:
        file.write(encrypted_encryption_key)

    # get all users and update their ENCRYPTED_SYMETRIC_DYCRYPTION_KEY in db
    users = search_db('SELECT * FROM USERS')
    for user in users:
        user[2] = encrypt_random_key(user[1],new_random_encryption_key)

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.executemany(f'INSERT INTO Users (USERNAME, PUBLIC_KEY, ENCRYPTED_SYMETRIC_DYCRYPTION_KEY) VALUES (?, ?, ?)',users)
    connection.commit()
    connection.close()
    

def sign_db_and_key(admin_private_key:str) -> None:
    with open(DB_PATH,'rb') as file:
        db_bytes = file.read()
    with open(ENCRYPTED_KEY,'rb') as file:
        key_bytes = file.read()

    admin_private_key = serialization.load_pem_private_key(admin_private_key.encode(),password=None)

    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(db_bytes)
    digest = hasher.finalize()

    db_sig = admin_private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )

    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(key_bytes)
    digest = hasher.finalize()

    key_sig = admin_private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(chosen_hash)
    )

    with open(ADMIN_DB_SIGNATURE,'wb') as file:
        file.write(db_sig)
    with open(ADMIN_KEY_SIGNATURE, 'wb') as file:
        file.read(key_sig)    
    
    return

