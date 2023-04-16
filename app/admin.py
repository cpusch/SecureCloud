import sqlite3
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding
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

def remove_user(username,):
    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute(f'DELETE FROM Users WHERE USERNAME = {username};')
    connection.commit()

def _reset_keys(admin_private_key:str):
    return

