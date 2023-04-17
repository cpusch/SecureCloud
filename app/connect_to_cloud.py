from CONSTANTS import *
from cryptography.hazmat.primitives import serialization,hashes
from cryptography.hazmat.primitives.asymmetric import padding,utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend

def _download_assets():
    """
    Downloads the files necessary for signature verification and the latest database. 
    """
    return True

def upload_file(filename:str):
    return True

def download_file(filename:str):
    return True

def list_files():
    return True


def download_assets_and_verify(admin_public_key: str) -> bool:
    """
    Verifies the downloaded auth files with the admins public key
    """
    _download_assets()

    admin_public_key = serialization.load_pem_public_key(admin_public_key.encode(),backend=default_backend())
    with open(ADMIN_DB_SIGNATURE,'rb') as file:
        db_signature = file.read()
    with open(ADMIN_KEY_SIGNATURE, 'rb') as file:
        key_signature = file.read()
    with open(DB_PATH,'rb') as file:
        db_bytes = file.read()
    with open(ENCRYPTED_KEY,'rb') as file:
        key_bytes = file.read()
    
    try: 
        chosen_hash = hashes.SHA256()
        hasher = hashes.Hash(chosen_hash)
        hasher.update(db_bytes)
        digest = hasher.finalize()
        admin_public_key.verify(
            db_signature,
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
        admin_public_key.verify(
            key_signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(chosen_hash)
        )

        return True
    except InvalidSignature:
        return False
