import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

BYTE_ENCODING = 'utf-8'
SALT_SIZE = 16
HASH_ITERATIONS = 1000000

############################## HELPER FUNCTIONS ###############################
def EncryptAndWriteToFile(path, password, dataToEncrypt):
    # generate a new salt that will be used to hash and encrypt the file
    salt = os.urandom(SALT_SIZE)

    # encrypt the data using the salt and password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=HASH_ITERATIONS,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode(BYTE_ENCODING)))
    fernet = Fernet(key)
    encryptedData = fernet.encrypt(dataToEncrypt.encode(BYTE_ENCODING))

    # write new salt and encrypted data to file
    with open(path, "wb") as fileHandle:
        fileHandle.write(salt + encryptedData)

def DecryptFile(path, password):
    with open(path, "rb") as fileHandle:
        fileContents = fileHandle.read()

        # get salt from encrypted file
        salt = fileContents[0:SALT_SIZE]

        # get encrypted data from file
        cipher = fileContents[SALT_SIZE:]

        # decrypt the data and return it
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=HASH_ITERATIONS,
            backend=default_backend(),
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode(BYTE_ENCODING)))
        fernet = Fernet(key)
        data = fernet.decrypt(cipher)
        return data.decode(BYTE_ENCODING)
