import base64
import os
import string
import secrets
from pathlib import Path
from getpass import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

############################# GLOBAL VARIABLES ################################
FILE_NAME = ".passwordVault"
FILE_PATH = os.path.join(Path.home(), FILE_NAME)
BYTE_ENCODING = 'utf-8'
SALT_SIZE = 16
HASH_ITERATIONS = 1000000

############################## HELPER FUNCTIONS ###############################

# Encrypts data using the password and writes it to a file. The file will contain 
#   The salt used for hashing appended to the start of the encrypted data.
# Takes in a file path, password, and data to be encrypted
def EncryptAndWriteToFile(password, dataToEncrypt):
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
    with open(FILE_PATH, "wb") as fileHandle:
        fileHandle.write(salt + encryptedData)

# Decrypts a file using a password. Will throw an error if the password is incorrect
# Takes in a file path and a password to use for decryption
def DecryptFile(password):
    with open(FILE_PATH, "rb") as fileHandle:
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

# Prints a message asking for user input. Reprints message until user provides 
#   a number between min and max inclusive
def GetIntegerFromUser(inputMessage, errorMessage, min, max):
    while True:
        try:
            userChoice = int(input(inputMessage))
            if (userChoice < min or userChoice > max):
                print(errorMessage)
            else:
                return userChoice
        except ValueError:
            print(errorMessage)
            continue

# Returns True if the password is strong, False if not.
# Passwords must be at least 8 characters in length and contain an upper case letter,
#   lowercase letter, number, and symbol
def IsStrongPassword(password):
    specialChars = string.punctuation
    numbers = string.digits
    # check length
    if (len(password) < 8):
        return False

    # check for uppercase, lowercase, special character, and number
    containsUpper = False
    containsLower = False
    containsSpecial = False
    containsNumber = False
    for char in password:
        if char.isupper():
            containsUpper = True
        if char.islower():
            containsLower = True
        if char in specialChars:
            containsSpecial = True
        if char in numbers:
            containsNumber = True
    
    if (not containsNumber or not containsSpecial or not containsUpper or not containsLower):
        return False
    else:
        return True

# Prints the password file's JSON data in a format that is viewable to the user
def PrintPasswordJsonData(data):
    try:
        print ("\nAll Passwords in Vault:")
        for obj in data:
            print ("Account: " + str(obj["accountName"]))
            print ("  Username: " + str(obj["username"]))
            print ("  Password: " + str(obj["password"]) + "\n")
    except:
        print("PasswordVault file has been corrupted. It will be deleted. Please rerun the program")
        if (os.path.isfile(FILE_PATH)):
            os.remove(FILE_PATH)
        exit()

# Promps the user to enter an account name, username, and gives the choice between entering a password or generating one
def AddPasswordToJsonData(data):
    accountName = input("What would you like to name this account? ")
    username = input("What is your username for this account? ")
    # Ask user if they want to generate a secure password
    while True:
        generate = input("Would you like to generate a secure password for this account? (y/n): ")
        if (generate.strip().lower() != 'y' and generate.strip().lower() != 'n'):
            print("Invalid choice")
        else:
            break
    # If yes, generate a password
    if (generate.strip().lower() == 'y'):
        password = GenerateSecurePassword()
        print("generated password: " + str(password))
    # If not, ask them to enter one
    else:
        while True:
            password = input("What is your password for this account? ")
            if (not IsStrongPassword(password)):
                print("Password is not strong (should contain at least 8 characters, an uppercase letter, lowercase letter, number, and symbol")
                while True:
                    useWeakPassword = input("Would you like to store this password anyway? (y/n): ")
                    if (generate.strip().lower() != 'y' and generate.strip().lower() != 'n'):
                        print("Invalid choice")
                    else:
                        break
                if useWeakPassword:
                    break
            else:
                break

    # Add the username/password combination to the JSON data
    data.append({
        "accountName": accountName,
        "username": username,
        "password": password,
    })

# Prompts the user on which account they want to delete, then deletes it
def RemovePasswordFromJsonData(data):
    PrintPasswordJsonData(data)
    while True:
        userChoice = input("Please enter the name of the account you want to remove (or 'quit' to go back to menu): ")
        if (userChoice.strip().lower() == 'quit'):
            return
        for obj in list(data):
            if (obj["accountName"].strip().lower() == userChoice.strip().lower()):
                data.remove(obj)
                return
        print("Invalid account name, please try again")

# Generates a secure password of a specified length provided by the user
def GenerateSecurePassword():
    length = GetIntegerFromUser("Input desired password length: ", "length must be between 8 and 64", 8, 64)
    allowedChars = string.ascii_letters + string.punctuation + string.digits
    return ''.join(secrets.choice(allowedChars) for _ in range(length))

# Prompts the user to enter their current password, followed by a new password
# New passwords are enforced by IsStrongPassword() function
def ChangeMasterPassword(oldPassword):
    while True:
        checkOldPassword = getpass("Please enter your current password: ")
        if (checkOldPassword != oldPassword):
            print ("  Incorrect, please try again")
        else:
            break
    
    while True:
        newPassword = getpass("Please enter your new master password: ")
        if (not IsStrongPassword(newPassword)):
            print ("  Password is not strong enough")
            print ("  Must contain at least 8 characters and contain at least one of each of the following:")
            print ("  uppercase letter, lowercase letter, number, symbol")
        else:
            confirmNewPassword = getpass("Re-enter new master password: ")
            if (newPassword != confirmNewPassword):
                print ("Passwords did not match, please retry")
                continue
            else:
                return newPassword