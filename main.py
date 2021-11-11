################################# IMPORTS #####################################
import os
import cryptography
import json
from getpass import getpass
from helperFunctions import *

############################### PROGRAM LOGIC #################################
print("############################")
print("  Welcome to PasswordVault")
print("############################\n")
# check if file exists. If not, create it and encrypt it with a new master password
if not os.path.exists(FILE_PATH):
    while True:
        password = getpass("No passwords configuration file was found. Please enter a master password to create one: ")
        if (not IsStrongPassword(password)):
            print ("  Password is not strong enough")
            print ("  Must contain at least 8 characters and contain at least one of each of the following:")
            print ("  uppercase letter, lowercase letter, number, symbol")
        else:
            break
    open(FILE_PATH, 'w')
    EncryptAndWriteToFile(password, '[]')
# if file exists and is not empty, give user 3 attempts at master password
else:
    attempts = 0
    while (True):
        if attempts >= 3:
            print("Too many failed attempts. Goodbye")
            exit()
        try:
            attempts += 1
            password = getpass("Enter your master password to continue: ")
            DecryptFile(password)
            break
        except cryptography.fernet.InvalidToken:
            print("Password was incorrect, please try again")


# attempt to decrypt the file and deserialize JSON data
fileContents = DecryptFile(password)
data = json.loads(fileContents)

# MAIN LOOP: AN INTERACTIVE MENU THAT GIVES USER A CHOICE ON WHAT THEY WANT TO DO NEXT
while True:
    # Print choices for user to do
    menuMessage = (
        "\n[1] View existing passwords \n"
        "[2] Add new password \n"
        "[3] Remove password from list \n"
        "[4] Generate a secure password \n"
        "[5] Change master password \n"
        "[0] Quit \n"
        "Please enter a number to continue: ")

    # Get user input and ensure it is a valid number
    userChoice = GetIntegerFromUser(menuMessage, "Not a valid choice. Try again.", 0, 5)

    # Decide what to do based on user's input
    if (userChoice == 0):
        exit()

    elif (userChoice == 1):
        PrintPasswordJsonData(data)

    elif (userChoice == 2):
        # Add new password to data, then re-encrypt/decrypt the password file to save the changes
        AddPasswordToJsonData(data)
        EncryptAndWriteToFile(password, json.dumps(data, separators=(',', ':')))
        fileContents = DecryptFile(password)
        data = json.loads(fileContents)

    elif (userChoice == 3):
        RemovePasswordFromJsonData(data)
        EncryptAndWriteToFile(password, json.dumps(data, separators=(',', ':')))
        fileContents = DecryptFile(password)
        data = json.loads(fileContents)

    elif (userChoice == 4):
        generatedPassword = GenerateSecurePassword()
        print("Generated password: " + str(generatedPassword))

    elif (userChoice == 5):
        # Change the user's master password and re-encrypt/decrypt the file to save the changes
        newPassword = ChangeMasterPassword(password)
        password = newPassword
        EncryptAndWriteToFile(password, json.dumps(data, separators=(',', ':')))
        fileContents = DecryptFile(password)
        data = json.loads(fileContents)

    else:
        print("Not a valid choice. Try again.")
        continue
