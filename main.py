################################# TODO List ###################################
# Change helper functions to be a Vault class
# Set more secure permissions on the file (read and write by user only)
# Do not allow user to create weak master password
# Figure out how to not show password in console as user is typing it
# Create main-loop menu that gives user the option of what to do
###############################################################################

################################# IMPORTS #####################################
import os
from pathlib import Path
import cryptography
from helperFunctions import *

############################# GLOBAL VARIABLES ################################
FILE_NAME = ".passwordVault"
FILE_PATH = os.path.join(Path.home(), FILE_NAME)

############################### PROGRAM LOGIC #################################
# check if file exists. If not, create it and encrypt it with a new master password
if not os.path.exists(FILE_PATH):
    password = input("No passwords configuration file was found. Please enter a master password to create one: ")
    open(FILE_PATH, 'w')
    EncryptAndWriteToFile(FILE_PATH, password, "{}")
# if file exists and is not empty, give user 3 attempts at master password
else:
    attempts = 0
    while (True):
        if attempts >= 3:
            print("Too many failed attempts. Goodbye")
            exit()
        try:
            attempts += 1
            password = input("Enter your master password: ")
            DecryptFile(FILE_PATH, password)
            break
        except cryptography.fernet.InvalidToken:
            print("Password was incorrect, please try again")


# attempt to decrypt the file using the user's master password
data = DecryptFile(FILE_PATH, password)
print(data)


# MAIN LOOP: AN INTERACTIVE MENU THAT GIVES USER A CHOICE ON WHAT THEY WANT TO DO NEXT


################################# CLEAN UP ####################################
