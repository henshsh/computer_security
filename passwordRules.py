import os
import re
#define the ini file's parameters
"""
passwordLength:int=None
complexedPassword:list=None
history:int=None
dictionary:list=None
loginTries:int=None
"""

smallLetter=r'^[a-z]+$'
capitalLetter=r'^[A-Z]+$'
digit=r'^[0-9]+$'
special=r'[!@#$%^&*()_+={}\[\]|\\:;\"\'<>,.?/]'



#a function that initializes the parameters of the ini file
def parse_ini_file():
    passwordLength: int = None
    complexedPassword: list = None
    history: int = None
    dictionary: list = None
    loginTries: int = None

    ini_file_path = "PasswordRules.ini"

    with open(ini_file_path, 'r') as file:
        for line in file:
            if '=' in line:
                key, value = line.strip().split('=', 1)
                key = key.strip()
                value = value.strip()

                if key == "passwordLength":
                    passwordLength = int(value)
                elif key == "complexedPassword":
                    complexedPassword = value[1:-1].split(',')
                    complexedPassword = [item.strip() for item in complexedPassword]
                elif key == "history":
                    history = int(value)
                elif key == "dictionary":
                    dictionary = value[1:-1].split(',')
                    dictionary = [item.strip().strip('"') for item in dictionary]
                elif key == "loginTries":
                    loginTries = int(value)

    return passwordLength, complexedPassword, history, dictionary, loginTries


# Example usage:
password_length, complexed_password, history, dictionary, login_tries = parse_ini_file()

print("Password Length:", password_length)
print("Complexed Password:", complexed_password)
print("History:", history)
print("Dictionary:", dictionary)
print("Login Tries:", login_tries)

def contains_special(password):
    # Use re.search to check if there is at least one special letter
    return bool(re.search(special, password))

def contains_digit(password):
    # Use re.search to check if there is at least one digit letter
    return bool(re.search(digit, password))

def contains_capital_letter(password):
    # Use re.search to check if there is at least one capital letter
    return bool(re.search(capitalLetter, password))

def contains_small_letter(password):
    # Use re.search to check if there is at least one lowercase letter
    return bool(re.search(smallLetter, password))

#to re-define it when we
"""
#defining counter and getting the number of tries that we have
global counterLoginTries
counterLoginTries=login_tries
# if the counter is 0, we return false
    # we must here to refresh the page or something+alerting the user that he tried to sign up too many times
    if (counterLoginTries == 0):
        return False
    #decrementing by one the counter
    counterLoginTries-=1
"""

def check_history(password):
    # Read the file and get the last `history_count` lines
    with open('historyPasswords.ini', 'r') as file:
        lines = file.readlines()
        # Get the last `history` lines
        recent_passwords = [line.strip() for line in lines[-history:]]
        # Check if the new password is in the recent passwords
        if password in recent_passwords:
            return False  # Password was found in the recent history
        return True  # Password was not found in the recent history

def validate_password(password):
    # Check if the password length is at least password_length
    if len(password) <= password_length:
        return False
    #check if the password appears in the dictionary (banned words)
    if password in dictionary:
        return False
    #in case the complex password in .ini file contains smallLetter, capitalLetter, digit, special we call the function that checks if it fills the condition.
    #if it returns false, we return false. otherwise we continue checking
    if 'smallLetter' in complexed_password:
        if contains_small_letter(password)==False:
            return False
        if 'capitalLetter' in complexed_password:
            if contains_capital_letter(password) == False:
                return False
        if 'digit' in complexed_password:
            if contains_digit(password)==False:
                return False
        if 'special' in complexed_password:
            if contains_special(password)==False:
                return False






