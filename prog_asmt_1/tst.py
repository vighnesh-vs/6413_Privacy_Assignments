'''
Programming assignment 1
'''

import os
import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

VAULT_FILE = 'vault.json'

def register(username, passwd, hash_algo):
    '''
    store user_data (username, salted password, hash_algorithm) in the vault file
    '''
    user_data = {}
    user_data['name'] = username

    # Generate 16 bytes of random data for the salt and store in base 64
    salt = os.urandom(16)
    b64_salt = base64.b64encode(salt).decode('utf-8')
    user_data['salt'] = b64_salt

    if hash_algo == 'sha256':
        user_data['hash'] = "SHA256"
    elif hash_algo == 'md5':
        user_data['hash'] = "MD5"
    else:
        raise ValueError("Unsupported algorithm")

    try:
        with open(VAULT_FILE, 'r') as file:
        # Load existing data into a Python list or dictionary
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        # If the file doesn't exist or is empty, start with an empty list
        data = []
    
    data.update(user_data)  
    # NOTE: this rewrites data in the json file, need to add to existing data

    try:
        # Open the vault file in write mode
        with open(VAULT_FILE, 'w') as json_file:
            # Use json.dump() to write the dictionary to the file
            # The 'indent=4' parameter makes the file human-readable
            json.dump(data, json_file, indent=4)
            print(f"Generated Salt: {b64_salt}")
        print(f"Successfully registered user {username}")

    except IOError as e:
        print(f"Error writing to file: {e}")

    pass


def store():
    '''
    '''
    pass


def read():
    '''
    '''
    pass


def tamper():
    '''
    '''
    pass


def delete_user():
    '''
    '''
    pass


def main():
    '''
    main function
    '''
    print('1.Register\n2.Store\n3.Read\n4.Tamper\n5.DeleteUser\n6.Exit')
    inpt = input()

    try:
        selected_option = int(inpt.strip())
    except Exception as e:
        raise Exception('Error, not a number, try again, enter a number...')

    if selected_option < 1 or selected_option > 6:
        print('Error, enter correct option...\n')
        main()

    else:
        if selected_option == 1:

            print('Enter username:')
            username = input()
            print('Enter password:')
            passwd = input()
            print('Preferred Hash mode (md5/sha256):')
            hash_algo = input()
            register(username, passwd, hash_algo)

        elif selected_option == 2:
            store()

        elif selected_option == 3:
            read()
        elif selected_option == 4:
            tamper()
        elif selected_option == 5:
            delete_user()
        elif selected_option == 6:
            exit()


try:
    if __name__ == '__main__':
        main()
except Exception as e:
    print(f'Error - {e}')
