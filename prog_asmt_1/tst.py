'''
Programming assignment 1
'''

import os
import json
import base64
import hashlib
import hmac
import traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

VAULT_FILE = 'vault.json'

def load_vault():
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "r") as f:
        return json.load(f)
    
def save_vault(data):
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=4)



def load_vault():
    if not os.path.exists(VAULT_FILE):
        return {}
    with open(VAULT_FILE, "r") as f:
        return json.load(f)


def save_vault(data):
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=4)


def verify_user(username):
    '''
    lookup input username in the valult file, returns dictionary pointer to user_data
    '''

    try:
        with open(VAULT_FILE, 'r') as file:
            # Load existing data into a Python list or dictionary
            data = json.load(file)
        for user in data:
            if user.get("name") == username:
                return user

    except (FileNotFoundError, json.JSONDecodeError):
        # If the file doesn't exist or is empty, start with an empty list
        print("Error loading JSON Data from vault")

    return None


def verify_login(input_password, stored_salt_b64, hash_algo, stored_password_b64):
    """
    Verifies an input password against stored Base64 salt and password_hash.
    """

    # Decode the stored Base64 strings back into raw bytes
    salt = base64.b64decode(stored_salt_b64)
    password_hash = base64.b64decode(stored_password_b64)

    # Hash the new input password using the EXACT SAME salt
    password_bytes = input_password.encode('utf-8')
    if hash_algo == 'SHA256':
        hash_obj = hashlib.sha256(salt + password_bytes)
    elif hash_algo == 'MD5':
        hash_obj1 = hashlib.md5(salt + password_bytes).digest()
        # Extending 16-byte output of md5 to 32 bytes
        hash_obj = hashlib.md5(hash_obj1 + password_bytes)
    else:
        return False

    new_hash = hash_obj.digest()

    # Use a secure comparison to prevent timing attacks
    # This is more secure than a simple '==' check
    return hmac.compare_digest(new_hash, password_hash)


def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:

    # Create cipher with key and IV in CBC mode
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Apply PKCS#7 padding
    padded_data = pad(plaintext, 16)
    ciphertext = cipher.encrypt(padded_data)

    # Return Ciphertext, base64 encoded
    return base64.b64encode(ciphertext)


def decrypt_aes_cbc(encrypted_data: bytes, key: bytes, iv: bytes) -> bytes:

    ciphertext = base64.b64decode(encrypted_data)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt and remove padding
    decrypted_padded_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_padded_data, 16)


def register(username, passwd, hash_algo):
    '''
    User Registration: store user_data (username, salted password, hash_algorithm) in the vault file
    '''

    # new user data stored in dictionary form
    user_data = {}
    user_data['name'] = username

    # Generate 16 bytes of random data for the salt and store in base 64
    salt = os.urandom(16)
    b64_salt = base64.b64encode(salt).decode('utf-8')
    user_data['salt'] = b64_salt

    # Generate derived key as HASH(salt||password)
    password_bytes = passwd.encode('utf-8')
    if hash_algo == 'sha256':
        user_data['hash'] = "SHA256"
        # sha256 hash output (32 bytes)
        hash_obj = hashlib.sha256(salt + password_bytes)
    elif hash_algo == 'md5':
        user_data['hash'] = "MD5"
        hash_obj1 = hashlib.md5(salt + password_bytes).digest()
        # Extending 16-byte output of md5 to 32 bytes
        hash_obj = hashlib.md5(hash_obj1 + password_bytes)
    else:
        raise ValueError("Unsupported algorithm")

    # 32-byte derived key for AES
    derived_key = hash_obj.digest()
    b64_hash = base64.b64encode(derived_key).decode('utf-8')
    # need to store salted password for future verification
    user_data['passwd'] = b64_hash

    # Fetch list of users from the valut_file
    try:
        with open(VAULT_FILE, 'r') as file:
            # Load existing data into a Python list or dictionary
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        # If the file doesn't exist or is empty, start with an empty list
        data = []

    if isinstance(data, list):
        data.append(user_data)
    else:
        # Handle cases where the top-level structure is a dictionary if needed
        print("Cannot append to a non-list JSON structure.")

    # Write updated user data in the json file, will add adictionary item to the list structure in the vault
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


def store(username, passwd, message):
    '''
    Password-based Key Derivation and Encryption: verify user and generate derived key, IV and ciphertext 
    '''

    # retrieves user data (if exists) from the list of dictionaries stored in vault file
    found_user = verify_user(username)

    if found_user:

        data = load_vault()

        if verify_login(passwd, found_user['salt'], found_user['hash'], found_user['passwd']):

            # 16 bytes for AES block size
            iv = os.urandom(16)
            # decoding 32-byte derived key from salted password (encoded in base 64)
            aes_key = base64.b64decode(found_user['passwd'])

            # compute padded encryption in base64 encoding
            ciphertext = encrypt_aes_cbc(message, aes_key, iv)
            integrity_hash = hashlib.sha256(iv+ciphertext)

            # updating user data with the encrypted note
            for user in data:
                if user.get('name') == username:
                    user['iv'] = base64.b64encode(iv).decode('utf-8')
                    user['ciphertext'] = ciphertext.decode('utf-8')
                    user['integrity_hash'] = base64.b64encode(
                        integrity_hash.digest()).decode('utf-8')
            save_vault(data)

            print(f"Derived Key (first 16 bytes): {aes_key[:16].hex()}")
            print(f"IV: {iv.hex()}")
            print(f"Ciphertext: {ciphertext.decode('utf-8')}")
            print("Encrypted and Stored.")
        else:
            print("Invalid password")
    else:
        print("Invalid Username")

    pass


def is_tampered(iv, ciphertext, integrity_hash):
    '''
    to check if the note is tampered or not
    '''
    d_iv = base64.b64decode(iv.encode('utf-8'))
    e_ciphertext = ciphertext.encode('utf-8')
    n_integrity_hash = hashlib.sha256(d_iv+e_ciphertext)
    nd_integrity_hash = base64.b64encode(n_integrity_hash.digest()).decode('utf-8')
    if hmac.compare_digest(integrity_hash, nd_integrity_hash):
        return False  
    else:
        return True 


def read(username, password):
    '''
    function to read the user notes
    '''
    user_data = verify_user(username)
    if verify_user(username):
        if verify_login(password, user_data['salt'],user_data['hash'], user_data['passwd']):
            if user_data.get('ciphertext'):
                if not is_tampered(user_data['iv'], user_data['ciphertext'], user_data['integrity_hash']):
                    aes_key = base64.b64decode(user_data['passwd'])
                    message = decrypt_aes_cbc(user_data['ciphertext'], aes_key, base64.b64decode(user_data['iv'].encode('utf-8')))
                    print(f'Decrypted: {message.decode('utf-8')}')
                else:
                    print('Tampering detected!')
            else:
                print('Add note to view')
        else:
            print('Incorrect password')
    else:
        print(f'User - {username} not found.')


def tamper():
    '''
    Intentionally modify 1 byte of the ciphertext.
    '''

    username = input("Enter username: ")

    data = load_vault()

    user = verify_user(username)

    if not user:
        print("User not found.")
        return

    if 'ciphertext' not in user:
        print("No stored note found to tamper with.")
        return

    # Decode ciphertext from Base64 to raw
    ciphertext = base64.b64decode(user['ciphertext'])
    print(ciphertext)

    # Convert to mutable bytearray so we can modify it
    tampered = bytearray(ciphertext)
    print(tampered)

    # Flip one bit in the first byte
    tampered[0] ^= 1

    # Convert back to Base64
    tampered_b64 = base64.b64encode(bytes(tampered)).decode('utf-8')
    print(tampered_b64)

    # updating the user's ciphertext to tampered text
    for u in data:
        if u.get("name") == username:
            u["ciphertext"] = tampered_b64

    # Save modified vault
    save_vault(data)

    print("Ciphertext has been tampered")


def delete_user():
    vault = load_vault()

    username = input("Username to delete: ")

    if username in vault:
        del vault[username]
        save_vault(vault)
        print("User deleted.")
    else:
        print("User not found.")
    vault = load_vault()

    username = input("Username to delete: ")

# if username in vault:
#       del vault[username]
#       save_vault(vault)

    if verify_user(username):
        updated_data = [user for user in vault if user.get("name") != username]
        save_vault(updated_data)
        print("User deleted.")
    else:
        print("User not found.")


def main():
    '''
    main function
    '''
    selected_option = 1
    while (selected_option <= 6):
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

                username = input('Enter username: ')
                passwd = input('Enter password: ')
                hash_algo = input('Preferred Hash mode (md5/sha256): ')
                register(username, passwd, hash_algo)

            elif selected_option == 2:

                username = input('Enter username: ')
                passwd = input('Enter password: ')
                print('Enter note:')
                # converting input note into bytes for encryption
                message = input().encode('utf-8')
                store(username, passwd, message)

            elif selected_option == 3:
                username = input('Enter username: ')
                passwd = input('Enter password: ')
                read(username, passwd)
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
    print(traceback.format_exc())
