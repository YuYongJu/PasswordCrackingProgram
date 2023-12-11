
import sys
import hashlib
import itertools
import string
from argparse import ArgumentParser

# Function to load a dataset of common passwords
def load_common_passwords(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read().splitlines()
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        sys.exit(1)

# Function for brute force password cracking
def brute_force_crack(hash_value, hash_type, length, charset):
    for guess in itertools.product(charset, repeat=length):
        guess = ''.join(guess)
        if hash_function(guess, hash_type) == hash_value:
            return guess
    return None

# Function for dictionary attack password cracking
def dictionary_attack(hash_value, hash_type, passwords):
    for password in passwords:
        if hash_function(password, hash_type) == hash_value:
            return password
    return None

# Function to hash a password
def hash_function(password, hash_type):
    if hash_type == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif hash_type == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif hash_type == 'bcrypt':
        import bcrypt
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    else:
        raise ValueError("Unsupported hash type")

# Main function
def main():
    parser = ArgumentParser(description="Password Cracker")
    parser.add_argument("-t", "--type", choices=["md5", "sha256", "bcrypt"], required=True, help="Hash type (md5, sha256, bcrypt)")
    parser.add_argument("-v", "--value", required=True, help="Hash value to crack")
    parser.add_argument("-m", "--mode", choices=["brute", "dictionary"], required=True, help="Mode of attack (brute or dictionary)")
    parser.add_argument("-f", "--file", help="File path for dictionary attack")
    args = parser.parse_args()

    if args.mode == 'brute':
        charset = string.ascii_lowercase + string.digits  # Can be expanded
        for length in range(1, 6):  # Example length range
            result = brute_force_crack(args.value, args.type, length, charset)
            if result:
                print(f"Password found: {result}")
                return
        print("Password not found")
    elif args.mode == 'dictionary':
        if not args.file:
            print("File path required for dictionary attack")
            sys.exit(1)
        common_passwords = load_common_passwords(args.file)
        result = dictionary_attack(args.value, args.type, common_passwords)
        if result:
            print(f"Password found: {result}")
        else:
            print("Password not found")

if __name__ == "__main__":
    main()

import json
import os

# Function to generate a simple Rainbow Table (conceptual demonstration)
def create_rainbow_table(charset, length, hash_type, file_path):
    rainbow_table = {}
    for guess in itertools.product(charset, repeat=length):
        guess = ''.join(guess)
        hashed = hash_function(guess, hash_type)
        rainbow_table[hashed] = guess

    with open(file_path, 'w') as file:
        json.dump(rainbow_table, file)

# Function to use the Rainbow Table for cracking
def use_rainbow_table(hash_value, file_path):
    try:
        with open(file_path, 'r') as file:
            rainbow_table = json.load(file)
        return rainbow_table.get(hash_value, None)
    except FileNotFoundError:
        print(f"Rainbow Table file not found: {file_path}")
        return None

# Function to simulate salting and storing hashes (file-based)
def salt_and_store(passwords, salt, hash_type, file_path):
    salted_hashes = {hash_function(p + salt, hash_type): p for p in passwords}
    with open(file_path, 'w') as file:
        json.dump(salted_hashes, file)

# Enhancing the main function to include new features
def main():
    # Existing argument parser code...
    
    parser.add_argument("-r", "--rainbow", help="Path to Rainbow Table file")
    parser.add_argument("-s", "--salt", help="Salt to use for hashing")
    parser.add_argument("-d", "--database", help="Path to database file for storing hashes")
    args = parser.parse_args()

    # Handling new features based on command line arguments
    if args.rainbow:
        result = use_rainbow_table(args.value, args.rainbow)
        if result:
            print(f"Password found in Rainbow Table: {result}")
        else:
            print("Password not found in Rainbow Table")
    elif args.salt and args.database:
        common_passwords = load_common_passwords(args.file)
        salt_and_store(common_passwords, args.salt, args.type, args.database)
        print(f"Passwords salted and stored in {args.database}")
    else:
        # Existing brute force and dictionary attack code...

if __name__ == "__main__":
    main()


# -------------------
# Salting and Storage
# -------------------

import sqlite3

# Function to create a database for storing hashed passwords and salts
def create_database():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS hashed_passwords (
            id INTEGER PRIMARY KEY,
            hash TEXT NOT NULL,
            salt TEXT
        )
    ''')
    conn.commit()
    conn.close()

# Function to store a hashed password and salt in the database
def store_hashed_password(hash_value, salt=None):
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO hashed_passwords (hash, salt) VALUES (?, ?)', (hash_value, salt))
    conn.commit()
    conn.close()

# Function to retrieve hashed passwords and salts from the database
def retrieve_hashed_passwords():
    conn = sqlite3.connect('passwords.db')
    cursor = conn.cursor()
    cursor.execute('SELECT hash, salt FROM hashed_passwords')
    rows = cursor.fetchall()
    conn.close()
    return rows

# -------------------
# Rainbow Table
# -------------------

# Function to create a Rainbow Table
def create_rainbow_table(hash_type, charset, chain_length, table_size):
    # Implement the logic to create a Rainbow Table
    pass

# Function to use a Rainbow Table for cracking passwords
def use_rainbow_table(hash_value, hash_type, rainbow_table):
    # Implement the logic to use a Rainbow Table for cracking passwords
    pass
