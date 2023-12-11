# PasswordCrackingProgram

## Overview
This Python-based program is designed to perform password cracking using various methods. It supports brute force attacks, dictionary attacks, and can handle different hash types including MD5, SHA-256, and BCrypt. This tool is intended for educational purposes and ethical testing only.

## Installation
To use this program, you need to have Python installed on your machine.
```
# Clone the repository
git clone [repository-url]
cd [repository-name]

# Install required packages
pip install -r requirements.txt
```

## Prerequisites
Make sure you have Python 3.x installed on your system.

Create a text file containing a list of common passwords (e.g., "common_passwords.txt") where each password is on a separate line. This file will be used for dictionary attacks.

## Running the Script
1. Open your terminal or command prompt.

2. Navigate to the directory where the script is located.

3. Use the following command to run the script:

```
python password_cracker.py -t <hash_type> -v <hash_value_to_crack> -m <attack_mode> [-f <dictionary_file>]
```

Replace the placeholders with the appropriate values:

+ **<hash_type>**: The type of hash to crack (choices: md5, sha256, bcrypt).
+ **<hash_value_to_crack>**: The hash value you want to crack.
+ **<attack_mode>**: The attack mode to use (choices: brute, dictionary).
+ **<dictionary_file>** (optional): The path to the file containing common passwords for dictionary attacks. Only required when using the "dictionary" attack mode.

## Examples
### Brute Force Attack:
To perform a brute force attack on an MD5 hash value, you can use the following command:

```
python password_cracker.py -t md5 -v <md5_hash_value_to_crack> -m brute
```

### Dictionary Attack:
To perform a dictionary attack on an SHA-256 hash value using a custom dictionary file ("common_passwords.txt"), you can use the following command:

```
python password_cracker.py -t sha256 -v <sha256_hash_value_to_crack> -m dictionary -f common_passwords.txt
```

## Output
The script will output the result of the password cracking attempt. If a matching password is found, it will be displayed. Otherwise, it will indicate that the password was not found.


