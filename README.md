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
## Usage
The program can be run from the command line with various arguments.

## Command Line Arguments
+ -t, --type : Specify the hash type (md5, sha256, bcrypt)
+ -v, --value : The hash value to crack
+ -m, --mode : Mode of attack (brute or dictionary)
+ -f, --file : File path for dictionary attack (if applicable)

## Examples
### Brute Force Attack
```
python FinalBruteForce.py -t md5 -v [hash_value] -m brute
```

### Dictionary Attack
```
python FinalBruteForce.py -t sha256 -v [hash_value] -m dictionary -f path/to/passwords.txt
```

## Extensions
+ Salting and storing passwords in a database.
+ Rainbow Table creation and usage (to be implemented).

## Dependencies
```
pip install -r requirements.txt
```
