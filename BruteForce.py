import itertools
import hashlib
import threading
import string

# This is the worker function that each thread will run
def worker(md5_hash, guesses, results):
    for guess in guesses:
        print(f"Checking: {guess}")  # Print out each guess
        if hashlib.md5(guess.encode()).hexdigest() == md5_hash:
            results.append(guess)

def crack_md5_hash(md5_hash, length, charset):
    # Create a list to hold the results
    results = []

    # Generate all possible guesses
    all_guesses = [''.join(guess) for guess in itertools.product(charset, repeat=length)]

    # Split the guesses into chunks (one for each thread)
    chunks = [all_guesses[i::4] for i in range(4)]

    # Create four threads
    threads = [threading.Thread(target=worker, args=(md5_hash, chunk, results)) for chunk in chunks]

    # Start all threads
    for thread in threads:
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # If any results were found, return the first one
    if results:
        return results[0]

    return None

# Example usage:
password = input("Enter a password to crack: ")
md5_hash = hashlib.md5(password.encode()).hexdigest()  # MD5 hash of the input password
charset = string.printable  # Character set to use
length = len(password)  # Length of the password

print(crack_md5_hash(md5_hash, length, charset))  # Outputs: the input password
