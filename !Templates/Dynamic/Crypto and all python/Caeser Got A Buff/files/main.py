#!/usr/bin/env python3
import random
import string

def enhanced_dynamic_caesar_encrypt(message, start_key):
    encrypted_message = []
    key = start_key
    
    for i, char in enumerate(message):
        # Check if the character is a letter or digit
        if char.isalpha():
            if char.isupper():
                shifted_char = chr(((ord(char) - ord('A') + key) % 26) + ord('A'))
            else:
                shifted_char = chr(((ord(char) - ord('a') + key) % 26) + ord('a'))
        elif char.isdigit():
            shifted_char = chr(((ord(char) - ord('0') + key) % 10) + ord('0'))
        elif char in '{}':
            shifted_char = char
        else:
            shifted_char = char
        
        # Append shifted character
        encrypted_message.append(shifted_char)
        
        # Append random characters after the shifted character
        random_chars = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(key))
        encrypted_message.append(random_chars)
        
        # Increment key for the next character
        key += 1
    
    return ''.join(encrypted_message)

def get_flag():
    with open('flag.txt', 'r') as f:
        flag = f.read().strip()
    return flag

def create_caesar_challenge():
    flag = get_flag()
    
    start_key = random.randint(1, 10)
    
    encrypted_flag = enhanced_dynamic_caesar_encrypt(flag, start_key)
    
    print(f"\nEncrypted Flag: {encrypted_flag}\n")
    print("\nHint: Only letters and digits are shifted based on their position in the string. Special characters like '{}', '$', '.', etc., are not shifted.\n")

def encrypt_any_data():
    print("\nEnter the message you want to encrypt:")
    message = input()
    start_key = random.randint(1, 10)

    print(f"\nYour Starting Key: {start_key}\n")
    
    encrypted_message = enhanced_dynamic_caesar_encrypt(message, start_key)
    
    print(f"\nEncrypted Message: {encrypted_message}\n")

def menu():
    while True:
        print("\n--- Impossible Caeser ---")
        print("1. Encrypt any data")
        print("2. Get Flag (encrypted text)")
        print("3. Exit")
        
        print("\nEnter your choice:")
        choice = input()
        
        if choice == '1':
            encrypt_any_data()
        elif choice == '2':
            create_caesar_challenge()
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    menu()
