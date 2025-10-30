#!/usr/bin/env python3

def dynamic_caesar_encrypt(message):
    encrypted_message = []
    
    for i, char in enumerate(message):
        # Check if the character is a letter or digit
        if char.isalpha():
            if char.isupper():
                shifted_char = chr(((ord(char) - ord('A') + (i + 1)) % 26) + ord('A'))
            else:
                shifted_char = chr(((ord(char) - ord('a') + (i + 1)) % 26) + ord('a'))
        elif char.isdigit():
            shifted_char = chr(((ord(char) - ord('0') + (i + 1)) % 10) + ord('0'))
        elif char in '{}':
            shifted_char = char
        else:
            shifted_char = char
        
        encrypted_message.append(shifted_char)
    
    return ''.join(encrypted_message)

def get_flag():
    with open('flag.txt', 'r') as f:
        flag = f.read().strip()
    return flag

def create_caesar_challenge():
    flag = get_flag()
    
    encrypted_flag = dynamic_caesar_encrypt(flag)
    
    print(f"\nEncrypted Flag: {encrypted_flag}\n")
    
    print("\nHint: Only letters and digits are shifted based on their position in the string. Special characters like '{}',$ , . etc are not shifted.\n")

    exit(0)

if __name__ == "__main__":
    create_caesar_challenge()
