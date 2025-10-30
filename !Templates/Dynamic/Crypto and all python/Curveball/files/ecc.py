from ecdsa import SigningKey, SECP256k1
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

# Load the flag from file
with open("flag.txt", "r") as f:
    FLAG = f.read().strip()

# Generate ECDSA private key and reused nonce for signing
sk = SigningKey.generate(curve=SECP256k1)  # ECDSA private key
vk = sk.verifying_key  # ECDSA public key

# Vulnerability: Fixed 'k' (nonce) reused for all signatures
fixed_k = int.from_bytes(os.urandom(16), "big")

# Derive AES encryption key from the ECDSA private key
aes_key = hashlib.sha256(sk.to_string()).digest()  # 256-bit key for AES

# Encrypt the flag using AES in ECB mode for simplicity
cipher = AES.new(aes_key, AES.MODE_ECB)
encrypted_flag = cipher.encrypt(pad(FLAG.encode(), AES.block_size)).hex()

# Function to sign a message with fixed 'k' (vulnerable)
def sign_message(message):
    # Hash the message
    message_hash = hashlib.sha256(message.encode()).digest()
    
    # Sign the message using the fixed 'k'
    sig = sk.sign_digest(message_hash, k=fixed_k)
    return sig

# Display public key for participants
print(f"Public Key (Hex): {vk.to_string().hex()}\n")
print("Curve Name: SECP256k1\n")

# Start interactive menu
while True:
    print("Choose an option:")
    print("1. Sign Message")
    print("2. Get Flag (encrypted)")
    print("3. Decrypt Flag (using obtained private key)")
    print("4. Exit")

    print("Enter your choice:")
    choice = input().strip()

    if choice == "1":
        # Option to sign a user-provided message
        print("Enter the message to sign:")
        user_message = input().strip()
        signature = sign_message(user_message)
        print(f"Signature (Hex): {signature.hex()}\n")

    elif choice == "2":
        # Option to retrieve the encrypted flag
        print(f"Encrypted Flag (Hex): {encrypted_flag}\n")

    elif choice == "3":
        # Option to decrypt the flag with a provided private key
        print("Enter your private key (Hex):")
        user_private_key_hex = input().strip()
        try:
            # Convert the hex input to bytes and derive the AES key
            user_private_key_bytes = bytes.fromhex(user_private_key_hex)
            user_aes_key = hashlib.sha256(user_private_key_bytes).digest()
            
            # Attempt to decrypt the flag
            user_cipher = AES.new(user_aes_key, AES.MODE_ECB)
            decrypted_flag = unpad(user_cipher.decrypt(bytes.fromhex(encrypted_flag)), AES.block_size).decode()
            print(f"Decrypted Flag: {decrypted_flag}\n")
        except Exception as e:
            print("Incorrect private key or decryption error. Please try again.\n")

    elif choice == "4":
        # Option to exit
        print("Goodbye!")
        break

    else:
        print("Invalid choice. Please select 1, 2, 3, or 4.\n")
