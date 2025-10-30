from ecdsa import VerifyingKey, SECP256k1
from ecdsa.util import sigdecode_string
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import binascii

# Encrypted flag and provided public key
encrypted_flag_hex = ""
public_key_hex = ""

# Signatures and corresponding messages
message_1 = ""
signature_1_hex = ""

message_2 = ""
signature_2_hex = ""

# Step 1: Hash both messages
hash_1 = int.from_bytes(hashlib.sha256(message_1.encode()).digest(), "big")
hash_2 = int.from_bytes(hashlib.sha256(message_2.encode()).digest(), "big")

# Step 2: Parse signatures into r and s values
r = int(signature_1_hex[:64], 16)  # r is the same in both signatures
s1 = int(signature_1_hex[64:], 16)
s2 = int(signature_2_hex[64:], 16)

# Step 3: Calculate the private key using the fixed nonce vulnerability
# k = ((hash_1 - hash_2) * modinv(s1 - s2, SECP256k1.order)) % SECP256k1.order
order = SECP256k1.order
k = ((hash_1 - hash_2) * pow(s1 - s2, -1, order)) % order
priv_key = ((s1 * k - hash_1) * pow(r, -1, order)) % order

# Convert the private key to hex for output and usage
priv_key_hex = priv_key.to_bytes(32, "big").hex()
print(f"Recovered Private Key (Hex): {priv_key_hex}")

