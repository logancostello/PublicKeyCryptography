from random import randrange
from random import randbytes
import hashlib
from Crypto.Cipher import AES
import sys

class User:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.symmetric_key = None

    def __repr__(self):
        return f"Public: {self.public_key}, Private: {self.private_key}, Symmetric: {self.symmetric_key}"

    # Generates Public & Private Key Pair
    def generate_diffie_hellman_pair(self, q, alpha):
        self.private_key = randrange(q)
        self.public_key = (alpha ** self.private_key) % q # this will need to be changed later for a better func

    # Generates Symmetric Key Using Other's Public Key
    def generate_secret_key(self, q, others_public):
        s = (others_public ** self.private_key) % q
        hash_obj = hashlib.sha256()
        hash_obj.update(bytes(s))
        self.symmetric_key = hash_obj.digest()[:16]

def pad(numPadding):
    padding = bytes([numPadding] * numPadding)
    return padding

def simulate_diffie_hellman(q, alpha, message):
    IV = randbytes(16)

    # Generate Users
    alice = User()
    bob = User()

    # Generate Key Pairs
    alice.generate_diffie_hellman_pair(q, alpha)
    bob.generate_diffie_hellman_pair(q, alpha)

    # Generate Symmetric Key Using Other's Public Key
    alice.generate_secret_key(q, bob.public_key)
    bob.generate_secret_key(q, alice.public_key)

    # Alice encrypts the message using her symmetric key
    data = bytes(message.encode())
    if len(data) > 16:
        print("Message too long")
        return
    data += pad(16 - len(data))
    alice_cipher = AES.new(alice.symmetric_key, AES.MODE_CBC, IV)
    encrypted = alice_cipher.encrypt(data)

    # Bob decrypts Alice's message using his symmetric key
    bob_cipher = AES.new(bob.symmetric_key, AES.MODE_CBC, IV)
    decrypted = bob_cipher.decrypt(encrypted).decode()

    # Output
    print(f"Alice's Keys: {alice}")
    print(f"Bob's Keys: {bob}")
    print()
    print(f"Alice's message: {message}")
    print(f"Alice's encrypted message: {encrypted}")
    print(f"Bob's decrypted message: {decrypted}")

if __name__ == '__main__':
    q = 37
    alpha = 5
    message = "Hello Bob!"
    simulate_diffie_hellman(q, alpha, message)

    # NEXT STEP:
    # 1. UPGRADE CALCULATIONS TO HANDLE LARGE Q AND ALPHA (FINISH TASK 1)
    # 2. MITM ATTACK (TASK 2)
    # 3. IMPLEMENT RSA (TASK 3)
