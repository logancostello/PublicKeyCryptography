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
        self.public_key = pow(alpha, self.private_key, q)

    # Generates Symmetric Key Using Other's Public Key
    def generate_symmetric_key(self, q, others_public):
        s = pow(others_public, self.private_key, q)
        hash_obj = hashlib.sha256()
        # hash_obj.update(bytes(s))
        hash_obj.update(s.to_bytes(s.bit_length() + 7 // 8, byteorder="big"))
        self.symmetric_key = hash_obj.digest()[:16]
        print("Symmetric Key", self.symmetric_key)

def pad(numPadding):
    padding = bytes([numPadding] * numPadding)
    return padding

def diffie_mal_send_q(q, alpha, message):
    IV = randbytes(16)

    # Generate Users
    alice = User()
    bob = User()

    # Generate Key Pairs
    alice.generate_diffie_hellman_pair(q, alpha)
    bob.generate_diffie_hellman_pair(q, alpha)

    # Generate Symmetric Key with mallory key q
    alice.generate_symmetric_key(q, q)
    bob.generate_symmetric_key(q, q)

    # Alice encrypts the message using her symmetric key
    data = bytes(message.encode())
    if len(data) > 16:
        print("Message too long")
        return
    data += pad(16 - len(data))
    alice_cipher = AES.new(alice.symmetric_key, AES.MODE_CBC, IV)
    encrypted = alice_cipher.encrypt(data)

    
    # We know public is 0 as q^1231 mod q is 0
    hash_obj = hashlib.sha256()
    s_val = 0
    hash_obj.update(s_val.to_bytes(s_val.bit_length() + 7 // 8, byteorder="big"))
    mallory_key = hash_obj.digest()[:16]
    # Bob decrypts Alice's message using his symmetric key
    bob_cipher = AES.new(mallory_key, AES.MODE_CBC, IV)
    decrypted = bob_cipher.decrypt(encrypted).decode()

    print(f"Alice's message: {message}")
    print(f"Bob's decrypted message: {decrypted}")


def diffie_mal_alpha_1(q, alpha, message):
    IV = randbytes(16)

    # Generate Users
    alice = User()
    bob = User()

    # Generate Key Pairs
    alice.generate_diffie_hellman_pair(q, alpha)
    bob.generate_diffie_hellman_pair(q, alpha)

    # Generate Symmetric Key with mallory key q
    alice.generate_symmetric_key(q, bob.public_key)
    bob.generate_symmetric_key(q, alice.public_key)

    # Alice encrypts the message using her symmetric key
    data = bytes(message.encode())
    if len(data) > 16:
        print("Message too long")
        return
    data += pad(16 - len(data))
    alice_cipher = AES.new(alice.symmetric_key, AES.MODE_CBC, IV)
    encrypted = alice_cipher.encrypt(data)

    
    # We know q ^ x mod q = 1, thus s = 1. So we sha X to get the key
    hash_obj = hashlib.sha256()
    s_val = 1
    hash_obj.update(s_val.to_bytes(s_val.bit_length() + 7 // 8, byteorder="big"))
    mallory_key = hash_obj.digest()[:16]
    # Bob decrypts Alice's message using his symmetric key
    bob_cipher = AES.new(mallory_key, AES.MODE_CBC, IV)
    decrypted = bob_cipher.decrypt(encrypted).decode()

    print(f"Alice's message: {message}")
    print(f"Bob's decrypted message: {decrypted}")


    
def diffie_mal_alpha_q(q, alpha, message):
    IV = randbytes(16)

    # Generate Users
    alice = User()
    bob = User()

    # Generate Key Pairs, public keys become 0
    alice.generate_diffie_hellman_pair(q, alpha)
    bob.generate_diffie_hellman_pair(q, alpha)

    # Generate Symmetric Key, which are sha(0)
    alice.generate_symmetric_key(q, bob.public_key)
    bob.generate_symmetric_key(q, alice.public_key)

    # Alice encrypts the message using her symmetric key
    data = bytes(message.encode())
    if len(data) > 16:
        print("Message too long")
        return
    data += pad(16 - len(data))
    alice_cipher = AES.new(alice.symmetric_key, AES.MODE_CBC, IV)
    encrypted = alice_cipher.encrypt(data)

    
    # We know q ^ x mod q = 0, public is 0, so public ^ private mod q is 0, so sha(0) = k
    hash_obj = hashlib.sha256()
    s_val = 0
    hash_obj.update(s_val.to_bytes(s_val.bit_length() + 7 // 8, byteorder="big"))
    mallory_key = hash_obj.digest()[:16]
    # Bob decrypts Alice's message using his symmetric key
    bob_cipher = AES.new(mallory_key, AES.MODE_CBC, IV)
    decrypted = bob_cipher.decrypt(encrypted).decode()

    print(f"Alice's message: {message}")
    print(f"Bob's decrypted message: {decrypted}")


def diffie_mal_alpha_minusq(q, alpha, message):
    IV = randbytes(16)

    # Generate Users
    alice = User()
    bob = User()

    # Generate Key Pairs, public keys become 0
    alice.generate_diffie_hellman_pair(q, alpha)
    bob.generate_diffie_hellman_pair(q, alpha)

    # Generate Symmetric Key, which are sha(0)
    alice.generate_symmetric_key(q, bob.public_key)
    bob.generate_symmetric_key(q, alice.public_key)

    # Alice encrypts the message using her symmetric key
    data = bytes(message.encode())
    if len(data) > 16:
        print("Message too long")
        return
    data += pad(16 - len(data))
    alice_cipher = AES.new(alice.symmetric_key, AES.MODE_CBC, IV)
    encrypted = alice_cipher.encrypt(data)

    
    # Public is either 1 or q - 1 depending on wiether or not private is even or odd.
    hash_obj = hashlib.sha256()
    s_val1 = 1
    s_val2 = q - 1
    hash_obj.update(s_val1.to_bytes(s_val1.bit_length() + 7 // 8, byteorder="big"))
    mallory_key1 = hash_obj.digest()[:16]
    hash_obj2 = hashlib.sha256()
    hash_obj2.update(s_val2.to_bytes(s_val2.bit_length() + 7 // 8, byteorder="big"))
    mallory_key2 = hash_obj2.digest()[:16]
    # Bob decrypts Alice's message using his symmetric key
    try:
        bob_cipher = AES.new(mallory_key1, AES.MODE_CBC, IV)
        decrypted = bob_cipher.decrypt(encrypted).decode()

        print("s was equal to 1")
        print(f"Alice's message: {message}")
        print(f"Bob's decrypted message: {decrypted}")
        return
    except:
        bob_cipher = AES.new(mallory_key2, AES.MODE_CBC, IV)
        decrypted = bob_cipher.decrypt(encrypted).decode()

        print("S was equal to q - 1")
        print(f"Alice's message: {message}")
        print(f"Bob's decrypted message: {decrypted}")
        return

