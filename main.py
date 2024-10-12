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
    q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
    alpha = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
    message = "Hello Bob!"
    simulate_diffie_hellman(q, alpha, message)

    # NEXT STEP:
    # 1. UPGRADE CALCULATIONS TO HANDLE LARGE Q AND ALPHA (FINISH TASK 1)
    # 2. MITM ATTACK (TASK 2)
    # 3. IMPLEMENT RSA (TASK 3)
