from Crypto.Util.number import getPrime
from random import randrange


def rsa_mallory(numBits):
    # Alice calculates these numbers
    p = getPrime(numBits)
    q = getPrime(numBits)
    n = p * q
    e = 65537

    # Bob received n & e, and gets s and c
    s_bob = randrange(n)
    c = pow(s_bob, e, n)

    # Mallory receives c, sends c' to Alice
    c_prime = n

    # Alice receives c', calculates s
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    s = pow(c_prime, d, n)

    return s

    # S must be 0
    # From here, s is hashed into a key that is used for encryption, but mallory
    # knows s is 0, so she can calculate the key as well, intercept the encrypted
    # message, then decrypt it with the key

if __name__ == '__main__':
    print(rsa_mallory(128))


