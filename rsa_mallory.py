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


