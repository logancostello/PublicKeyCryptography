from Crypto.Util.number import getPrime

def rsa(numBits, message):
    # generate p and q
    p = getPrime(numBits)
    q = getPrime(numBits)
    e = 65537

    print(f"p: {p}")
    print(f"q: {q}")
    print()
    # check p and q are different
    while q == p:
        q = getPrime(numBits)

    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)

    pu = (e, n)
    pr = (d, n)

    print(f"Public Key: {pu}")
    print(f"Private Key: {pr}")
    print()

    # Turn message to number
    print(f"Original Message: {message}")
    ciphertext = string_to_num(message)

    if ciphertext >= n:
        print("MESSAGE TOO BIG")
        return

    # Encrypt
    c = pow(ciphertext, e, n)
    print(f"Encrypted: {c}")
    # Decrypt
    m = pow(c, d, n)

    # Turn back into text
    decrypted = num_to_string(m)
    print(f"Decrypted: {decrypted}")



def string_to_num(str):
    result = ""
    for c in str:
        result += hex(ord(c))[2:]
    return int(result, 16)

def num_to_string(num):
    hex_string = hex(num)[2:]

    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string

    chars = [hex_string[i:i + 2] for i in range(0, len(hex_string), 2)]

    result = ''.join([chr(int(char, 16)) for char in chars])

    return result


if __name__ == '__main__':
    # Takes a couple seconds to run with large numBits
    numBits = 2048
    message = "Hello world!"
    rsa(numBits, message)

