from random import randrange
from random import randbytes
import hashlib
from Crypto.Cipher import AES
from mallory_funcs import diffie_mal_alpha_1, diffie_mal_alpha_q, diffie_mal_send_q, diffie_mal_alpha_minusq
import sys


if __name__ == '__main__':
    q = 0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371
    alpha = 0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5
    message = "Hello Bob!"
    print("\nMallory gives her q to both parties\nUses sha(0) to generate sym k for decrypt")
    diffie_mal_send_q(q, alpha, message)

    print("\nMallory sets a to 1")
    print("We know s is one, so sha(1) generate sym key")
    diffie_mal_alpha_1(q, 1, message)


    print("\nMallory sets a to q")
    print("Makes public key 0, so s = 0, so k = sha(0), decrypted")
    diffie_mal_alpha_q(q, q, message)


    print("\nMallory sets a to q-1")
    print("s alterantes between 1 and q-1, so try sha(1) and sha(q - 1)")
    diffie_mal_alpha_minusq(q, q-1, message)

    # NEXT STEP:
    # 1. UPGRADE CALCULATIONS TO HANDLE LARGE Q AND ALPHA (FINISH TASK 1)
    # 2. MITM ATTACK (TASK 2)
    # 3. IMPLEMENT RSA (TASK 3)
