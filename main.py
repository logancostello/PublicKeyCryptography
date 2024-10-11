from random import randrange
class User:
    def __init__(self):
        self.public_key = None
        self.private_key = None
        self.symmetric_key = None

    def __repr__(self):
        return f"Public: {self.public_key}, Private: {self.private_key}, Symmetric: {self.symmetric_key}"

    def generate_diffie_hellman_pair(self, q, alpha):
        self.private_key = randrange(q)
        self.public_key = (alpha ** self.private_key) % q # this will need to be changed later for a better func

    def generate_secret_key(self, q, others_public):
        self.symmetric_key = (others_public ** self.private_key) % q


if __name__ == '__main__':
    q = 37
    alpha = 5

    alice = User()
    alice.generate_diffie_hellman_pair(q, alpha)

    bob = User()
    bob.generate_diffie_hellman_pair(q, alpha)

    alice.generate_secret_key(q, bob.public_key)
    bob.generate_secret_key(q, alice.public_key)

    # FROM HERE, NEED TO ENCRYPT MESSAGES
    # ONCE THAT WORKS, SWITCH TO LARGER Q AND ALPHA
    # THEN SWITCH CALCULATIONS TO HANDLE LARGE NUMBERS

    print(alice)
    print(bob)


