'''
>>> B = 64
>>> k1 = AVCrypt(bits=B)
>>> k2 = AVCrypt(k=k1.k, bits=B)
>>> k3 = gen_multiple_key(k1, k2)
>>> N = 4
>>> clears = [random.StrongRandom().randint(1, B) for i in range(N)]
>>> cipher = [k3.encrypt(i) for i in clears]
>>> d = multiple_decrypt_shuffle(cipher, k1, k2)
>>> clears == d
False
>>> sorted(clears) == sorted(d)
True

>>> B = 8
>>> k1 = AVCrypt(bits=B)
>>> k1.setk(167,156,89,130) #doctest: +ELLIPSIS
<Crypto.PublicKey.ElGamal.ElGamalobj object at 0x...>
>>> k2 = AVCrypt(bits=B)
>>> k2.setk(167,156,53,161) #doctest: +ELLIPSIS
<Crypto.PublicKey.ElGamal.ElGamalobj object at 0x...>
>>> k3 = AVCrypt(bits=B)
>>> k3.k = ElGamal.construct((167, 156, 4717))
>>> k3.k.p, k3.k.g, k3.k.y
(167, 156, 4717)
>>> N = 4
>>> clears = [2,3,6,4]
>>> cipher = [(161, 109), (17, 101), (148, 163), (71, 37)]
>>> d = multiple_decrypt_shuffle(cipher, k2, k1)
>>> clears == d
False
>>> sorted(clears) == sorted(d)
True
'''


from pprint import pprint

from Crypto.PublicKey import ElGamal
from Crypto.Random import random
from Crypto import Random
from Crypto.Util.number import GCD


def rand(p):
    while True:
        k = random.StrongRandom().randint(1, p - 1)
        if GCD(k, p - 1) == 1: break
    return k


def gen_multiple_key(*crypts):
    k1 = crypts[0]
    k = AVCrypt(k=k1.k, bits=k1.bits)
    k.k.y = 1
    for kx in crypts:
        k.k.y *= kx.k.y
    return k


def multiple_decrypt(c, *crypts):
    a, b = c
    for k in crypts:
        b = k.decrypt((a, b))
    return b


def multiple_decrypt_shuffle(ciphers, *crypts):
    b = ciphers
    for i, k in enumerate(crypts):
        last = i == len(crypts) - 1
        b = k.shuffle_decrypt(b, last)
    return b


class AVCrypt:
    def __init__(self, k=None, bits=256):
        self.bits = bits
        if k:
            self.k = self.getk(k.p, k.g)
        else:
            self.k = self.genk()

    def genk(self):
        self.k = ElGamal.generate(self.bits, Random.new().read)
        return self.k

    def getk(self, p, g):
        x = rand(p)
        y = pow(g, x, p)
        self.k = ElGamal.construct((p, g, y, x))
        return self.k

    def setk(self, p, g, y, x):
        self.k = ElGamal.construct((p, g, y, x))
        return self.k

    def encrypt(self, m):
        r = rand(self.k.p)
        a, b = self.k.encrypt(m, r)
        return a, b

    def decrypt(self, c):
        m = self.k.decrypt(c)
        return m

    def shuffle_decrypt(self, msgs, last=True):
        msgs2 = msgs.copy()
        msgs3 = []
        while msgs2:
            n = random.StrongRandom().randint(0, len(msgs2) - 1)
            a, b = msgs2.pop(n)
            clear = self.decrypt((a, b))
            if last:
                msg = clear
            else:
                msg = (a, clear)
            msgs3.append(msg)

        return msgs3


if __name__ == "__main__":
    import doctest
    doctest.testmod()
