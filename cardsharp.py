#!/usr/bin/env python3


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
    k = Crypt(k=k1.k, bits=k1.bits)
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


class Crypt:
    def __init__(self, k=None, bits=256):
        self.bits = bits
        if k:
            self.k = self.getk(k)
        else:
            self.k = self.genk()

    def genk(self):
        return ElGamal.generate(self.bits, Random.new().read)

    def getk(self, k):
        x = rand(k.p)
        y = pow(k.g, x, k.p)
        return ElGamal.construct((k.p, k.g, y, x))

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


B = 64
k1 = Crypt(bits=B)
k2 = Crypt(k=k1.k, bits=B)
k3 = gen_multiple_key(k1, k2)

print("K1", k1.k.g, k1.k.p, k1.k.y, k1.k.x)
print("K2", k2.k.g, k2.k.p, k2.k.y, k2.k.x)
print("K3", k3.k.g, k3.k.p, k3.k.y)

N = 4
clears = [random.StrongRandom().randint(1, B) for i in range(N)]
cipher = [k3.encrypt(i) for i in clears]

d = multiple_decrypt_shuffle(cipher, k1, k2)
print(clears, d, sorted(clears) == sorted(d))
