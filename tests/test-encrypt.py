import sys
from avcrypt import AVCrypt
from avcrypt import ElGamal


p, g, y = map(int, sys.argv[1].split(','))
k = AVCrypt(bits=8)
k.k = ElGamal.construct((p, g, y))

clears = [2,3,6,4]
cipher = [','.join(map(str, k.encrypt(i))) for i in clears]
print(' '.join(cipher))
