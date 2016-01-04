#!/usr/bin/python3


import sys
import os
import threading
import socket
import socketserver

from avcrypt import AVCrypt


B = 8
HOST = 'localhost'
PORT = 5000


class AVMixNet(socketserver.BaseRequestHandler):
    def readline(self, sock):
        data = b''
        while not data.endswith(b'\r\n'):
            data += sock.recv(1024)
        return data

    def mix_req(self, mix, data):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        host, port = mix.split(b":")
        received = b''

        try:
            sock.connect((host, int(port)))
            sock.sendall(data + b'\r\n')
            received = self.readline(sock)
        finally:
            sock.close()

        return received

    def handle(self):
        data = self.readline(self.request)

        splitted = data.split(b' ')
        command = splitted[0]
        id = splitted[1]
        args = splitted[2:]

        resp = b'Invalid command'

        if command == b'GEN_KEY':
            print("GENERATING KEY %s" % id.decode())
            mixs = args[0]
            g, p = 0, 0
            if len(args) > 1:
                p, g = args[1].split(b',')
            mixs = mixs.split(b',')
            resp = self.gen_key(id, mixs, p, g)
        elif command == b'DECRYPT':
            print("DECRYPT %s" % id.decode())
            mixs = args[0]
            msgs = args[1:]
            mixs = mixs.split(b',')
            resp = self.decrypt(id, mixs, msgs)
        elif command == b'SHUFFLE':
            print("SHUFFLE %s" % id.decode())
            mixs = args[0]
            pk = args[1]
            pk = tuple(int(i) for i in pk.split(b','))
            self.save_pk(id, pk)
            msgs = args[2:]
            mixs = mixs.split(b',')
            resp = self.shuffle(id, mixs, msgs)
        else:
            print('INVALID COMMAND:\n%s' % data.decode())

        self.request.sendall(resp + b'\r\n')

    def createdirs(self, id):
        global PORT
        avdir = b'/tmp/avmix/%d' % PORT
        if not os.path.exists(b'/tmp/avmix'):
            os.mkdir(b'/tmp/avmix')
        if not os.path.exists(avdir):
            os.mkdir(avdir)
        return os.path.join(avdir, id)

    def save_key(self, id, avcrypt):
        stpath = self.createdirs(id)
        k = avcrypt.k
        key = '%d,%d,%d,%d' % (k.p, k.g, k.y, k.x)
        with open(stpath, 'w') as f:
            f.write(key)

    def save_pk(self, id, pk):
        stpath = self.createdirs(id) + b'.pk'
        key = '%d,%d,%d' % pk
        with open(stpath, 'w') as f:
            f.write(key)

    def load_key(self, id, avcrypt):
        stpath = self.createdirs(id)
        if os.path.exists(stpath):
            p, g, y, x = map(int, open(stpath).read().split(','))
            k = avcrypt.setk(p, g, y, x)
            return True
        else:
            return False

    def load_pk(self, id):
        stpath = self.createdirs(id) + b'.pk'
        if os.path.exists(stpath):
            p, g, y = map(int, open(stpath).read().split(','))
            return p, g, y
        else:
            return None

    def gen_key(self, id, mixs, p, g):
        avcrypt = AVCrypt(bits=B)
        if self.load_key(id, avcrypt):
            k = avcrypt.k
        elif (not g or not p):
            k = avcrypt.genk()
            self.save_key(id, avcrypt)
        else:
            k = avcrypt.getk(int(p), int(g))
            self.save_key(id, avcrypt)

        me = mixs[0]
        others = mixs[1:]
        if others:
            resp = self.mix_req(others[0], b'GEN_KEY %s %s %d,%d' %
                    (id, b','.join(others), k.p, k.g))
            p, g, y = resp.split(b',')
            y = (int(y) * k.y) % k.p
            return b'%s,%s,%d' % (p, g, y)
        else:
            return b'%d,%d,%d' % (k.p, k.g, k.y)

    def decrypt(self, id, mixs, msgs):
        avcrypt = AVCrypt(bits=B)
        if self.load_key(id, avcrypt):
            k = avcrypt.k

        me = mixs[0]
        others = mixs[1:]
        last = not others
        msgs = [list(map(int, i.split(b','))) for i in msgs]
        msgs = avcrypt.shuffle_decrypt(msgs, last)

        if not last:
            msgs = b' '.join(b'%d,%d' % (a, b) for a, b in msgs)
            resp = self.mix_req(others[0], b'DECRYPT %s %s %s' %
                    (id, b','.join(others), msgs))
            return resp
        else:
            return b' '.join(b'%d' % i for i in msgs)

    def shuffle(self, id, mixs, msgs):
        avcrypt = AVCrypt(bits=B)
        pk = self.load_pk(id)

        me = mixs[0]
        others = mixs[1:]
        last = not others
        msgs = [list(map(int, i.split(b','))) for i in msgs]
        msgs = avcrypt.shuffle(msgs, pk)
        msgs = b' '.join(b'%d,%d' % (a, b) for a, b in msgs)

        epk = b'%d,%d,%d' % pk

        if not last:
            resp = self.mix_req(others[0], b'SHUFFLE %s %s %s %s' %
                    (id, b','.join(others), epk, msgs))
            return resp
        else:
            return msgs


if __name__ == '__main__':
    port = 5000
    if len(sys.argv) == 2:
        port = int(sys.argv[1])

    HOST = "localhost"
    PORT = port
    server = socketserver.TCPServer((HOST, PORT), AVMixNet)
    print("Server running in %s:%s" % (HOST, PORT))
    server.serve_forever()
