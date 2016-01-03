import sys
import socket


def readline(sock):
    data = b''
    while not data.endswith(b'\r\n'):
        data += sock.recv(1024)
    return data


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host, port = sys.argv[1].split(":")
sock.connect((host, int(port)))
sock.sendall(sys.argv[2].encode() + b'\r\n')
received = readline(sock)
sock.close()

print(received.decode().strip())
