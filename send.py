import socket
import time

s = socket.socket()

s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096 * 2)
s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096 * 2)
s.connect(("1.1.1.1", 42))
s.settimeout(1)
print("Connected.")

for i in range(100):
    try:
        sent = s.send(b"a" * 4095 * 10)
    except OSError as e:
        print("BLOCKING", e)
        while True:
            try:
                print(f"{len(s.recv(4096 * 10 * 10))=}")
            except OSError as e:
                print("Cannot read anymore.", e)
                break
        sent = 0
    print(f"{i=} {sent=}")
    time.sleep(0.5)
