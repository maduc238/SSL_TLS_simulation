import socket
import os
from _thread import *

ServerSideSocket = socket.socket()
host = '127.0.0.1'
port = 443
ThreadCount = 0
try:
    ServerSideSocket.bind((host, port))
except socket.error as e:
    print(str(e))
    exit()
print('Socket is listening..')
ServerSideSocket.listen(5)

Clients = [None, None, None]

def Connect(connection):
    connection.send(str.encode('Server is working:'))
    while True:
        data = connection.recv(65536)
        if not data:
            break
        # print(data)
        if data[:4] == b'rank':      # join
            rank = data[5]-48
            if rank >= 0 and rank <= 2:
                global Clients
                Clients[rank] = connection
                print(f'Server {rank} đã kết nối được internet')
            else:
                print('Rank không hợp lệ')
        else:                       # switch
            dest = data[1]
            try:
                Clients[dest].send(data)
            except:
                print('Không gửi được tới dest')
        
    connection.close()

while True:
    client, address = ServerSideSocket.accept()
    print('Connected to: ' + address[0] + ':' + str(address[1]))
    # Clients.append(client)
    start_new_thread(Connect, (client, ))
    ThreadCount += 1
    # print('Thread Number: ' + str(ThreadCount))

ServerSideSocket.close()