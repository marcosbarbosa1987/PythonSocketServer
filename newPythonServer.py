import socket
import sys
from _thread import *

HOST = '192.168.25.2' # all availabe interfaces
PORT = 8801 # arbitrary non privileged port
USERS = []

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except socket.error as msg:
    print('Could not create socket. Error Code: {} Error: {}' .format(msg[0], msg[1]))
    sys.exit(0)

print("[-] Socket Created")

# bind socket
try:
    s.bind((HOST, PORT))
    print("[-] Socket Bound to port " + str(PORT))
except socket.error as msg:
    print("Bind Failed. Error Code: {} Error: {}".format(str(msg[0]), msg[1]))
    sys.exit()

s.listen(10)
print("Listening...")

# The code below is what you're looking for ############

def client_thread(conn):
    message = 'Conectado'
    conn.send(message.encode())

    while True:
        data = conn.recv(4096)
        if not data:
            break
        reply = data
        #conn.sendall(reply)
        if len(USERS) == 2:
            if USERS[0].__getitem__('connection') == conn:
                USERS[1].__getitem__('connection').send(reply)
            else:
                USERS[0].__getitem__('connection').send(reply)

    conn.close()

while True:
    # blocking call, waits to accept a connection
    conn, addr = s.accept()

    print("[-] Connected to {}:{}".format(addr[0], addr[1]))
    newClient = {'connection': conn, 'ip': addr[0], 'port': addr[1]}

    if USERS.__contains__(newClient.__getitem__('ip')):
        start_new_thread(client_thread, (conn,))
        print('contem')
    else:
        USERS.append(newClient)
        start_new_thread(client_thread, (conn,))
        print('nao tem e adicionou')


    # start_new_thread(client_thread, (conn,))
s.close()