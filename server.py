import socket
import time
import threading

import rsa
from cryptography.fernet import Fernet

host = '127.0.0.1'
port = 65432

connections = []
hosts = []
pubKeys = {}
keys = {}


server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
server.listen()




def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        print("Decryption Error!")


def keyEx(host,pubKey):
    print(f"Key Ex with {host}")
    
    if(host in keys.keys()):
        encKey = keys[host]
    else:
        encKey = Fernet.generate_key().decode()
        keys[host] = encKey
    
    #broadcast(encKey)
    #print(encKey)

    publicKey_fromhex = bytes.fromhex(pubKey)
    publicKey = rsa.PublicKey.load_pkcs1(publicKey_fromhex)
    pubKeys[host] = publicKey

    #print(pubKey)
    
    try:
        #print(f"SVR-KEYEX-RPLY:{host}:{encrypt(encKey,pubKeys[host]).hex()}")
        broadcast(f"{host}:SVR-KEYEX-RPLY:{encrypt(encKey,pubKeys[host]).hex()}")
        print(f"Key Sent to {host}")
    except:
        print(f"Key Ex with {host} Failed!")
        broadcast(f"{host}:SVR-KEY-EX-ReINIT")


def broadcast(message):
    for connection in connections:
        connection.send(bytes(message,'ascii'))


def handle(client):
    while True:
        try:
            dataFrame = client.recv(4096).decode()
            dataFrame = dataFrame.split(":")
            #print(dataFrame)
            if("NEW-CON" in dataFrame): #NEW-CON:HOST:PubK
                    hosts.append(dataFrame[0])
                    keyEx_thread = threading.Thread(target=keyEx, args=(dataFrame[0],dataFrame[2]))
                    keyEx_thread.start()
            elif(dataFrame[0] in hosts):
                print(dataFrame)
        except:
            connections.remove(client)
            client.close()
            break


def receive():
    while True:
        con, address = server.accept()
        print("Connected with {}".format(str(address)))

        connections.append(con)

        thread = threading.Thread(target=handle, args=(con,))
        thread.start()



receive()