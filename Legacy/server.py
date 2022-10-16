import socket
import time
import threading

import rsa
from cryptography.fernet import Fernet

print("Initializing the Server............")

HOST = "127.0.0.1"
PORT = 65432

connections = []
hosts = []
pubKeys = {}
keys = {}

SVR = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SVR.bind((HOST, PORT))
SVR.listen()


def broadcast(msg):
    # try:
    #     con.sendall(bytes(msg, 'ascii'))
    # except:
    #     print(f"Error broadcasting -> {msg}")

    for connection in connections:
        connection.send(bytes(msg, 'ascii'))


def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        print("Decryption Error!")



def keyEx(host,pubKey):
    print(f"Key Ex with {host}")
    
    encKey = Fernet.generate_key().decode()
    keys[host] = encKey

    print(connections)
    broadcast(encKey)
    
    # # if(host in keys.keys()):
    # #     encKey = keys[host]
    # # else:
    # #     encKey = Fernet.generate_key().decode()
    # #     keys[host] = encKey
    
    # broadcast("test")
    # print(encKey)

    # publicKey_fromhex = bytes.fromhex(pubKey)
    # publicKey = rsa.PublicKey.load_pkcs1(publicKey_fromhex)
    # #print(publicKey)
    # pubKeys[host] = publicKey

    

    # try:
    #     #X = encrypt("test",keys[host])
    #     #print(X.hex())
    #     #print(f"SVR-KEY-EX:{host}:{encrypt(newKey,keys[host]).hex()}")
    #     #broadcast(f"SVR-KEY-EX:{host}:{encrypt(encKey,pubKeys[host]).hex()}")
    #     pass
    #     #print("test")
    # except:
    #     print(f"Key Ex with {host} Failed!")
    #     #broadcast(f"SVR-KEY-EX-ReINIT:{host}:{publicKey}")




print("Server up and running........")

#keyEx("H1","2d2d2d2d2d424547494e20525341205055424c4943204b45592d2d2d2d2d0a4d49474a416f4742414b6f384a324951376335437372736b56794932586c463243504f78575a753149694944486e687669636a5a616842527045584e6e6569760a724b59653955623278636f36597035426b3565504d653946793456457145637739447137384a6d45314d516d6b654a4453736b667a4e4a4a3730586e7a456e560a6e5255635834714d3471564f62375658784f324475376138314f484a6f325a64565378712f6f393841545870667232493246435041674d424141453d0a2d2d2d2d2d454e4420525341205055424c4943204b45592d2d2d2d2d0a")

def SERVER(_,__):
    try:
        while True:
            conn, addr = SVR.accept()
            with conn:
                print(f"Connected by {addr}")
                connections.append(conn)
                data = conn.recv(4096).decode()

                if("NEW-CON" in data): #NEW-CON:HOST:PubK
                    data = data.split(":")
                    hosts.append(data[1])
                    #pubKeys[data[1]] = data[2]

                    #print(data)
                    #print(f"{data[1]} => {data[2]}")
                    
                    keyEx(data[1],data[2])
                    
                    #keyEx_thread = threading.Thread(target=keyEx, args=(data[1],data[2]))
                    #keyEx_thread.start()

                    


                else:
                    print(f"{addr} -> {data}")
                    thread = threading.Thread(target=broadcast, args=("SVR-REPLY",))
                    thread.start()

    except:
        print("Server Stopped!")


if __name__ == "__main__":
    SVR_thread = threading.Thread(target=SERVER, args=("",""))
    SVR_thread.start()
    #SERVER()