import socket
import time
import threading

import rsa
from cryptography.fernet import Fernet

HOST = "127.0.0.1"
PORT = 65432

hosts = []
pubKeys = {}
keys = {}

SVR = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SVR.bind((HOST, PORT))
SVR.listen()


def keyEx(host):
    print(f"Key Ex with {host}")
    newKey = Fernet.generate_key()

def breadcast(dst,msg):
    SVR.send(f"")

def conHandler(address,payload):
    print(f"{address} -> {payload}")
    # if("NEW-CON" in data):
    #     data = data.split(":")
    #pass



try:
    while True:
        conn, addr = SVR.accept()
        with conn:
            #print(f"Connected by {addr}")
            data = conn.recv(4096).decode()

            if("NEW-CON" in data): #NEW-CON:HOST:PubK
                data = data.split(":")
                hosts.append(data[1])
                pubKeys[data[1]] = data[2]

                print(f"{data[1]} => {data[2]}")


            else:
                thread = threading.Thread(target=conHandler, args=(addr,data))
                thread.start()

except:
    print("Server Stopped!")