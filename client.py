import socket
import time
import threading

import rsa
from cryptography.fernet import Fernet

clientID = "Client1"
keys = {"priK":"", "pubK":"", "shareKey":""}

# Connecting To Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 65432))


def generateKeys(ksize=1024):
    (publicKey, privateKey) = rsa.newkeys(ksize)
    return publicKey, privateKey

def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        print("Decryption Error!")

def keyEx():
    publicKey, privateKey = generateKeys()
    keys["priK"] = privateKey
    keys["pubK"] = publicKey

    send(f"NEW-CON:{keys['pubK']._save_pkcs1_pem().hex()}")

def receive():
    while True:
        try:
            DataFrame = client.recv(4096).decode('ascii')
            if (f"{clientID}:SVR-KEYEX-RPLY" in DataFrame):
                DataFrame = DataFrame.split(":")
                #print(DataFrame)
                keys["shareKey"] = decrypt(bytes.fromhex(DataFrame[2]),keys["priK"])
                print(keys["shareKey"])
            else:
                print(DataFrame)
        except:
            print("An error occured!")
            client.close()
            break

def send(message):
    client.send(bytes(f"{clientID}:{message}", 'ascii'))


def mainLoop():
    keyEx()
    while True:
        if(not keys["shareKey"] == ""):
            send(str(input("> ")))



receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=mainLoop)
write_thread.start()