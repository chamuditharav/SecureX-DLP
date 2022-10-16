import socket
import time

import rsa
from cryptography.fernet import Fernet

client = "client1"
HOST = "127.0.0.1"  
PORT = 65432  

keys = {"priK":"", "pubK":"", "key":""}

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

keyEx()
time.sleep(1)
while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as CLIENT:
        CLIENT.connect((HOST, PORT))
        #CLIENT.sendall(b"Hello, world")
        CLIENT.sendall(bytes(f"NEW-CON:{client}:{keys['pubK']._save_pkcs1_pem().hex()}", 'ascii'))
        data = CLIENT.recv(1024)

    print(f"Received {data!r}")
    time.sleep(5)