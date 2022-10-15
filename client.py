import socket
import time

import rsa
from cryptography.fernet import Fernet

client = "client1"
HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 65432  # The port used by the server

keys = {"priK":"", "pubK":"", "key":""}

CLIENT = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
CLIENT.connect((HOST, PORT))


def generateKeys(ksize=1024):
    (publicKey, privateKey) = rsa.newkeys(ksize)
    return publicKey, privateKey

def encrypt(message, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt(ciphertext, key):
    try:
        return rsa.decrypt(ciphertext, key).decode('ascii')
    except:
        print("Decryption Error")

def keyEx():
    publicKey, privateKey = generateKeys()
    keys["priK"] = privateKey
    keys["pubK"] = publicKey



while True:
    keyEx()
    time.sleep(2)
    CLIENT.sendall(bytes(f"NEW-CON:{client}:{keys['pubK']._save_pkcs1_pem().hex()}", 'ascii'))
    time.sleep(20)



#keyEx()
#print(keys["pubK"]._save_pkcs1_pem().hex())
