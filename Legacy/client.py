import socket
import time

import rsa
from cryptography.fernet import Fernet

client = "client1"
HOST = "127.0.0.1"  
PORT = 65432  

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
        print("Decryption Error!")

def keyEx():
    publicKey, privateKey = generateKeys()
    keys["priK"] = privateKey
    keys["pubK"] = publicKey


keyEx()
#time.sleep(5)
#print(f"NEW-CON:{client}:{keys['pubK']._save_pkcs1_pem().hex()}")
#CLIENT.sendall(bytes(f"NEW-CON:{client}:{keys['pubK']._save_pkcs1_pem().hex()}", 'ascii'))

while True:
    #CLIENT.sendall(b"TEST")
    #data = CLIENT.recv(4096)
    #print(data.decode())

    CLIENT.sendall(bytes(f"TEST MSG", 'ascii'))


#keyEx()
#print(keys["pubK"]._save_pkcs1_pem().hex())
