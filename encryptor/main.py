import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad

from icecream import ic
   
    

def start():
    choice = input("sym or asym? ")
    if choice.upper() == 'SYM':
        runSym()
    else:
        runAsym()

def runSym():
    choice = input("ecb, CBC or AES-GCM? ")
    if choice.upper() == 'ECB':
        runECB()
    elif choice.upper() == 'CBC':
        runCBC()
    elif choice.upper() == 'AES-GCM':
        runAES_GCM()

def runECB():
    choice = input("encrypt or decrypt? ")
    if choice.upper() == 'ENCRYPT':
        run_ecb_encrypt()
    elif choice.upper() == 'DECRYPT':
        run_ecb_decrypt()

def run_ecb_encrypt():
    print("encrypt file in ecb mode")
    data = get_data()
    print("generate key: ")
    key = get_random_bytes(32)
    print("write key to what file? ")
    write_key(key)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data, 16))
    print("write ciphertext to what file? ")
    write_data(ciphertext)
    print(ciphertext)

def run_ecb_decrypt():
    print("decrypt file in ecb mode")
    key = get_key()
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = get_data()
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    print(plaintext)
    
def runCBC():
    choice = input("encrypt or decrypt? ")
    if choice.upper() == 'ENCRYPT':
        run_cbc_encrypt()
    elif choice.upper() == 'DECRYPT':
        run_cbc_decrypt()

def run_cbc_encrypt():
    print('encrypt file in cbc mode')
    data = get_data()
    print('generate key: ')
    key = get_random_bytes(16)
    print('write key to what file? ')
    write_key(key)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})
    print(result)

    file_out = open('result.json', 'w')
    file_out.write(result)
    file_out.close()

def run_cbc_decrypt():
    print('decrypt file in cbc mode')
    key = get_key()

    file_in = open('result.json', "r")
    result = file_in.read()
    file_in.close()

    b64 = json.loads(result)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
    print(plaintext)

def runAES_GCM():
    print("aes-gcm")
    data = get_file()
    print("generating AES key")
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print("writing key to key.bin")


    print("writing to encrypted.bin")
    file_out = open("encrypted.bin", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()

def runAsym():
    print("running asym")


def get_data():
    data_file = input("indicate file to encrypt/decrypt: ")
    file_in = open(data_file, "rb")
    data = file_in.read()
    file_in.close()
    return data

def write_data(data):
    data_file = input("name of data file: ")
    file_out = open(data_file, 'wb')
    file_out.write(data)
    file_out.close()

def get_key():
    key_file = input("indicate key file: ")
    file_in = open(key_file, "rb")
    key = file_in.read()
    file_in.close()
    return key

def write_key(key):
    key_file = input('name of key file: ')
    file_out = open(key_file, 'wb')
    file_out.write(key)
    file_out.close()
