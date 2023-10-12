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
    choice = input("ecb, cbc or eax? ")
    if choice.upper() == 'ECB':
        run_ecb()
    elif choice.upper() == 'CBC':
        run_cbc()
    elif choice.upper() == 'EAX':
        run_eax()

def run_ecb():
    choice = input("e for encrypt, d for decrypt? ")
    if choice.upper() == 'E':
        run_ecb_encrypt()
    elif choice.upper() == 'D':
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
    
def run_cbc():
    choice = input("e for encrypt, d for decrypt? ")
    if choice.upper() == 'E':
        run_cbc_encrypt()
    elif choice.upper() == 'D':
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
    write_json(result)

def run_cbc_decrypt():
    print('decrypt file in cbc mode')
    key = get_key()
    result = get_json()
    b64 = json.loads(result)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
    print(plaintext)

def run_eax():
    choice = input("e for encrypt, d for decrypt? ")
    if choice.upper() == 'E':
        run_eax_encrypt()
    elif choice.upper() == 'D':
        run_eax_decrypt()

def run_eax_encrypt():
    print("encrypt file in eax mode")
    data = get_data()
    print('generate key: ')
    key = get_random_bytes(16)
    print('write key to what file? ')
    write_key(key)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    file = input("writing to what file? ")
    file_out = open(file, "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()

def run_eax_decrypt():
    print('decrypt file in eax mode')
    key = get_key()
    file = input('read from what file? ')
    file_in = open(file, 'rb')
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    file_in.close()
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print(data)

def runAsym():
    print("running asym")


# helper functions

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

def get_json():
    file = input('what file to read from? ')
    file_in = open(file, "r")
    result = file_in.read()
    file_in.close()
    return result

def write_json(result):
    file = input('what file to save to? ')
    file_out = open(file, 'w')
    file_out.write(result)
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
