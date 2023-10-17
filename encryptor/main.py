import json
import struct
from icecream import ic

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

def start():
    while True:
        print()
        choice = input("Choose s for symmetric encryption, a for asymmetric encrpytion, q to quit: ")
        if choice.upper() == 'S':
            run_sym()
        elif choice.upper() == 'A':
            run_asym()
        elif choice.upper() == 'Q':
            break
        else:
            print('command not found, please try again.')

def run_sym():
    choice = input('Choose mode, e for ecb, c for cbc, a for eax: ')
    if choice.upper() == 'E':
        run_ecb()
    elif choice.upper() == 'C':
        run_cbc()
    elif choice.upper() == 'A':
        run_eax()
    else:
        print('command not found, please try again.')
        run_sym()

def run_ecb():
    choice = input('Choose e for encryption, d for decryption: ')
    if choice.upper() == 'E':
        run_ecb_encrypt()
    elif choice.upper() == 'D':
        run_ecb_decrypt()
    else:
        print('command not found, please try again.')
        run_ecb()

def run_ecb_encrypt():
    print('encrypting file in ecb mode..')
    file = input('indicate file to encrypt: ')
    data = get_binary(file)
    ic(data)
    print('generating key..')
    key = get_random_bytes(32)
    file = input('indicate file to write key: ')
    write_binary(file, key)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(data, 16))
    file = input('indicate file to write encrypted message: ')
    write_binary(file, ciphertext)

def run_ecb_decrypt():
    print('decrypting file in ecb mode..')
    file = input('indicate file to get key: ')
    key = get_binary(file)
    file = input('indicate file to get encrypted message: ')
    ciphertext = get_binary(file)
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    ic(plaintext)
    
def run_cbc():
    choice = input("Choose e for encryption, d for decryption: ")
    if choice.upper() == 'E':
        run_cbc_encrypt()
    elif choice.upper() == 'D':
        run_cbc_decrypt()
    else:
        print('command not found, please try again.')
        run_cbc()

def run_cbc_encrypt():
    print('encrypting file in cbc mode..')
    file = input('indicate file to encrypt: ')
    data = get_binary(file)
    ic(data)
    print('generating key..')
    key = get_random_bytes(16)
    file = input('indicate file to write key: ')
    write_binary(file, key)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(data, AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')
    result = json.dumps({'iv': iv, 'ciphertext': ct})
    file = input('indicate file to write encrypted message: ')
    write_plaintext(file, result)

def run_cbc_decrypt():
    print('decrypting file in cbc mode..')
    file = input('indicate file to get key: ')
    key = get_binary(file)
    file = input('indicate file to get encrypted message: ')
    result = get_plaintext(file)
    b64 = json.loads(result)
    iv = b64decode(b64['iv'])
    ct = b64decode(b64['ciphertext'])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), AES.block_size)
    ic(plaintext)
    file = input('indicate file to write decrypted message: ')
    write_binary(file, plaintext)

def run_eax():
    choice = input("Choose e for encryption, d for decryption: ")
    if choice.upper() == 'E':
        run_eax_encrypt()
    elif choice.upper() == 'D':
        run_eax_decrypt()
    else:
        print('command not found, please try again.')
        run_eax()

def run_eax_encrypt():
    print('encrypting file in eax mode..')
    file = input('indicate file to encrypt: ')
    data = get_binary(file)
    ic(data)
    print('generating key..')
    key = get_random_bytes(16)
    file = input('indicate file to write key: ')
    write_binary(file, key)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    file = input('indicate file to write encrypted message: ')
    file_out = open(file, 'wb')
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()

def run_eax_decrypt():
    print('decrypting file in eax mode..')
    file = input('indicate file to get key: ')
    key = get_binary(file)
    file = input('indicate file to get encrypted message: ')
    file_in = open(file, 'rb')
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    file_in.close()
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    ic(plaintext)

def run_asym():
    choice = input('Choose g to generate rsa-keys, e for encryption, d for decryption: ')
    if choice.upper() == 'G':
        generate_keys()
    elif choice.upper() == 'E':
        encrypt()
    elif choice.upper() == 'D':
        decrypt()
    else:
        print('command not found, please try again.')
        run_asym()

def generate_keys():
    print('generating rsa-key..')
    (n, e, d) = generate_rsa()
    private_key = json.dumps({'n': n, 'd': d}) # 'e': e, 'd': d, 'p': p, 'q': q})
    public_key = json.dumps({'n': n, 'e': e})
    ic(private_key)
    ic(public_key)

    file = input('indicate file to write private key: ')
    write_plaintext(file, private_key)
    file = input('indicate file to write public key: ')
    write_plaintext(file, public_key)

def encrypt():
    # 1. Receive a public key as an argument
    ########################################
    file = input('indicate file to get public key: ')
    public_key = json.loads(get_plaintext(file))
    n = public_key['n']
    e = public_key['e']

    # 2. Generate a symmetric key for an AEAD cipher
    ################################################
    print('generating aead key..')
    aead_bytes = get_random_bytes(16)
    cipher_sym = AES.new(aead_bytes, AES.MODE_EAX)
    
    # 3. Encrypt the body of the file with the symmetric AEAD cipher
    ################################################################
    file = input('indicate file to encrypt with aead key: ')
    data = get_binary(file)
    ic(data)
    ciphertext, tag = cipher_sym.encrypt_and_digest(data)

    # 4. Encrypt the symmetric key with the public asymetric key
    ############################################################
    aead_int = int.from_bytes(aead_bytes, byteorder='big', signed=False)
    aead_int_encrypted = pow(aead_int, e, n)

    # 5. Append the encrypted symmetric key and the encrypted body of the file
    # 6. Save this result as the file
    ##########################################################################
    ct = b64encode(ciphertext).decode('utf-8')
    tag = b64encode(tag).decode('utf-8')
    nonce = b64encode(cipher_sym.nonce).decode('utf-8')
    result = json.dumps({'aead_key': str(aead_int_encrypted), 'ciphertext': ct, 'tag': tag, 'nonce': nonce})
    file = input('indicate file to write encrypted aead key and encrypted message: ')
    write_plaintext(file, result)

def decrypt():
    # 1. Receive a private key as an argument
    #########################################
    file = input('indicate file to get private key: ')
    private_key = json.loads(get_plaintext(file))
    n = private_key['n']
    d = private_key['d']

    # 2. Extract the encrypted symmetric key and the encrypted content from the file
    ################################################################################
    file = input('indicate file to get encrypted aead key and encrypted message: ')
    result = get_plaintext(file)
    b64 = json.loads(result)
    ciphertext = b64decode(b64['ciphertext'])
    tag = b64decode(b64['tag'])
    nonce = b64decode(b64['nonce'])
    aead_encrypted = int(b64['aead_key'])

    # 3. Decrypt the symmetric key with the private asymmetric key
    ##############################################################
    print('decrypting aead key..')
    aead_int = pow(aead_encrypted, d, n)
    aead_bytes = int.to_bytes(aead_int, 16, 'big', signed=False)
    ic(aead_bytes)

    # 4. Decrypt the encrypted body of the file using the symmetric key
    ###################################################################
    print('decrypting message with aead key..')
    cipher = AES.new(aead_bytes, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    ic(data)
    file = input('indicate file to write decrypted message: ')
    write_binary(file, data)

# helper functions
##################
def get_plaintext(file):
    try:
        with open(file, 'r') as file_in:
            contents = file_in.read()
        return contents
    except FileNotFoundError:
        new_file = input('file does not exist, please try again: ')
        contents = get_binary(new_file)
        return contents

def write_plaintext(file, result):
    file_out = open(file, 'w')
    file_out.write(result)
    file_out.close()

def get_binary(file):
    try:
        with open(file, 'rb') as file_in:
            contents = file_in.read()
        return contents
    except FileNotFoundError:
        new_file = input('file does not exist, please try again: ')
        contents = get_binary(new_file)
        return contents
        
def write_binary(file, key):
    file_out = open(file, 'wb')
    file_out.write(key)
    file_out.close()

EXPONENT = 65537
MODULUS = 2048

def generate_rsa(key_length=MODULUS, exponent=EXPONENT):
    e = exponent
    k = key_length
    t = 0
    p = q = 2

    while gcd(e, t) != 1:
        p = getPrime(k // 2) 
        q = getPrime(k // 2)
        t = lcm(p - 1, q - 1)

    n = p * q
    d = invmod(e, t)
    return(n, e, d)

# Extended Euclidean Algorithm    
def exgcd(a, b):
    old_s, s = 1, 0
    old_t, t = 0, 1
    while b:
        q = a // b
        s, old_s = old_s - q * s, s
        t, old_t = old_t - q * t, t
        a, b = b, a % b
    return a, old_s, old_t

# Modular multiplicative inverse of the public key e with respect to the modulus m
def invmod(e, m):
    g, x, y = exgcd(e, m)
    assert g == 1

    # Now we have e*x + m*y = g = 1, so e*x ≡ 1 (mod m).
    # The modular multiplicative inverse of e is x.
    if x < 0:
        x += m
    return x

# Greates common divisor
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

#Lowes Common Multiple
def lcm(a, b):
    return a // gcd(a, b) * b
