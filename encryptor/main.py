import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime

import struct

# from Crypto.Math.Numbers import Integer
from Crypto.PublicKey import RSA 

from icecream import ic

def start():


    # ty = type("hello world".encode("utf-8").decode('utf-8'))
    # print(ty)

    key = RSA.generate(2048)
    # private_key = key.export_key
    # ic(private_key)

    public_key = key.publickey().export_key()
    # ic(public_key)

    choice = input("s for sym, a for asym: ")
    if choice.upper() == 'S':
        runSym()
    elif choice.upper() == 'A':
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

# new functionalities: generation of key-pairs, asymetric encryption and decryption of files
def runAsym():
    choice = input('g for generate rsa-keys, e for encrypt, d for decrypt: ')
    if choice.upper() == 'G':
        generate_keys()
    elif choice.upper() == 'E':
        encrypt()
    elif choice.upper() == 'D':
        decrypt()

def generate_keys():

    # :ivar n: RSA modulus
    # :vartype n: integer

    # :ivar e: RSA public exponent
    # :vartype e: integer

    # :ivar d: RSA private exponent
    # :vartype d: integer

    # :ivar p: First factor of the RSA modulus
    # :vartype p: integer

    # :ivar q: Second factor of the RSA modulus
    # :vartype q: integer

    # p = getPrime(255) # for modulus n = 512
    # q = getPrime(256)
    # n = p*q
    # phi = (p-1)*(q-1)
    # e = 65537
    # d = pow(e, -1, phi)
    # ic(d)
    # cipher = (m**e) % n
    # plain = (cipher**d) % n

    (n, e, d) = generate_rsa()

    private_key = json.dumps({'n': n, 'd': d}) # 'e': e, 'd': d, 'p': p, 'q': q})
    public_key = json.dumps({'n': n, 'e': e})
    ic(private_key)
    ic(public_key)

    print('write private key: ')
    write_json(private_key)
    print('write public key: ')
    write_json(public_key)


def encrypt():

    # 1. Receive a public key as an argument
    ########################################
    print('load public key: ')
    public_key = json.loads(get_json())
    n = public_key['n']
    e = public_key['e']

    # #
    print('load private key: ')
    private_key = json.loads(get_json())
    n = private_key['n']
    d = private_key['d']

    # alice = MY_RSA()

    # key_sym = get_random_bytes(3)
    # ic(key_sym)
    # enc = alice.encrypt(key_sym)
    # ic(enc)
    # dec = alice.decrypt(enc)
    # ic(dec)
    #

    

    # 2. Generate a symmetric key for an AEAD cipher
    ################################################
    # print('generate symmetric key: ')
    key_sym_bytes = get_random_bytes(16)
    ic(key_sym_bytes)
    cipher_sym = AES.new(key_sym_bytes, AES.MODE_EAX)
    
    # 3. Encrypt the body of the file with the symmetric AEAD cipher
    ################################################################
    print('get file to encrypt with aead: ')
    # data = get_data()
    data = b'hello world'
    ciphertext, tag = cipher_sym.encrypt_and_digest(data)

    # 4. Encrypt the symmetric key with the public asymetric key
    ############################################################
    # key_sym_int = struct.unpack('B', key_sym_bytes[0:1])[0]
    key_sym_int = int.from_bytes(key_sym_bytes, byteorder='big', signed=False)
    ic(key_sym_int)

    key_sym_encrypted_int = pow(key_sym_int, e, n)
    # key_sym_encrypted_int = (key_sym_int**e) % n
    ic(key_sym_encrypted_int)
    # key_sym_encrypted_bytes = struct.pack('B', key_sym_encrypted_int)
    # key_sym_encrypted_bytes = int.to_bytes(key_sym_encrypted_int, 40, 'big', signed=False)
    # ic(key_sym_encrypted_bytes)

    # Test decryption
    #################
    # key_sym_encrypted_int = int.from_bytes(key_sym_encrypted_bytes, byteorder='big', signed=False)
    # key_sym_decrypted_int = (key_sym_encrypted_int**d) % n
    # ic(key_sym_decrypted_int)
    # key_sym_decrypted_bytes = int.to_bytes(key_sym_decrypted_int, 4, 'big', signed=False)
    # ic(key_sym_decrypted_bytes)

    # 5. Append the encrypted symmetric key and the encrypted body of the file
    # 6. Save this result as the file
    ##########################################################################
    ct = b64encode(ciphertext).decode('utf-8')
    tag = b64encode(tag).decode('utf-8')
    nonce = b64encode(cipher_sym.nonce).decode('utf-8')
    result = json.dumps({'aead_key': str(key_sym_encrypted_int), 'ciphertext': ct, 'tag': tag, 'nonce': nonce})
    write_json(result)
    ic(result)

    # file = input("writing cypher_sym to what file? ")
    # file_out = open(file, "wb")
    # [ file_out.write(x) for x in (cipher_sym.nonce, tag, ciphertext) ]
    # file_out.close()
    
    # key_sym_encrypted_bytes = key_sym_encrypted.to_bytes(16, byteorder='big')
    # ic(key_sym_encrypted_bytes)
    # print('write encrypted sym key: ')
    # write_key(key_sym_encrypted_bytes)
    

def decrypt():
    # 1. Receive a private key as an argument
    #########################################
    print('load private key: ')
    private_key = json.loads(get_json())
    n = private_key['n']
    d = private_key['d']

    # 2. Extract the encrypted symmetric key and the encrypted content from the file
    ################################################################################
    result = get_json()
    b64 = json.loads(result)
    ct = b64decode(b64['ciphertext'])
    tag = b64decode(b64['tag'])
    nonce = b64decode(b64['nonce'])
    aead_encrypted = int(b64['aead_key'])
    ic(aead_encrypted)

    # 3. Decrypt the symmetric key with the private asymmetric key
    ##############################################################
    # aead_int = (aead_encrypted**d) % n
    aead_int = pow(aead_int, d, n)
    aead_bytes = int.to_bytes(aead_int, 16, 'big', signed=False)
    ic(aead_bytes)

    # 4. Decrypt the encrypted body of the file using the symmetric key
    ###################################################################
    cipher = AES.new(aead_bytes, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    write_data(data)

    # print('load encrypted sym key: ')
    # key_sym_encrypted_bytes = get_key()
    # ic(key_sym_encrypted_bytes)
    # key_sym_encrypted = int.from_bytes(key_sym_encrypted_bytes, byteorder='big')
    # key_sym = (key_sym_encrypted**d) % n
    # key_sym_bytes = key_sym.to_bytes(2, byteorder='big')
    # ic(key_sym_bytes)


    # file = input('read symmetrically encrypted from what file? ')
    # file_in = open(file, 'rb')
    # nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ]
    # file_in.close()
    # cipher = AES.new(key_sym_bytes, AES.MODE_EAX, nonce)
    # data = cipher.decrypt_and_verify(ciphertext, tag)
    # ic(data)

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

RSA_DEFAULT_EXPONENT = 65537
RSA_DEFAULT_MODULUS_LEN = 2048

def generate_rsa(key_length=RSA_DEFAULT_MODULUS_LEN, exponent=RSA_DEFAULT_EXPONENT):
    e = exponent
    t = 0
    p = q = 2

    while gcd(e, t) != 1:
        # just use getPrime or the one from original??
        p = getPrime(key_length // 2) 
        q = getPrime(key_length // 2)
        t = lcm(p - 1, q - 1)

    n = p * q
    d = invmod(self.e, t)
    return(n, e, d)
    
class MY_RSA:
    """Implements the RSA public key encryption/decryption with default
    exponent 65537 and default key size 2048"""

    def __init__(self, key_length=RSA_DEFAULT_MODULUS_LEN, exponent=RSA_DEFAULT_EXPONENT):
        self.e = exponent
        # self.fast = fast_decrypt
        t = 0
        p = q = 2

        while gcd(self.e, t) != 1:
            p = getPrime(key_length // 2)
            q = getPrime(key_length // 2)
            t = lcm(p - 1, q - 1)

        self.n = p * q
        self.d = invmod(self.e, t)

        # if (fast_decrypt):
            # self.p, self.q = p, q
            # self.d_P = self.d % (p - 1)
            # self.d_Q = self.d % (q - 1)
            # self.q_Inv = invmod(q, p)

    def encrypt(self, binary_data: bytes):
        # int_data = uint_from_bytes(binary_data)
        int_data = struct.unpack('B', binary_data[0:1])[0]
        return pow(int_data, self.e, self.n)

    def decrypt(self, encrypted_int_data: int):
        int_data = pow(encrypted_int_data, self.d, self.n)
        return struct.pack('B', int_data) # uint_to_bytes(int_data)


def exgcd(a, b):
    """Extended Euclidean Algorithm that can give back all gcd, s, t 
    such that they can make Bézout's identity: gcd(a,b) = a*s + b*t
    Return: (gcd, s, t) as tuple"""
    old_s, s = 1, 0
    old_t, t = 0, 1
    while b:
        q = a // b
        s, old_s = old_s - q * s, s
        t, old_t = old_t - q * t, t
        a, b = b, a % b
    return a, old_s, old_t

def invmod(e, m):
    """Find out the modular multiplicative inverse x of the input integer
    e with respect to the modulus m. Return the minimum positive x"""
    g, x, y = exgcd(e, m)
    assert g == 1

    # Now we have e*x + m*y = g = 1, so e*x ≡ 1 (mod m).
    # The modular multiplicative inverse of e is x.
    if x < 0:
        x += m
    return x

def gcd(a, b):
    '''Computes the Great Common Divisor using the Euclid's algorithm'''
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    """Computes the Lowest Common Multiple using the GCD method."""
    return a // gcd(a, b) * b
