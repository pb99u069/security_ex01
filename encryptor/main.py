from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from icecream import ic
import os

# home_directory = os.path.expanduser( '~')
# print(home_directory)

# text = str.encode(input("prompt: "))
# data = b'secret data'

# key = get_random_bytes(16)
# cipher = AES.new(key, AES.MODE_EAX)
# ciphertext, tag = cipher.encrypt_and_digest(text)

# def start():
#     print(key)
#     file_out = open("encrypted.bin", "wb")
#     [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
#     file_out.close()

#     file_in = open("encrypted.bin", "rb")
#     nonce2, tag2, ciphertext2 = [ file_in.read(x) for x in (16, 16, -1) ]
#     file_in.close()

#     cipher2 = AES.new(key, AES.MODE_EAX, nonce2)
#     data2 = cipher2.decrypt_and_verify(ciphertext, tag)

#     print(data2)
#     # print(dec)

# secret_code = "Unguessable"
# key = RSA.generate(2048)
# encrypted_key = key.export_key(passphrase=secret_code, pkcs=8, protection="scryptAndAES128-CBC")

# file_out = open("rsa_key.bin", "wb")
# file_out.write(encrypted_key)
# file_out.close()


# def start():
#     print(key.public_key().export_key())

    
#     encoded_key = open("rsa_key.bin", "rb").read()
#     key2 = RSA.import_key(encoded_key, passphrase=secret_code)

#     print(key.public_key().export_key())

key = RSA.generate(2048)
private_key = key.export_key()
file_out = open("private.pem", "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().export_key()
file_out = open("receiver.pem", "wb")
file_out.write(public_key)
file_out.close()

def start():
    data = "how I met i plodder".encode("utf-8")

    file_out = open("encrypted_data.bin", "wb")
    recipient_key = RSA.import_key(open("receiver.pem").read())
    # recipient_key = public_key
    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
    file_out.close()


    # on the recipients side
    file_in = open("encrypted_data.bin", "rb")

    private_key1 = RSA.import_key(open("private.pem").read())

    enc_session_key1, nonce1, tag1, ciphertext1 = [ file_in.read(x) for x in (private_key1.size_in_bytes(), 16, 16, -1) ]
    file_in.close()

    ic(nonce1)
    ic(tag1)

    cipher_rsa1 = PKCS1_OAEP.new(private_key1)
    session_key1 = cipher_rsa1.decrypt(enc_session_key1)

    cipher_aes1 = AES.new(session_key1, AES.MODE_EAX, nonce1)
    data1 = cipher_aes1.decrypt_and_verify(ciphertext1, tag1)
    print(data1.decode("utf-8"))
    