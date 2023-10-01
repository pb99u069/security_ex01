from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

data = b'secret data'

key = get_random_bytes(16)
cipher = AES.new(key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(data)

def start():
    print(key)
    file_out = open("encrypted.bin", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()

    file_in = open("encrypted.bin", "rb")
    nonce2, tag2, ciphertext2 = [ file_in.read(x) for x in (16, 16, -1) ]
    file_in.close()

    cipher2 = AES.new(key, AES.MODE_EAX, nonce2)
    data2 = cipher2.decrypt_and_verify(ciphertext, tag)

    print(data2)
    # print(dec)
