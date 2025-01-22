from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from ecb_cbc import *

key = get_random_bytes(16)
iv = get_random_bytes(16)

def main():
    # generate random aes key and iv
    attack_word = bytearray((";admin=true;").encode())
    attack_text = ("x" * 12) + ("X" * 16)
    intext = bytearray(("userid=456;userdata=" + attack_text + ";session-id=31337").encode())
    cipher = bytearray(submit(attack_text))
    for i in range(len(attack_word)):
        xored = intext[i + 32] ^ cipher[i + 16]
        something = xored ^ attack_word[i]
        cipher[i + 16] = something
        print(chr(something ^ xored))
    print(verify(cipher))

#function submit 
def submit(intext: str):
    intext = "userid=456;userdata=" + intext + ";session-id=31337"
    #encode any ; (%3b) and = (%3d) characters
    intext = intext.replace(";", "%3b").replace("=", "%3d").encode()
    cipher = cbc_encrypt(intext, key, iv)
    return cipher

def verify(ciphertext: bytes):
    plaintext = cbc_decrypt(ciphertext, key, iv)
    # cipher = AES.new(key, AES.MODE_CBC, iv)
    # unpad_pkcs7(plaintext, 16)
    print(plaintext)
    if (plaintext.find(b";admin=true;") == -1):
        return False
    return True
    # pt = cipher.decrypt(ciphertext)
    # print(str(pt))
    # return ";admin=true;" in str(pt)


if __name__ == '__main__':
    main()

