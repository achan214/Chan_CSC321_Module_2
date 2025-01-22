from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def pad_pkcs7(data, block_size):
    x = len(data) % block_size
    pad_length = block_size - x
    return data + (chr(pad_length) * pad_length).encode()
    #return data + bytes([pad_length]) * pad_length

def unpad_pkcs7(padded_data, block_size):
    # Check if padded_data is empty or invalid
    if not padded_data or len(padded_data) % block_size != 0:
        raise ValueError("Invalid padded data.")
    
    # Get the value of the last byte
    pad_length = padded_data[-1]
    
    # Ensure the padding is valid
    if pad_length < 1 or pad_length > block_size:
        raise ValueError("Invalid padding.")
    
    # Verify that the padding bytes match the expected value
    if padded_data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("Invalid padding.")
    
    # Remove the padding
    return padded_data[:-pad_length]


def ecb_encrypt(plaintext, key):
    # split into 128 bit (16 byte) blocks and add padding
    ciphertext = b''
    print(len(plaintext))
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        if (len(block) < 16):
            block = pad_pkcs7(block, 16)
        cipher = AES.new(key, AES.MODE_ECB)
        ciphertext += cipher.encrypt(block)
    return ciphertext

def cbc_encrypt(plaintext, key, iv):
    # split into 128 bit (16 byte) blocks and add padding
    ciphertext = b''
    prev = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        if (len(block) < 16):
            block = pad_pkcs7(block, 16)
        block = bytes([block[j] ^ prev[j] for j in range(AES.block_size)])
        cipher = AES.new(key, AES.MODE_ECB)
        prev = cipher.encrypt(block)
        ciphertext += prev
    return ciphertext

def ecb_decrypt(ciphertext, key):
    # split into 128 bit (16 byte) blocks
    plaintext = b''
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext += cipher.decrypt(block)
        if (i == len(ciphertext)):
            plaintext = unpad_pkcs7(plaintext, 16)
    return plaintext

def cbc_decrypt(ciphertext, key, iv):
    # split into 128 bit (16 byte) blocks
    plaintext = b''
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = cipher.decrypt(block)
        plaintext += bytes([decrypted[j] ^ prev[j] for j in range(AES.block_size)])
        prev = block
        if (i == len(ciphertext)):
            plaintext = unpad_pkcs7(plaintext, 16)
    return plaintext

def main():

    mode = 'ECB'    # hardcode mode btwn ECB and CBC

    with open('mustang.bmp', 'rb') as f:
        header = f.read(54)  # BMP header is 54 bytes
        # print(header)
        plaintext = f.read()

    f.close()
    # Generate random key and IV
    # AES-CBC uses 16-byte blocks. Both key and IV must be 16 bytes
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    # Encrypt based on mode
    if mode == 'ECB':
        ciphertext = ecb_encrypt(plaintext, key)
    else:
        ciphertext = cbc_encrypt(plaintext, key, iv)

    # Decrypt based on mode
    if mode == 'ECB':
        plaintext = ecb_decrypt(ciphertext, key)
    else:
        plaintext = cbc_decrypt(ciphertext, key, iv)

    # Write to file
    with open('encrypted.bmp', 'wb') as f:
        f.write(header)
        f.write(ciphertext)
        f.close()

    # Write to file
    with open('decrypted.bmp', 'wb') as f:
        f.write(header)
        f.write(plaintext)
        f.close()

if __name__ == '__main__':
    main()
