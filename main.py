#!/usr/bin/python

from os import urandom
from aes import CBCMode, AES

def new(key, IV=None):
    if IV is None:
        raise ValueError
    return CBCMode(AES(key), IV)

def main(data):
    key_128 = os.urandom(16)
    IV = os.urandom(16)

    print "Input: {}, {} bytes".format(data, len(data))
    print "Key: {}, {} bytes".format(key_128, len(key_128))
    print "IV: {}, {} bytes".format(IV, len(IV))

    encryptor = new(key_128, IV)
    encrypted = encryptor.encrypt(data)
    print "Encrypted: {}, {} bytes".format(encrypted, len(encrypted))
    #print "Hex: " + encrypted.encode('hex')

    decryptor = new(key_128, IV)
    decrypted = decryptor.decrypt(encrypted)
    print "Decrypted: {}, {}".format(decrypted, len(decrypted))
    #print "Hex: " + decrypted.encode('hex')

if __name__ == "__main__":
    plaintext_16 = "thisissecrettext"
    plaintext_32 = "thisissecrettextthisissecrettext"
    plaintext_64 = "thisissecrettextthisissecrettextthisissecrettextthisissecrettext" 
    main(plaintext_64)
