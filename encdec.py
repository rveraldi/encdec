#!/usr/bin/env python3
#
# please installa chacha-poly1305 support before running
#
# pip install chacha20poly1305
#
#

import os
import sys
import hashlib
import getpass
import os.path
import base64
try:
    from chacha20poly1305 import ChaCha20Poly1305
except ModuleNotFoundError:
    print("Can't find chacha20poly1305")
    print("run \"pip install chacha20poly1305\"")
    exit(0)

version = "0.1"
cryptext = ".cha"

def usage(pname):
    print("\n")
    print("{}: -c|-d filename".format(pname))
    print("{}: -v".format(pname))
    print("-c encrypt file (output to file.cha)")
    print("-d decrypt file.cha (output to file)")
    print("-v print version")
    print("\n")

def is_binary(filename):
    with open(filename, 'rb') as f:
        for block in f:
            if b'\0' in block:
                return True
    return False


def getkey():
    key = getpass.getpass("Enter passphrase: ")
    key2 = getpass.getpass("Check entered passphrase: ")
    if (key != key2):
        print("passphrase does not match!")
        print("exiting...")
        exit(0)
    key_32 = hashlib.sha256(key.encode()).digest()
    cipher = ChaCha20Poly1305(key_32)
    nonce_12 = hashlib.sha3_256(key.encode()).digest()[:12]
    return key_32,nonce_12,cipher



def main():
    pname = sys.argv[0]
    c = 0
    d = 0
    v = 0

    if ( len(sys.argv) == 3):
        if ( sys.argv[1] == "-c" ):
            c = 1
        if ( sys.argv[1] == "-d" ):
            d = 1
    elif ( len(sys.argv) == 2 and sys.argv[1] == "-v" ):
        v = 1
    else:
        usage(pname)
        exit(0)
    
    if (c):
        tobcrypt=sys.argv[2]
        encrypted=tobcrypt+cryptext
        if (not os.path.exists(tobcrypt)):
            print("file {} doesn't exist".format(tobcrypt))
            exit(0)
        if (os.path.exists(encrypted)):
            print("file {} does already exist".format(encrypted))
            exit(0)
        with open(tobcrypt, 'rb') as file:
            data = file.read()
        hkey, hnonce, cip = getkey()
        ciphertext = cip.encrypt(hnonce,  data)
        with open(encrypted, 'wb') as encfile:
            encfile.write(ciphertext)
        
    if (d):
        encrypted=sys.argv[2]
        if(encrypted.find(cryptext) < 0):
            print("file {} needs to be a {} encrypted file".format(encrypted,cryptext))
            exit(0)
        decrypted=sys.argv[2][:-4]
        if (not os.path.exists(encrypted)):
            print("file {} doesn't exist".format(encrypted))
            exit(0)
        if (os.path.exists(decrypted)):
            print("file {} does already exist".format(decrypted))
            exit(0)
        with open(encrypted, 'rb') as file:
            datacipher = file.read()
        hkey, hnonce, cip = getkey()
        try:
            plaintext = cip.decrypt(hnonce, datacipher)
        except:
            print("Decryption error")
            exit(0)
        with open(decrypted, 'wb') as decrfile:
            decrfile.write(plaintext)

    if (v):
        print("Version {}".format(version))
        


if __name__ == "__main__":
    main()
