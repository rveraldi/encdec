#!/usr/bin/env python3
#
# please install chacha-poly1305 support before running
#
# pip3 install chacha20poly1305
#
#

import os
import sys
import hashlib
import getpass
import os.path
from random import randrange
import time
import itertools
import re

try:
    from chacha20poly1305 import ChaCha20Poly1305
except ModuleNotFoundError:
    print("Can't find chacha20poly1305")
    print("run \"pip install chacha20poly1305\"")
    exit(0)

version = "0.5"
cryptext = ".cha"
PASSLEN = 12

def usage(pname):
    print("\n")
    print("{} -c|-d filename".format(pname))
    print("{} -v".format(pname))
    print("-c encrypt file (output to file.cha)")
    print("-d decrypt file.cha (output to file)")
    print("-dt decrypt file.cha (txt output sent to terminal)")
    print("-v print version")
    print("\n")



def lfsr(seed, mask):
    result = seed
    nbits = mask.bit_length()-1
    while True:
        result = (result << 1)
        xor = result >> nbits
        if xor != 0:
            result ^= mask
        yield xor, result
        if seed > result:
            break


def isBinary(s):
    encodings = 'ascii', 'utf-8' # , 'utf-16'
    for enc in encodings:
        try:
            s.decode(enc)
        except UnicodeDecodeError:
            return True
    return False


def password_check(password):
    """
        12 characters length or more
        1 digit or more
        1 symbol or more
        1 uppercase letter or more
        1 lowercase letter or more
    """

    # calculating the length
    length_error = len(password) < PASSLEN

    # searching for digits
    digit_error = re.search(r"\d", password) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", password) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", password) is None

    # searching for symbols
    symbol_error = re.search(r"\W", password) is None

    # overall result
    password_ok = not ( length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    if not password_ok:
        return length_error, digit_error, uppercase_error, lowercase_error, symbol_error
    else:
        return True



def getkey(option):
    nonce_12 = 0
    try:
        key = getpass.getpass("Enter passphrase: ")
        res = password_check(key)
        if (option == "-c" and type(res) is tuple):
            if res[0] is True:
                print("Password length must be at least 12 characters")
            if res[1] is True:
                print("Password must contain at least one digit")
            if res[2] is True:
                print("Password must contain at least one uppercase character")
            if res[3] is True:
                print("Password must contain at least one lowercase character")
            if res[4] is True:
                print("Password must contain at least one symbol/special character")
            print("Exiting...")
            exit(0)
    except KeyboardInterrupt:
        print("Exiting...")
        exit(0)
    if (option == "-c"):
        try:
            key2 = getpass.getpass("Check entered passphrase: ")
        except KeyboardInterrupt:
            print("\nExiting...\n")
            exit(0)
        if (key != key2):
            print("passphrase does not match!")
            print("exiting...")
            exit(0)
        else:
            milli = round(time.time() * 1000)
            msk = randrange(100000000000000000,999999999999999999)
            print("Creating nonce...")
            spinner = itertools.cycle(['-', '/', '|', '\\'])
            for xor, sr in lfsr(milli,msk):
                sys.stdout.write(next(spinner))   # write the next character
                sys.stdout.flush()                # flush stdout buffer (actual character display)
                sys.stdout.write('\b')            # erase the last written char
            nonce_12 = hashlib.sha3_256(str(sr).encode()).digest()[:12]
    key_32 = hashlib.sha256(key.encode()).digest()
    cipher = ChaCha20Poly1305(key_32)
    return key_32,nonce_12,cipher


def main():
    pname = sys.argv[0]
    c = 0
    d = 0
    dt = 0
    v = 0

    if ( len(sys.argv) == 3):
        if ( sys.argv[1] == "-c" ):
            c = 1
        if ( sys.argv[1] == "-d" ):
            d = 1
        if ( sys.argv[1] == "-dt" ):
            d = 1
            dt = 1
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
        _, hnonce, cip = getkey("-c")
        ciphertext = cip.encrypt(hnonce,  data)
        with open(encrypted, 'wb') as encfile:
            encfile.write(hnonce)
            encfile.write(ciphertext)
        
    if (d):
        encrypted=sys.argv[2]
        decrypted=sys.argv[2][:-4]
        if(encrypted.find(cryptext) < 0):
            print("file {} needs to be a {} encrypted file".format(encrypted,cryptext))
            exit(0)
        if (not dt):
            if (os.path.exists(decrypted)):
                print("file {} does already exist".format(decrypted))
                exit(0)
        if (not os.path.exists(encrypted)):
            print("file {} doesn't exist".format(encrypted))
            exit(0)
        with open(encrypted, 'rb') as file:
            hnonce = file.read(12)
            datacipher = file.read()
        hkey, _ , cip = getkey("-d")
        try:
            plaintext = cip.decrypt(hnonce, datacipher)
        except:
            print("Decryption error")
            exit(0)
        if (dt):
            if (isBinary(plaintext)):
                print("Decrypted file is not a text file\nCan't output on terminal\nExiting...")
            else:
                print(plaintext.decode())
        else:
            with open(decrypted, 'wb') as decrfile:
                decrfile.write(plaintext)

    if (v):
        print("Version {}".format(version))
        


if __name__ == "__main__":
    main()
