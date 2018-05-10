#!/usr/bin/env python3
"""Cryptopals Set 1 Challenge 7"""
import base64
from Crypto.Cipher import AES


def main():
    key = "YELLOW SUBMARINE"
    obj = AES.new(key, AES.MODE_ECB)

    # https://cryptopals.com/static/challenge-data/7.txt
    with open("7.txt", 'r') as f:
        result = obj.decrypt(base64.b64decode(f.read()))
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
