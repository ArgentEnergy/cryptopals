#!/usr/bin/env python3
"""Cryptopals Set 2 Challenge 10"""
import base64
from Crypto.Cipher import AES

from challenge06 import get_blocks
from challenge09 import pkcs7_pad, pkcs7_unpad


def _xor(a, b):
    """
    Runs XOR on the first bytes object against the second bytes object.
    :param a: first bytes object
    :param b: second bytes object
    :type a: bytes
    :type b: bytes
    :returns: the XOR'd string in bytes
    :rtype: bytes
    """
    return bytes([c ^ d for c, d in zip(a, b)])


def aes_ecb_encrypt(plaintext, key):
    """
    Encrypts the plaintext using AES ECB mode.

    :param plaintext: the plaintext to encrypt
    :param key: the encryption key
    :type plaintext: bytes
    :type key: str
    :returns: the ciphertext
    :rtype: bytes
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pkcs7_pad(plaintext, AES.block_size))


def aes_ecb_decrypt(ciphertext, key):
    """
    Decrypts the ciphertext using AES ECB mode.

    :param ciphertext: the ciphertext to decrypt
    :param key: the encryption key
    :type ciphertext: bytes
    :type key: str
    :returns: the plaintext
    :rtype: bytes
    """
    cipher = AES.new(key, AES.MODE_ECB)
    return pkcs7_unpad(cipher.decrypt(ciphertext))


def aes_cbc_encrypt(plaintext, key, iv):
    """
    Encrypts the plaintext using AES CBC mode.

    :param plaintext: the plaintext to encrypt
    :param key: the encryption key
    :param iv: the initialization vector
    :type plaintext: bytes
    :type key: str
    :type iv: bytes
    :returns: the ciphertext
    :rtype: bytes
    """
    size = len(iv)

    ciphertext = b""
    pb = iv
    for cb in get_blocks(plaintext, size):
        cb = pkcs7_pad(cb, size)
        encrypted_block = aes_ecb_encrypt(_xor(cb, pb), key)
        ciphertext += encrypted_block
        pb = encrypted_block
    return ciphertext


def aes_cbc_decrypt(ciphertext, key, iv):
    """
    Decrypts the ciphertext using AES CBC mode.

    :param ciphertext: the ciphertext to decrypt
    :param key: the encryption key
    :param iv: the initialization vector
    :type ciphertext: bytes
    :type key: str
    :type iv: bytes
    :returns: the plaintext
    :rtype: bytes
    """
    plaintext = b""
    pb = iv
    for cb in get_blocks(ciphertext, len(iv)):
        decrypted_block = aes_ecb_decrypt(cb, key)
        decrypted_block = _xor(pb, decrypted_block)
        plaintext += decrypted_block
        pb = cb
    return pkcs7_unpad(plaintext)


def main():
    iv = b"\x00" * AES.block_size
    key = "YELLOW SUBMARINE"

    # Tests that the encryption and decryption works
    data = b"This is a plain string to test"
    ciphertext = aes_cbc_encrypt(data, key, iv)
    plaintext = aes_cbc_decrypt(ciphertext, key, iv)
    assert data == plaintext

    # https://cryptopals.com/static/challenge-data/10.txt
    with open("10.txt", 'r') as f:
        result = aes_cbc_decrypt(base64.b64decode(f.read()), key, iv)
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
