#!/usr/bin/env python3
"""Cryptopals Set 2 Challenge 11"""
from Crypto.Cipher import AES
from Crypto import Random
import random

from challenge08 import is_ecb_encrypted
from challenge10 import aes_ecb_encrypt, aes_cbc_encrypt


def _encrypt(plaintext):
    """
    Encrypts the plaintext using ECB or CBC.

    :param plaintext: the plaintext to encrypt
    :type plaintext: bytes
    :returns: the encryption mode and ciphertext
    :rtype: (str, bytes)
    """
    front_pad = Random.new().read(random.randint(5, 10))
    back_pad = Random.new().read(random.randint(5, 10))

    data = front_pad + plaintext + back_pad
    size = AES.block_size
    key = Random.new().read(size)

    if bool(random.randint(0, 1)):
        # CBC encryption
        iv = Random.new().read(size)
        ciphertext = aes_cbc_encrypt(data, key, iv)
        mode = "CBC"
    else:
        # ECB encryption
        ciphertext = aes_ecb_encrypt(data, key)
        mode = "ECB"
    return (mode, ciphertext)


def _detect_cipher(ciphertext):
    """
    Detects the cipher used.

    :param ciphertext: the ciphertext to determine the cipher
    :type ciphertext: bytes
    :returns: the cipher mode used for encryption
    :rtype: str
    """
    # If there are repetitions then it's ECB
    return "ECB" if is_ecb_encrypted(ciphertext) else "CBC"


def main():
    # Create plaintext that has repeating characters for ECB detection
    plaintext = bytes([0]*64)
    mode, ciphertext = _encrypt(plaintext)

    # Test detection
    detected = _detect_cipher(ciphertext)
    assert mode == detected
    print("[*] Result: {}".format((mode, ciphertext)))


if __name__ == "__main__":
    main()
