#!/usr/bin/env python3
"""Cryptopals Set 2 Challenge 12"""
import base64
from Crypto.Cipher import AES
from Crypto import Random

from challenge06 import get_blocks
from challenge08 import is_ecb_encrypted
from challenge09 import pkcs7_unpad
from challenge10 import aes_ecb_encrypt


class Oracle:
    """Oracle that encrypts plaintext using ECB."""

    def __init__(self, pad):
        self._pad = base64.b64decode(pad)
        self._key = Random.new().read(AES.block_size)

    def encrypt(self, plaintext):
        """
        Encrypts the plaintext using ECB.

        :param plaintext: the plaintext to encrypt
        :type plaintext: bytes
        :returns: the ciphertext
        :rtype: bytes
        """
        data = plaintext + self._pad
        return aes_ecb_encrypt(data, self._key)

    def get_block_size(self):
        """
        Gets the encryption block size.

        :returns: the block size
        :rtype: int
        """
        # Get the initial ciphertext size to use to determine the block size
        payload = b""
        initial_size = len(self.encrypt(payload))
        block_size = 0

        plaintext = b"A"*15
        for c in plaintext:
            payload += c.to_bytes(1, byteorder="little")
            ciphertext = self.encrypt(payload)

            # After so matter iterations the block size can be determined by
            # subtracting the initial size from the current ciphertext size
            block_size = len(ciphertext) - initial_size

            if block_size != 0:
                break
        return block_size

    def is_ecb(self):
        """
        Detects if the encryption used is ECB.

        :returns: True if ECB is used
        :rtype: bool
        """
        plaintext = bytes([0]*64)
        ciphertext = self.encrypt(plaintext)
        return is_ecb_encrypted(ciphertext)


def _get_next_byte(oracle, block_size, known_bytes):
    """
    Gets the next found byte using the oracle to encrypt the plaintext with 
    the known bytes.

    :param oracle: the ECB oracle
    :param block_size: the found block size
    :param known_bytes: the known bytes found so far
    :type oracle: Oracle
    :type block_size: int
    :type known_bytes: bytes
    :returns: the next found byte or None if we reached the end
    :rtype: bytes
    """
    # Modulus is used to handle next blocks when known bytes exceeds block size
    plaintext = b"A" * (block_size - (len(known_bytes) % block_size) - 1)
    records = {}

    for c in range(256):
        payload = plaintext + known_bytes + bytes([c])
        ciphertext = oracle.encrypt(payload)
        records[c] = ciphertext

    ciphertext = oracle.encrypt(plaintext)
    blocks = get_blocks(ciphertext, block_size)
    found_byte = None
    i = len(known_bytes) // block_size

    for k, v in records.items():
        b = get_blocks(v, block_size)

        try:
            if blocks[i] == b[i]:
                found_byte = bytes([k])
                break
        except IndexError:
            break
    return found_byte


def main():
    pad = (
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK"
    )
    oracle = Oracle(pad)
    block_size = oracle.get_block_size()

    # Following Step 2 as mentioned
    assert oracle.is_ecb() == True

    known_bytes = b""
    while True:
        found_byte = _get_next_byte(oracle, block_size, known_bytes)
        if found_byte is None:
            break
        known_bytes += found_byte

    result = pkcs7_unpad(known_bytes)
    assert result == base64.b64decode(pad)
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
