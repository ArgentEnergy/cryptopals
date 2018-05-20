#!/usr/bin/env python3
"""Cryptopals Set 2 Challenge 16"""
from Crypto.Cipher import AES
from Crypto import Random

from challenge06 import get_blocks
from challenge10 import aes_cbc_encrypt, aes_cbc_decrypt


class Oracle:
    """Oracle that encrypts plaintext using CBC mode."""

    def __init__(self):
        self._key = Random.new().read(AES.block_size)
        self._iv = Random.new().read(AES.block_size)
        self._prefix = b"comment1=cooking%20MCs;userdata="
        self._suffix = b";comment2=%20like%20a%20pound%20of%20bacon"

    def encrypt(self, plaintext):
        """
        Encrypts the plaintext using CBC.

        :param plaintext: the plaintext to encrypt
        :type plaintext: bytes
        :returns: the ciphertext
        :rtype: bytes
        """
        data = plaintext.replace(b";", b'";"').replace(b"=", b'"="')
        data = self._prefix + data + self._suffix
        return aes_cbc_encrypt(data, self._key, self._iv)

    def has_admin_string(self, ciphertext):
        """
        Decrypts the ciphertext and checks if the admin string is in the 
        plaintext.

        :param ciphertext: the ciphertext to decrypt
        :type ciphertext: bytes
        :returns: True if the admin string is found, otherwise False
        :rtype: bool
        """
        plaintext = aes_cbc_decrypt(ciphertext, self._key, self._iv)
        return b";admin=true;" in plaintext

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


def _get_prefix_end(oracle, block_size):
    """
    Gets the prefix end block index.

    :param oracle: the encryption oracle
    :param block_size: the block size
    :type oracle: Oracle
    :type block_size: int
    :returns: the prefix end block index
    :rtype: int
    """
    ciphertext1 = oracle.encrypt(b"")
    ciphertext2 = oracle.encrypt(b"a")

    blocks1 = get_blocks(ciphertext1, block_size)
    blocks2 = get_blocks(ciphertext2, block_size)
    prefix_end_block = 0

    for i, (b1, b2) in enumerate(zip(blocks1, blocks2)):
        if b1 != b2:
            prefix_end_block = i
            break
    return prefix_end_block


def _perform_bitflipping(oracle):
    """
    Performs a bitflipping attack against CBC encryption mode.

    :param oracle: the CBC oracle to perform bitflipping
    :type oracle: Oracle
    :returns: True if the ciphertext has the admin string, otherwise False
    :rtype: bool
    """
    # Encrypt the payload; ? in ASCII is 63
    delimiter = b"?"
    payload = delimiter + b"admin" + delimiter + b"true" + delimiter
    ciphertext = oracle.encrypt(payload)

    block_size = oracle.get_block_size()
    blocks = get_blocks(ciphertext, block_size)
    # -1 is used as index starts at 0
    i = _get_prefix_end(oracle, block_size) - 1

    block = list(blocks[i])
    # 63 ^ 4 = 59 (";")
    block[0] ^= 4
    # 63 ^ 2 = 61 ("=")
    block[6] ^= 2
    # 63 ^ 4 = 59 (";")
    block[11] ^= 4

    blocks[i] = bytes(block)
    return oracle.has_admin_string(b"".join(blocks))


def main():
    oracle = Oracle()
    assert oracle.has_admin_string(oracle.encrypt(b";admin=true;")) == False

    result = _perform_bitflipping(oracle)
    assert result == True
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
