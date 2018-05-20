#!/usr/bin/env python3
"""Cryptopals Set 2 Challenge 14"""
import base64
from Crypto.Cipher import AES
from Crypto import Random
import random

from challenge06 import get_blocks
from challenge09 import pkcs7_unpad
from challenge12 import Oracle


class HarderOracle(Oracle):
    """ECB Oracle that encrypts plaintext using ECB."""

    def __init__(self, pad):
        super(HarderOracle, self).__init__(pad)
        self._random_prefix = Random.new().read(random.randint(0, 255))
        self._encrypt = self.encrypt

    def ecb_encrypt(self, plaintext):
        """
        Encrypts the plaintext using ECB.

        :param plaintext: the plaintext to encrypt
        :type plaintext: bytes
        :returns: the ciphertext
        :rtype: bytes
        """
        data = self._random_prefix + plaintext
        return self._encrypt(data)


def _get_next_byte(oracle, block_size, known_bytes, prefix_size):
    """
    Gets the next found byte using the oracle to encrypt the plaintext with
    the known bytes.

    :param oracle: the ECB oracle
    :param block_size: the found block size
    :param known_bytes: the known bytes found so far
    :param prefix_size: the determined random prefix size
    :type oracle: HarderOracle
    :type block_size: int
    :type known_bytes: bytes
    :type prefix_size: int
    :returns: the next found byte or None if we reached the end
    :rtype: bytes
    """
    # Modulus is used to handle next blocks when known bytes exceeds block size
    a = block_size - (prefix_size % block_size)
    b = block_size - (len(known_bytes) % block_size) - 1
    plaintext = b"A" * ((a + b) % block_size)
    records = {}

    for c in range(256):
        payload = plaintext + known_bytes + bytes([c])
        ciphertext = oracle.ecb_encrypt(payload)
        records[c] = ciphertext

    ciphertext = oracle.ecb_encrypt(plaintext)
    blocks = get_blocks(ciphertext, block_size)
    found_byte = None
    i = (prefix_size + len(known_bytes)) // block_size

    for k, v in records.items():
        b = get_blocks(v, block_size)

        try:
            if blocks[i] == b[i]:
                found_byte = bytes([k])
                break
        except IndexError:
            break
    return found_byte


def _get_prefix_end(oracle, block_size):
    """
    Gets the prefix end block index.

    :param oracle: the encryption oracle
    :param block_size: the block size
    :type oracle: HarderOracle
    :type block_size: int
    :returns: the prefix end block index
    :rtype: int
    """
    ciphertext1 = oracle.ecb_encrypt(b"")
    ciphertext2 = oracle.ecb_encrypt(b"a")

    blocks1 = get_blocks(ciphertext1, block_size)
    blocks2 = get_blocks(ciphertext2, block_size)
    prefix_end_block = 0

    for i, (b1, b2) in enumerate(zip(blocks1, blocks2)):
        if b1 != b2:
            prefix_end_block = i
            break
    return prefix_end_block


def _get_prefix_size(oracle, block_size):
    """
    Gets the determined prefix size in bytes.

    :param oracle: the encryption oracle
    :param block_size: the block size
    :type oracle: HarderOracle
    :type block_size: int
    :returns: the determined prefix size
    :rtype: int
    """
    def _is_equal(blocks):
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                return True
        return False

    prefix_end_block = _get_prefix_end(oracle, block_size)
    remainder = 0

    for i in range(block_size):
        fake_input = bytes([0] * (2*block_size + i))
        ciphertext = oracle.ecb_encrypt(fake_input)
        blocks = get_blocks(ciphertext, block_size)

        if _is_equal(blocks):
            remainder = block_size - i

        if remainder != 0:
            break

    # If the remainder using the fake input equals the block size then the
    # random prefix fits equally with the block size
    if remainder == block_size:
        remainder = 0
    return prefix_end_block * block_size + remainder


def main():
    pad = (
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
        "YnkK"
    )
    oracle = HarderOracle(pad)
    block_size = oracle.get_block_size()

    # Following Step 2 as mentioned
    assert oracle.is_ecb() == True

    prefix_size = _get_prefix_size(oracle, block_size)
    # Testing to make sure the random prefix length is determined correctly
    assert len(oracle._random_prefix) == prefix_size

    known_bytes = b""
    while True:
        found_byte = _get_next_byte(oracle, block_size, known_bytes,
                                    prefix_size)
        if found_byte is None:
            break
        known_bytes += found_byte

    result = pkcs7_unpad(known_bytes)
    assert result == base64.b64decode(pad)
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
