#!/usr/bin/env python3
"""Cryptopals Set 1 Challenge 6"""
import base64
from itertools import combinations, zip_longest

from challenge3 import decrypt_message
from challenge5 import repeat_key_xor


def _get_hamming_distance(x, y):
    """
    Gets the hamming distance between two equal length strings.

    :param x: first byte string
    :param y: second byte string
    :type x: bytes
    :type y: bytes
    :returns: the hamming distance
    :rtype: int
    """
    # Runs XOR on each character and counts the differences
    return sum(bin(a ^ b).count('1') for a, b in zip(x, y))


def _get_blocks(data, size):
    """
    Partitions the data into blocks based on the incoming size.

    :param data: the data to partition
    :param size: the size of the blocks
    :type data: bytes
    :type size: int
    :returns: the blocks
    :rtype: list
    """
    return [data[i:i+size] for i in range(0, len(data), size)]


def _normalize_edit_distance(data, keysize):
    """
    Normalize the edit distances between the data blocks.

    :param data: the encrypted data
    :param keysize: the guessed length of the key
    :type data: bytes
    :type keysize: int
    :returns: the average normalized edit distance
    :rtype: float
    """
    # Break the data into key size blocks and take the first 4 as mentioned
    # in step 4 to use to average the distances
    blocks = _get_blocks(data, keysize)[:4]

    # Create combination pairs of 2 from the blocks
    pairs = list(combinations(blocks, 2))

    dists = [_get_hamming_distance(p1, p2) / float(keysize)
             for p1, p2 in pairs]
    return sum(dists) / len(dists)


def _break_repeat_key_xor(data, keysize):
    """
    Breaks the repeat-key XOR by determining the key from the data and using 
    that key to decrypt the data.
    :param data: data to decrypt
    :param keysize: the most probable key size
    :type data: bytes
    :type keysize: int
    :returns: the key and the decrypted message
    :rtype: (str, str)
    """
    blocks = _get_blocks(data, keysize)

    # Converts blocks to ASCII code values
    transposed_blocks = list(zip_longest(*blocks, fillvalue=0))

    # Build the key from the decrypted blocks
    key = ''.join([decrypt_message(b)["key"] for b in transposed_blocks])
    return (key, repeat_key_xor(data, key))


def main():
    # https://cryptopals.com/static/challenge-data/6.txt
    with open("6.txt") as f:
        data = base64.b64decode(f.read())

    # Determine the most probable key size
    key_range = range(2, 41)
    keysize = min(key_range, key=lambda k: _normalize_edit_distance(data, k))
    key, msg = _break_repeat_key_xor(data, keysize)

    result = (key, base64.b64encode(msg).decode())
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
