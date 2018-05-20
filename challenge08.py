#!/usr/bin/env python3
"""Cryptopals Set 1 Challenge 8"""
from itertools import combinations


from challenge06 import get_blocks

def is_ecb_encrypted(data):
    """
    Determines if the data is encrypted with ECB.

    :param data: the data to process
    :type data: bytes
    :returns: True if ECB encrypted
    :rtype: bool
    """
    blocks = get_blocks(data, 16)
    pairs = list(combinations(blocks, 2))
    dists = [p1 == p2 for p1, p2 in pairs]

    # With all the combinations, if it finds identical blocks then the string
    # is encrypted with ECB
    return True in dists


def main():
    result = None

    # https://cryptopals.com/static/challenge-data/8.txt
    with open("8.txt", 'r') as f:
        i = 1
        for line in f:
            result = bytes.fromhex(line.strip())

            if is_ecb_encrypted(result):
                result = (i, line.strip())
                break
            i += 1

    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
