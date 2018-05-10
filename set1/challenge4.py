#!/usr/bin/env python3
"""Cryptopals Set 1 Challenge 4"""
from challenge3 import decrypt_message


def _decrypt_line(line):
    """
    Decrypts the line using single character XOR.

    :param line: the encrypted line
    :type line: str
    :returns: the score, key, and decrypted line
    :rtype: (float, str, str)
    """
    return decrypt_message(bytes.fromhex(line))


def main():
    # https://cryptopals.com/static/challenge-data/4.txt
    with open("4.txt", 'r') as f:
        lines = [line.strip() for line in f]

    rs = map(lambda l: _decrypt_line(l), lines)
    result = max(rs, key=lambda r: r["score"])
    result = (result["key"], result["message"].strip())
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
