#!/usr/bin/env python3
"""Cryptopals Set 1 Challenge 5"""
import binascii
from itertools import zip_longest


def repeat_key_xor(input_bytes, key):
    """
    Runs XOR on the input bytes using a repeating-key XOR implementation.
    :param input_bytes: message in bytes to XOR
    :param key: encryption key
    :type input_bytes: bytes
    :type key: str
    :returns: the XOR'd message
    :rtype: bytes
    """
    size = len(input_bytes)
    repeat = int(size / len(key))
    remainder = size % len(key)

    # e.g. k = ICEICEIC if input_bytes size was 8
    k = key * repeat + (key[:remainder])
    s = list(zip_longest(input_bytes, k))

    result = [a ^ ord(b) for a, b in s]
    return ''.join(chr(x) for x in result).encode()


def main():
    inp = (
        "Burning 'em, if you ain't quick and nimble\n"
        "I go crazy when I hear a cymbal"
    )
    key = "ICE"
    result = binascii.hexlify(repeat_key_xor(inp.encode(), key)).decode()
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
