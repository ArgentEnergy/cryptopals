#!/usr/bin/env python3
"""Cryptopals Set 2 Challenge 9"""


def pkcs7_pad(data, size):
    """
    Pads the incoming data to the incoming size.

    :param data: the data to pad
    :param size: the size of the data with padding
    :type data: bytes
    :type size: int
    :returns: the padded data
    :rtype: bytes
    """
    # https://en.wikipedia.org/wiki/Padding_(cryptography)
    if len(data) == size:
        return data
    pad = (size - len(data) % size)
    return data + bytes([pad]) * pad


def pkcs7_unpad(data):
    """
    Removes the padding from the data.

    :param data: the data to remove the padding
    :type data: bytes
    :type pad: bytes
    :returns: the unpadded data
    :rtype: bytes
    """
    if len(data) == 0:
        raise Exception("The input data needs to be at least one byte")

    # Grab the last bytes based on the last numeric value
    padding = data[-data[-1]:]

    if all(i == len(padding) for i in padding):
        return data.rstrip(bytes([data[-1]]))
    return data


def main():
    block_size = 20
    plaintext = b"YELLOW SUBMARINE"
    result = pkcs7_pad(plaintext, block_size)

    assert pkcs7_unpad(result) == plaintext
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
