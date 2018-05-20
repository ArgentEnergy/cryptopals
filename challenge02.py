#!/usr/bin/env python3
"""Cryptopals Set 1 Challenge 2"""


def _xor(a, b):
    """
    Runs XOR on the first bytes object against the second bytes object.
    :param a: first bytes object
    :param b: second bytes object
    :type a: bytes
    :type b: bytes
    :returns: the XOR'd string converted to hex
    :rtype: str
    """
    result = [a[i] ^ b[i] for i in range(max(len(a), len(b)))]
    return ''.join(format(x, "02x") for x in result)


def main():
    inp_1 = "1c0111001f010100061a024b53535009181c"
    inp_1 = bytes.fromhex(inp_1)

    inp_2 = "686974207468652062756c6c277320657965"
    inp_2 = bytes.fromhex(inp_2)

    result = _xor(inp_1, inp_2)
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
