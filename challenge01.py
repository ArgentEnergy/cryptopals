#!/usr/bin/env python3
"""Cryptopals Set 1 Challenge 1"""
import base64


def main():
    inp = (
        "49276d206b696c6c696e6720796f757220627261696e206c"
        "696b65206120706f69736f6e6f7573206d757368726f6f6d"
    )
    inp = bytes.fromhex(inp)
    result = base64.encodebytes(inp).strip().decode()
    print("[*] Result: {}".format(result))


if __name__ == "__main__":
    main()
