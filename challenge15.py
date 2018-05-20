#!/usr/bin/env python3
"""Cryptopals Set 2 Challenge 15"""

from challenge09 import pkcs7_unpad

_BAD_PADDING_MSG = "Not a valid PKCS7 padded value"


def _is_valid_pkcs7_pad(plaintext):
    """
    Determines if the incoming plaintext has a valid PKCS7 padding.

    :param plaintext: the plaintext with padding
    :type plaintext: bytes
    :throws e: when invalid PKCS7 padding is used
    :returns: the unpadded plaintext
    :rtype: bytes
    """
    padding = plaintext[-plaintext[-1]:]

    is_valid = all(c == len(padding) for c in padding)
    if not is_valid:
        raise Exception(_BAD_PADDING_MSG)
    return pkcs7_unpad(plaintext)


def _run_bad_padded_case(bad_padded_text):
    """
    Runs the bad padded case.

    :param bad_padded_text: bad PKCS7 padded text
    :type bad_padded_text: bytes
    """
    try:
        _is_valid_pkcs7_pad(bad_padded_text)
    except Exception as e:
        assert str(e) == _BAD_PADDING_MSG


def main():
    expected = b"ICE ICE BABY"

    bad_padded_text = expected + b"\x05" * 4
    _run_bad_padded_case(bad_padded_text)

    bad_padded_text = expected + b"\x01\x02\x03\x04"
    _run_bad_padded_case(bad_padded_text)

    padded_text = expected + b"\x04" * 4
    result = _is_valid_pkcs7_pad(padded_text)
    assert result == expected
    print("[*] Result: {}".format(result.decode()))


if __name__ == "__main__":
    main()
