#!/usr/bin/env python3
"""Cryptopals Set 1 Challenge 3"""

# Ref: https://en.wikipedia.org/wiki/Letter_frequency
_FREQS = {
    ' ': 0.17200, 'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253,
    'e': 0.12702, 'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966,
    'j': 0.00153, 'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749,
    'o': 0.07507, 'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327,
    't': 0.09056, 'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150,
    'y': 0.01974, 'z': 0.00074
}


def _xor(input_bytes, key):
    """
    Runs XOR on the input bytes using the key to decrypt the message.
    :param input_bytes: bytes object
    :param key: single character ASCII code
    :type input_bytes: bytes
    :type key: int
    :returns: the decrypted message
    :rtype: str
    """
    result = [i ^ key for i in input_bytes]
    return "".join(chr(x) for x in result)


def _get_score(msg):
    """
    Gets the score.
    :param msg: decrypted message
    :type msg: str
    :returns: the score
    :rtype: float
    """
    score = 0
    # Zero values for characters not in the frequency dictionary
    # Score is the sum of each character frequency in the output
    score = sum(_FREQS.get(i.lower(), 0) for i in msg)
    return float(score)


def decrypt_message(data):
    """
    Decrypts the byte string using single character XOR.

    :param data: encrypted message
    :type data: bytes
    :returns: the key and decrypted message
    :rtype: (str, str)
    """
    max_score = 0
    result = {
        "score": 0,
        "key": None,
        "message": None
    }

    for k in range(256):
        msg = _xor(data, k)
        score = _get_score(msg)
        if score > max_score:
            max_score = score
            result["score"] = score
            result["key"] = chr(k)
            result["message"] = msg
    return result


def main():
    inp = (
        "1b37373331363f78151b7f2b783431333d"
        "78397828372d363c78373e783a393b3736"
    )
    inp = bytes.fromhex(inp)
    result = decrypt_message(inp)
    print("[*] Result: {}".format((result["key"], result["message"])))


if __name__ == "__main__":
    main()
