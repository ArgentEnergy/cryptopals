#!/usr/bin/env python3
"""Cryptopals Set 2 Challenge 13"""
from Crypto.Cipher import AES
from Crypto import Random

from challenge09 import pkcs7_pad
from challenge10 import aes_ecb_encrypt, aes_ecb_decrypt


def _encode_dict(obj):
    """
    Encodes the dictionary to a string.

    :param obj: the dictionary to encode
    :type obj: dict
    :returns: the encoded dictionary as text
    :rtype: bytes
    """
    fields = [k.encode() + b"=" + str(v).encode() for k, v in obj.items()]
    return b'&'.join(fields)


def _decode_text(encoded_text):
    """
    Decodes the encoded text to a dictionary.

    :param encoded_text: the encoded text in query parameter format
    :type encoded_text: bytes
    :returns: the decoded text as a dict
    :rtype: dict
    """
    obj = {}
    for field in encoded_text.split(b"&"):
        values = field.split(b"=")
        key = values[0].decode()
        value = values[1].decode()

        if value.isdigit():
            value = int(value)

        obj[key] = value
    return obj


def _profile_for(email):
    """
    Creates a profile for the email.

    :param email: the email address
    :type email: bytes
    :returns: the profile as a dictionary
    :rtype: dict
    """
    email = email.replace(b'&', b'').replace(b'=', b'')
    return _decode_text(b"email=" + email + b"&uid=10&role=user")


def _encrypt_profile(plaintext, key):
    """
    Encrypt the profile for the incoming plaintext.

    :param plaintext: the plaintext to encrypt
    :param key: the encryption key
    :type plaintext: bytes
    :type key: str
    :returns: the ciphertext
    :rtype: bytes
    """
    encoded_text = _encode_dict(_profile_for(plaintext))
    return aes_ecb_encrypt(encoded_text, key)


def _decrypt_profile(ciphertext, key):
    """
    Decrypt the profile ciphertext.

    :param ciphertext: the ciphertext to decrypt
    :param key: the encryption key
    :type ciphertext: bytes
    :type key: str
    :returns: the plaintext
    :rtype: bytes
    """
    return aes_ecb_decrypt(ciphertext, key)


def _ecb_cut_and_paste(key):
    """
    Cuts the ECB ciphertexts into pieces and combines the ciphertexts to 
    create an admin profile.

    :param key: the encryption key
    :type key: str
    :returns: the ciphertext with the admin role
    :rtype: bytes
    """
    # Block 1 = email=foolz@bar.
    # Block 2 = com&uid=10&role=
    # Block 3 = user\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04
    plaintext = b"foolz@bar.com"
    ciphertext1 = _encrypt_profile(plaintext, key)

    # Block 1 = email=AAAAAAAAAA
    # Block 2 = admin\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04\x04
    # Block 3 = &uid=10&role=use
    block_1 = b"A" * (AES.block_size - len("email="))
    block_2 = pkcs7_pad(b"admin", AES.block_size)
    plaintext = block_1 + block_2
    ciphertext2 = _encrypt_profile(plaintext, key)

    ciphertext = ciphertext1[:AES.block_size * 2]
    ciphertext += ciphertext2[AES.block_size:AES.block_size*2]
    return ciphertext


def main():
    key = Random.new().read(AES.block_size)
    ciphertext = _ecb_cut_and_paste(key)
    plaintext = _decrypt_profile(ciphertext, key)
    assert _decode_text(plaintext)["role"] == "admin"
    print("[*] Result: {}".format(plaintext.decode()))


if __name__ == "__main__":
    main()
