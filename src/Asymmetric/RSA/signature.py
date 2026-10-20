##
## EPITECH PROJECT, 2026
## signature.py
## File description:
## RSA signature (bonus): sign a ciphered message and check it
##

import hashlib

from src.Asymmetric.RSA.rsa import parse_rsa_key, rsa_process
from src.utils import bring_together, exit_error

HEX_BASE = 16


def hash_message(message: str, modulus: int) -> int:
    """Return the SHA-256 digest of a message, as an integer smaller than n.

    The digest is reduced modulo n so that it always fits in the RSA key.
    With real keys (512 bits and more) the reduction changes nothing, because
    a SHA-256 digest is already smaller than n. With tiny keys it weakens the
    signature, so those keys are only good for testing.
    """
    digest = hashlib.sha256(message.encode("utf-8")).digest()
    return int.from_bytes(digest, "little") % modulus


def sign(message: str, private_key_hex: str) -> str:
    """Sign a message with an RSA private key (format "d-n", little-endian hex).

    S = hash(message)^d mod n

    Returns the signature as a little-endian hex string.
    """
    exponent, modulus = parse_rsa_key(private_key_hex)
    signature = pow(hash_message(message, modulus), exponent, modulus)
    return "".join(bring_together(hex(signature)[2:]))


def verify(message: str, signature_hex: str, public_key_hex: str) -> bool:
    """Check a signature with the RSA public key of the sender ("e-n").

    The signature is valid if S^e mod n equals the hash of the message.
    """
    exponent, modulus = parse_rsa_key(public_key_hex)
    try:
        signature = int("".join(bring_together(signature_hex)), HEX_BASE)
    except ValueError:
        return False
    if signature >= modulus:
        return False
    return pow(signature, exponent, modulus) == hash_message(message, modulus)


def add_signature(ciphered: str, private_key_hex: str) -> str:
    """Append the signature of the ciphered output as a last line (-c with -s).

    Output:
        <ciphered message (one or several lines)> <signature>

    Example:
        >>> add_signature("744ce22c385958348f0df26eceb62eef", private_key)
        '744ce22c385958348f0df26eceb62eef\\n8cc70d54...'
    """
    return ciphered + " " + sign(ciphered, private_key_hex)


def remove_signature(data: str, public_key_hex: str) -> str:
    """Check the last line of data and return the ciphered message (-d with -s).

    The signature is the last line, everything before it is the ciphered
    message, so the ciphered message may span several lines (PGP, X25519).
    Exit with the error code if the signature is missing or invalid.
    """
    ciphered, separator, signature = data.rpartition(" ")
    if not separator:
        exit_error("Missing signature")
    if not verify(ciphered, signature.strip(), public_key_hex):
        exit_error("Invalid signature")
    return ciphered


def rsa_signed_process(message: str, key_hex: str, sign_key_hex: str,
                       is_cipher: bool) -> str:
    """RSA ciphering or deciphering with the -s option.

    Args:
        message (str): The clear message (-c) or the ciphered message followed
            by its signature on the last line (-d).
        key_hex (str): The recipient's public key (-c) or private key (-d).
        sign_key_hex (str): The sender's private key (-c) or public key (-d).
        is_cipher (bool): True to cipher and sign, False to check and decipher.
    """
    if is_cipher:
        ciphered = rsa_process(message, key_hex, True)
        return add_signature(ciphered, sign_key_hex)
    ciphered = remove_signature(message, sign_key_hex)
    return rsa_process(ciphered, key_hex, False)