##
## EPITECH PROJECT, 2026
## rsa_encrypt.py
## File description:
## rsa process
##

from src.utils import *

HEX_BASE = 16
EXIT_ERROR_CODE = 84

def rsa_encrypt(message: str, key_hex: str) :
    try:
        the_list = key_hex.split("-")
        if len(the_list) != 2 :
            exit_error("Invalid key.")
            sys.exit(EXIT_ERROR_CODE)
        e = int ("".join(bring_together(the_list[0])) , HEX_BASE)
        n = int ("".join(bring_together(the_list[1])) , HEX_BASE)
    except Exception:
        exit_error("Invalid key")
        sys.exit(EXIT_ERROR_CODE)
    message_in_ltendian = "".join(str_to_ltendian(message))
    message_number = int(message_in_ltendian, HEX_BASE)
    if n <= message_number:
        exit_error("ASymmetric key too big for this message.")
    result = pow(message_number, e, n)
    return "".join(bring_together(str(hex(result))[2:]))

def rsa_decrypt(message: str, key_hex: str) :
    try:
        the_list = key_hex.split("-")
        if len(the_list) != 2 :
            exit_error("Invalid key.")
            sys.exit(EXIT_ERROR_CODE)
        d = int ("".join(bring_together(the_list[0])) , HEX_BASE)
        n = int ("".join(bring_together(the_list[1])) , HEX_BASE)
    except Exception:
        exit_error("Invalid key")
        sys.exit(EXIT_ERROR_CODE)
    try :
        message_in_ltendian = "".join(bring_together(message))
        message_number = int(message_in_ltendian, HEX_BASE)
    except Exception:
        exit_error("Invalid Encrypted Message")
        sys.exit(EXIT_ERROR_CODE)
    result = pow(message_number, d, n)
    result = bring_together(str(hex(result))[2:])
    return ltendian_to_str(result[::-1])

def rsa_process(message: str, key_hex: str, is_cipher: bool) -> str:
    if is_cipher :
        return rsa_encrypt(message=message, key_hex=key_hex)
    else :
        return rsa_decrypt(message=message, key_hex=key_hex)

def parse_rsa_key(key_hex: str) -> tuple:
    the_list = key_hex.split("-")
    if len(the_list) != 2:
        exit_error("Invalid RSA key")
    try:
        exponent = int("".join(bring_together(the_list[0])), HEX_BASE)
        modulus = int("".join(bring_together(the_list[1])), HEX_BASE)
    except Exception:
        exit_error("Invalid RSA key.")
    return exponent, modulus

def rsa_encrypt_hex(number_hex: str, key_hex: str) -> str:
    exponent, modulus = parse_rsa_key(key_hex)
    try:
        number = int("".join(bring_together(number_hex)), HEX_BASE)
    except Exception:
        exit_error("Invalid symmetric key.")
    if number >= modulus:
        exit_error("Symmetric key too big for this RSA key.")
    result = pow(number, exponent, modulus)
    return "".join(bring_together(hex(result)[2:]))

def rsa_decrypt_hex(number_hex: str, key_hex: str) -> str:
    exponent, modulus = parse_rsa_key(key_hex)
    try:
        number = int("".join(bring_together(number_hex)), HEX_BASE)
    except Exception:
        exit_error("Invalid ciphered symmetric key.")
    if number >= modulus:
        exit_error("Ciphered key too long for this RSA key.")
    result = pow(number, exponent, modulus)
    return "".join(bring_together(hex(result)[2:]))
