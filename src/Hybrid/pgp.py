##
## EPITECH PROJECT, 2026
## pgp.py
## File description:
## pgp mod
##

from src.utils import exit_error
from src.Asymmetric.RSA.rsa import rsa_encrypt_hex, rsa_decrypt_hex

def split_pgp_key(key: str) -> tuple:
    """Split symmetric and rsa keys
    """
    parts = key.split(":")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        exit_error("Invalid key format. Expected: SYMMETRIC_KEY:RSA_KEY")
    return parts[0], parts[1]

def pgp_process(message: str, key: str, is_block_mode: bool, is_cipher: bool, symmetric_process) -> str:
    """
    """
    first_key, rsa_key = split_pgp_key(key)
    if is_cipher:
        ciphered_key = rsa_encrypt_hex(first_key, rsa_key)
        ciphered_message = symmetric_process(message, first_key, is_block_mode, True)
        return ciphered_key + "\n" + ciphered_message
    sym_key = rsa_decrypt_hex(first_key, rsa_key)
    return symmetric_process(message, sym_key, is_block_mode, False)
