##
## EPITECH PROJECT, 2026
## xor.py
## File description:
## xor process
##

import sys
from src.utils import *

EXIT_ERROR_CODE = 84

def xor_bytes(data: bytes, key: bytes) -> bytes:
    """Apply an XOR operation between a byte sequence and a repeating key.

    Args:
        data (bytes): The byte sequence to process.
        key (bytes): The key used for the XOR operation.

    Returns:
        bytes: The resulting bytes after applying the XOR operation.
    """
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def xor_process(message: str, key_hex: str, is_block_mode: bool, is_cipher: bool) -> str:
    """Process a message with XOR encryption or decryption.

    Args:
        message (str): The input message (plaintext or hex-encoded ciphertext).
        key_hex (str): The encryption key in hexadecimal format.
        is_block_mode (bool): If True, restricts operation to a single block.
        is_cipher (bool): True to cipher the message, False to decipher it.

    Returns:
        str: The processed result as a hex string or UTF-8 text string.
    """
    try:
        key_bytes = hex_to_bytes_le(key_hex)
    except Exception:
        sys.exit(EXIT_ERROR_CODE)
    block_size = len(key_bytes)
    if block_size == 0:
        sys.exit(EXIT_ERROR_CODE)
    if is_cipher:
        data = message.encode('utf-8')
    else:
        try:
            data = hex_to_bytes_le(message)
        except Exception:
            sys.exit(EXIT_ERROR_CODE)
    if is_block_mode:
        if len(data) != block_size:
            sys.exit(EXIT_ERROR_CODE)
        result_bytes = xor_bytes(data, key_bytes)
    else:
        blocks = split_blocks(data, block_size)
        output = bytearray()
        for block in blocks:
            if len(block) < block_size:
                block = pad_zeros(block, block_size)
            output.extend(xor_bytes(block, key_bytes))
        result_bytes = bytes(output)
    if is_cipher:
        return bytes_to_hex_le(result_bytes)
    else:
        return result_bytes.decode('utf-8', errors='replace')
