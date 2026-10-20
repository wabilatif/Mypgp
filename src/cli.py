##
## EPITECH PROJECT, 2026
## cli.py
## File description:
## Parse command line arguments and read stdin
##

import sys
from dataclasses import dataclass
from typing import Optional
from src.help_message import help_message

VALID_SYSTEMS = {"xor", "aes", "rsa", "pgp-xor", "pgp-aes", "X25519"}
GENERATOR_SYSTEMS = {"rsa", "X25519"}
EXIT_ERROR_CODE = 84
EXIT_SUCCESS_CODE = 0

@dataclass
class CLIArgs:
    crypto_system: str
    mode: str
    is_block_mode: bool
    key: Optional[str]
    sign_key : Optional[str]
    rsa_p: Optional[str] = None
    rsa_q: Optional[str] = None
    message: Optional[str] = None

def error_exit(msg: str) -> None:
    sys.stderr.write(f"Error: {msg}\n")
    sys.exit(EXIT_ERROR_CODE)

def parse_cli() -> CLIArgs:
    argv = sys.argv[1:]
    if len(argv) == 1 and argv[0] == "-h":
        help_message()
        sys.exit(EXIT_SUCCESS_CODE)
    if len(argv) < 2:
        error_exit("Invalid number of arguments.")
    crypto_system = argv[0]
    if crypto_system not in VALID_SYSTEMS:
        error_exit(f"Unknown crypto system '{crypto_system}'.")
    mode_raw = argv[1]
    is_block_mode, signe_mode = False, False
    mode = None
    rsa_p, rsa_q = None, None
    idx = 1
    if mode_raw == "-gp":
        mode = 'gp'
        if crypto_system != "rsa":
            error_exit("-gp mode is only available for RSA.")
        if len(argv) != 2:
            error_exit("-gp mode takes no additional arguments.")
    elif mode_raw.startswith("-g"):
        mode = 'g'
        if crypto_system not in GENERATOR_SYSTEMS :
            error_exit("-g mode is only available for RSA and X25519.")
        if crypto_system == 'rsa' :
            if len(argv) != 4 :
                error_exit("-g mode should have 4 arguments.")
            rsa_p = argv[2]
            rsa_q = argv[3]
    elif mode_raw.startswith("-"):
        flags = mode_raw[1:]
        if 'b' in flags:
            is_block_mode = True
            flags = flags.replace('b', '')
        if flags in ("c", "d"):
            mode = "-" + flags
        else:
            error_exit(f"Invalid mode flag '-{flags}'.")
    else:
        error_exit("Mode parameter missing.")
    key = None
    sign_key = None
    index = 0
    while index < len(argv):
        if argv[index] == "-s":
            if crypto_system != "rsa":
                error_exit("-s option is only available for RSA.")
            if index + 1 >= len(argv) or argv[index + 1].startswith("-"):
                error_exit("Missing signature key after -s.")
            sign_key = argv[index + 1]
            del argv[index:index + 2]
        else:
            index += 1
    if mode not in ('g', 'gp'):
        idx += 1
        if idx < len(argv) and argv[idx] == "-b":
            is_block_mode = True
            idx += 1
        if idx >= len(argv):
            error_exit("Missing encryption/decryption key.")
        key = argv[idx]
    message = None
    if mode not in ('g', 'gp'):
        input_data = sys.stdin.readline()
        if input_data.endswith('\n'):
            input_data = input_data[:-1]
        if input_data.endswith('\r'):
            input_data = input_data[:-1]
        message = input_data
    return CLIArgs(crypto_system=crypto_system, mode=mode, is_block_mode=is_block_mode, key=key, rsa_p=rsa_p, rsa_q=rsa_q, message=message, sign_key=sign_key)
