##
## EPITECH PROJECT, 2026
## main.py
## File description:
## main file
##

from src.cli import parse_cli
from src.Symmetric.XOR.xor import xor_process
from src.utils import exit_error
from src.Asymmetric.RSA.genarate_key import generate_key, generate_random_primes_cmd
from src.Asymmetric.RSA.rsa import rsa_process
from src.Symmetric.AES.aes import aes_process
from src.Hybrid.pgp import pgp_process
from src.Asymmetric.X25519.X25519 import x25519_process, generate_x25519_keys
from src.Asymmetric.RSA.signature import rsa_signed_process

def main():
    args = parse_cli()
    if args.mode in ["-c", "-d"]:
        message = args.message if args.message is not None else ""
        result = None
        is_cipher = (args.mode == "-c")
        if args.crypto_system == "xor":
            result = xor_process(message, args.key, args.is_block_mode, is_cipher)
        elif args.crypto_system == "rsa":
            if args.sign_key == None:
                result = rsa_process(message, args.key, is_cipher)
            else:
                result = rsa_signed_process(message, args.key, args.sign_key, is_cipher)
        elif args.crypto_system == "X25519":
            result = x25519_process(message, args.key, is_cipher)
        elif args.crypto_system == "aes":
            result = aes_process(message, args.key, args.is_block_mode, is_cipher)
        elif args.crypto_system == "pgp-xor":
            result = pgp_process(message, args.key, args.is_block_mode, is_cipher, xor_process)
        elif args.crypto_system == "pgp-aes":
            result = pgp_process(message, args.key, args.is_block_mode, is_cipher, aes_process)
        else:
            exit_error("Error: aucun cryptosystem")
        if result != None :
            print(result)
    elif args.mode == "g":
        if args.crypto_system == "rsa":
            generate_key(args.rsa_p, args.rsa_q)
        else :
            generate_x25519_keys()
    elif args.mode == "gp":
        generate_random_primes_cmd()
    else:
        exit_error("Error: Invalid mode.")

if __name__ == "__main__":
    main()