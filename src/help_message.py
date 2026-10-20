##
## EPITECH PROJECT, 2026
## help_message.py
## File description:
## print the help flag
##

def help_message() -> None:
    """Display the usage of my_pgp

    Returns:
        None
    """
    print("USAGE")
    print("      ./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [key]\n")
    print("DESCRIPTION\n")
    print("Cipher or decipher MESSAGE using a given CRYPTO_SYSTEM. The MESSAGE is read from the standard input.\n")
    print("   CRYPTO SYSTEM")
    print("      \"xor\"            computation using XOR algorithm")
    print("      \"aes\"            computation using AES algorithm")
    print("      \"rsa\"            computation using RSA algorithm")
    print("      \"pgp-xor\"        computation using both RSA and XOR algorithm")
    print("      \"pgp-aes\"        computation using both RSA and AES algorithm")
    print("\n   MODE")
    print("      -c               MESSAGE is clear and we want to cipher it")
    print("      -d               MESSAGE is ciphered and we want to decipher it")
    print("      -g P Q           RSA only: don't read a MESSAGE, but instead generate a public and private key")
    print("      pair from the prime number P and Q")
    print("\n   OPTIONS")
    print("      -b               for XOR, AES and PGP, only works on one block. The MESSAGE and the symmetric")
    print("      key must be the same size")
    print("\n   key                 Key used to cipher/decipher MESSAGE (incompatible with -g MODE)")
