##
## EPITECH PROJECT, 2026
## x25519.py
## File description:
## X25519 key exchange (RFC 7748) and hybrid ciphering with XOR
##

import hashlib
import secrets
import sys

from src.Symmetric.XOR.xor import xor_process

EXIT_ERROR_CODE = 84
KEY_SIZE = 32
PRIME = 2 ** 255 - 19
A24 = 121665                    # (486662 - 2) / 4, constant of Curve25519
BASE_POINT = 9


def fail(message: str) -> None:
    """Print an error on stderr and exit with the error code."""
    print(message, file=sys.stderr)
    sys.exit(EXIT_ERROR_CODE)


# --- Key encoding: 32 bytes, little endian (same convention as the project) ---

def decode_key(key_hex: str) -> int:
    """Convert a 32-byte little-endian hex string into an integer.

    Example:
        >>> decode_key("09" + "00" * 31)
        9
    """
    try:
        key_bytes = bytes.fromhex(key_hex)
    except ValueError:
        fail("The key is not in hexadecimal")
    if len(key_bytes) != KEY_SIZE:
        fail("An X25519 key must be 32 bytes")
    return int.from_bytes(key_bytes, "little")


def encode_key(number: int) -> str:
    """Convert an integer into a 32-byte little-endian hex string."""
    return number.to_bytes(KEY_SIZE, "little").hex()


# --- X25519 (Montgomery ladder, RFC 7748 section 5) ---

def clamp(scalar: int) -> int:
    """Force the bits X25519 requires on a private key."""
    scalar &= ~7                # the 3 lowest bits to 0
    scalar &= ~(1 << 255)       # bit 255 to 0
    scalar |= 1 << 254          # bit 254 to 1
    return scalar


def ladder_step(x1: int, x2: int, z2: int, x3: int, z3: int) -> tuple:
    """One step of the ladder: double (x2, z2) and add (x2, z2) + (x3, z3)."""
    a, b = (x2 + z2) % PRIME, (x2 - z2) % PRIME
    c, d = (x3 + z3) % PRIME, (x3 - z3) % PRIME
    aa, bb = a * a % PRIME, b * b % PRIME
    e = (aa - bb) % PRIME
    da, cb = d * a % PRIME, c * b % PRIME
    return (aa * bb % PRIME,
            e * (aa + A24 * e) % PRIME,
            (da + cb) ** 2 % PRIME,
            x1 * (da - cb) ** 2 % PRIME)


def x25519(scalar_hex: str, point_hex: str) -> str:
    """Multiply a point by a scalar on Curve25519.

    Examples:
        public key:    x25519(private_key, encode_key(BASE_POINT))
        shared secret: x25519(my_private_key, other_public_key)
    """
    scalar = clamp(decode_key(scalar_hex))
    x1 = decode_key(point_hex) & (2 ** 255 - 1)     # bit 255 is ignored
    x2, z2, x3, z3 = 1, 0, x1, 1
    swap = 0
    for index in reversed(range(255)):
        bit = (scalar >> index) & 1
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        x2, z2, x3, z3 = ladder_step(x1, x2, z2, x3, z3)
    if swap:
        x2, x3, z2, z3 = x3, x2, z3, z2
    return encode_key(x2 * pow(z2, PRIME - 2, PRIME) % PRIME)


def public_key(private_hex: str) -> str:
    """Return the public key matching a private key."""
    return x25519(private_hex, encode_key(BASE_POINT))


# --- Hybrid ciphering: shared secret -> symmetric key -> XOR ---

def shared_key(private_hex: str, public_hex: str) -> str:
    """Derive the symmetric key (hex) shared by two X25519 key pairs."""
    secret = x25519(private_hex, public_hex)
    if int(secret, 16) == 0:
        fail("Invalid public key")
    return hashlib.sha256(bytes.fromhex(secret)).hexdigest()


def x25519_cipher(message: str, public_hex: str) -> str:
    """Cipher a message for the owner of public_hex.

    Output on 2 lines: the ephemeral public key, then the ciphered message.
    """
    ephemeral = secrets.token_hex(KEY_SIZE)
    key = shared_key(ephemeral, public_hex)
    ciphered = xor_process(message, key, False, True)
    return public_key(ephemeral) + " " + ciphered


def x25519_decipher(data: str, private_hex: str) -> str:
    """Decipher the output of x25519_cipher with the private key."""
    lines = data.strip().split(" ")
    if len(lines) != 2:
        fail("Invalid ciphered message")
    key = shared_key(private_hex, lines[0])
    return xor_process(lines[1], key, False, False).rstrip("\0")


# --- Entry points used by main ---

def generate_x25519_keys() -> None:
    """Generate a random key pair and print it (like the RSA -g mode).

    Example:
        $> ./my_pgp x25519 -g
        public key: 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
        private key: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
    """
    private = secrets.token_hex(KEY_SIZE)
    print("public key: " + public_key(private))
    print("private key: " + private)


def x25519_process(message: str, key_hex: str, is_cipher: bool) -> str:
    """Cipher with a public key (-c) or decipher with a private key (-d).

    Args:
        message (str): The clear message (-c) or the 2 lines produced by -c (-d).
        key_hex (str): The public key (-c) or the private key (-d), in hex.
        is_cipher (bool): True to cipher, False to decipher.
    """
    if key_hex is None:
        fail("Error: a key is required")
    if is_cipher:
        return x25519_cipher(message, key_hex)
    return x25519_decipher(message, key_hex)