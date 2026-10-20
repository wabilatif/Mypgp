##
## EPITECH PROJECT, 2026
## genarate_key.py
## File description:
## Functions for the generate public 
## and private key of RSA
##

from src.utils import bring_together
from src.utils import exit_error
import math
import sys
import re
import random

def get_primes(maximum: int) -> list[int]:
    if maximum <= 2:
        return []
    sieve = bytearray([1]) * maximum
    sieve[0:2] = b'\x00\x00'
    for i in range(2, int(maximum**0.5) + 1):
        if sieve[i]:
            sieve[i*i:maximum:i] = b'\x00' * len(range(i*i, maximum, i))
    return [i for i, is_p in enumerate(sieve) if is_p]

try:
    from my_rust_module import get_primes as rust_get_primes
    get_primes = rust_get_primes
except ImportError:
    pass

HEX_BASE = 16
EXIT_SUCCESS_CODE = 0
HEX_PATTERN = re.compile(r"[0-9a-fA-F]+")

def get_two_random_primes(limit: int = 1_000_000):
    primes = get_primes(limit)
    if len(primes) < 2:
        raise ValueError("La limite est trop basse pour trouver deux nombres premiers.")
    return random.sample(primes, 2)

def generate_random_primes_cmd():
    p, q = get_two_random_primes()
    p_hex = "".join(bring_together(hex(p)[2:]))
    q_hex = "".join(bring_together(hex(q)[2:]))
    print(f"P: {p_hex}")
    print(f"Q: {q_hex}")
    sys.exit(EXIT_SUCCESS_CODE)


def extented_euclide(a : int, m : int) -> int :
    if m == 0:
        return a, 1, 0
    gcd, x1, y1 = extented_euclide(m, a % m)
    x = y1
    y = x1 - (a // m) * y1
    return gcd, x, y

def inverse_modulaire(a: int, m: int) -> int:
    gcd, x, _ = extented_euclide(a, m)
    if gcd != 1:
        raise Exception("Modular reverse doesn't exist")
    else:
        return x % m

def generate_e(Carmichael: int) -> int:
    number = 0
    index = 0
    the_number = 0
    while index < 5 :
        number = (2 ** (2 ** index)) + 1
        if number >= Carmichael :
            break
        index += 1
        if math.gcd(Carmichael, number) == 1 :
            the_number = number
    return the_number


def is_probable_prime(number: int) -> bool:
    return number >= 2 and pow(2, number - 1, number) == 1

def parse_prime(text: str) -> int:
    if not HEX_PATTERN.fullmatch(text) :
        exit_error("The numbers sent are not in hexadecimal")
    return int("".join(bring_together(text)), HEX_BASE)

def generate_key(p_text: str , q_text: str):
    p = parse_prime(p_text)
    q = parse_prime(q_text)
    if p == q :
        exit_error("The two prime numbers must be different")
    if not is_probable_prime(p) or not is_probable_prime(q) :
        exit_error("The numbers sent are not prime")
    n = p * q
    Carmichael = math.gcd((p - 1), (q - 1))
    Carmichael = ((p - 1) * (q - 1)) // Carmichael
    e = generate_e(Carmichael)
    if e == 0 :
        exit_error("No valid public exponent for these prime numbers")
    d = inverse_modulaire(e, Carmichael)
    n_hex = bring_together(str(hex(n))[2:])
    e_hex = bring_together(str(hex(e))[2:])
    d_hex = bring_together(str(hex(d))[2:])
    print("public key: " + "".join(e_hex) + "-" + "".join(n_hex))
    print("private key: " + "".join(d_hex) + "-" + "".join(n_hex))
    sys.exit(EXIT_SUCCESS_CODE)
