##
## EPITECH PROJECT, 2026
## test_generate_key.py
## File description:
## Unit tests for genarate_key.py
##

import unittest
from unittest.mock import patch
from io import StringIO
from src.Asymmetric.RSA.genarate_key import (
    extented_euclide,
    inverse_modulaire,
    is_probable_prime,
    parse_prime,
    generate_key,
    EXIT_SUCCESS_CODE
)

class TestGenerateKey(unittest.TestCase):

    def test_extented_euclide(self):
        gcd, x, y = extented_euclide(35, 15)
        self.assertEqual(gcd, 5)
        self.assertEqual(35 * x + 15 * y, gcd)

    def test_inverse_modulaire_success(self):
        inv = inverse_modulaire(3, 5)
        self.assertEqual(inv, 2)

    def test_inverse_modulaire_failure(self):
        with self.assertRaises(Exception):
            inverse_modulaire(2, 4)

    def test_is_probable_prime(self):
        self.assertTrue(is_probable_prime(3))
        self.assertTrue(is_probable_prime(5))
        self.assertTrue(is_probable_prime(7))
        self.assertFalse(is_probable_prime(4))
        self.assertFalse(is_probable_prime(1))

    def test_parse_prime_invalid_hex(self):
        with self.assertRaises(SystemExit):
            parse_prime("invalid_hex_!@#")

    @patch('sys.stdout', new_callable=StringIO)
    def test_generate_key_success(self, mock_stdout):
        with self.assertRaises(SystemExit) as cm:
            generate_key("3", "5")
        
        # Vérifie que le programme s'arrête avec le code de succès (0)
        self.assertEqual(cm.exception.code, EXIT_SUCCESS_CODE)
        
        output = mock_stdout.getvalue()
        self.assertIn("public key:", output)
        self.assertIn("private key:", output)

    def test_generate_key_same_primes_raises_error(self):
        with self.assertRaises(SystemExit):
            generate_key("3", "3")


if __name__ == '__main__':
    unittest.main()