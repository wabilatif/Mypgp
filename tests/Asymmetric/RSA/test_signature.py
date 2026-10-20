##
## EPITECH PROJECT, 2026
## test_signature.py
## File description:
## Unit tests for signature.py
##

import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch
from src.Asymmetric.RSA.rsa import EXIT_ERROR_CODE
from src.Asymmetric.RSA.signature import (
    sign, verify, add_signature, remove_signature, rsa_signed_process
)

MODULUS = ("c9f91a9ff3bd6d84005b9cc8448296330bd23480f8cf8b36fd4edd0a8cd925de1"
           "39a0076b962f4d57f50d6f9e64e7c41587784488f923dd60136c763fd602fb3")
PUBLIC_KEY = "010001-" + MODULUS
PRIVATE_KEY = ("81b08f4eb6dd8a4dd21728e5194dfc4e349829c9991c8b5e44b31e6ceee1e5"
               "6a11d66ef23389be92ef7a4178470693f509c90b86d4a1e1831056ca0757f3"
               "e209-" + MODULUS)
CIPHERED = "744ce22c385958348f0df26eceb62eef"


def run_expecting_exit(function, *args):
    """Run function, silence stderr and return the exit code."""
    with redirect_stderr(io.StringIO()):
        with unittest.TestCase().assertRaises(SystemExit) as cm:
            function(*args)
    return cm.exception.code


class TestSignature(unittest.TestCase):

    def test_sign_then_verify(self):
        signature = sign(CIPHERED, PRIVATE_KEY)
        self.assertTrue(verify(CIPHERED, signature, PUBLIC_KEY))

    def test_sign_is_deterministic(self):
        self.assertEqual(sign(CIPHERED, PRIVATE_KEY),
                         sign(CIPHERED, PRIVATE_KEY))

    def test_verify_fails_if_message_changed(self):
        signature = sign(CIPHERED, PRIVATE_KEY)
        self.assertFalse(verify(CIPHERED + "00", signature, PUBLIC_KEY))

    def test_verify_fails_if_signature_changed(self):
        signature = sign(CIPHERED, PRIVATE_KEY)
        first = "11" if signature[:2] != "11" else "22"
        self.assertFalse(verify(CIPHERED, first + signature[2:], PUBLIC_KEY))

    def test_verify_fails_with_other_key(self):
        signature = sign(CIPHERED, PRIVATE_KEY)
        self.assertFalse(verify(CIPHERED, signature, "0101-19bb"))

    def test_verify_fails_if_signature_not_hexadecimal(self):
        self.assertFalse(verify(CIPHERED, "zz", PUBLIC_KEY))

    def test_verify_fails_if_signature_bigger_than_modulus(self):
        self.assertFalse(verify(CIPHERED, "ff" * 80, PUBLIC_KEY))

    def test_sign_with_invalid_key_raises_error(self):
        code = run_expecting_exit(sign, CIPHERED, "missing_dash")
        self.assertEqual(code, EXIT_ERROR_CODE)

    def test_add_signature_adds_one_last_line(self):
        result = add_signature(CIPHERED, PRIVATE_KEY)
        lines = result.split(" ")
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0], CIPHERED)
        self.assertEqual(lines[1], sign(CIPHERED, PRIVATE_KEY))

    def test_remove_signature_returns_ciphered(self):
        signed = add_signature(CIPHERED, PRIVATE_KEY)
        self.assertEqual(remove_signature(signed, PUBLIC_KEY), CIPHERED)

    def test_remove_signature_with_multiline_ciphered(self):
        ciphered = "97f2af4c1b712008c1 " + CIPHERED
        signed = add_signature(ciphered, PRIVATE_KEY)
        self.assertEqual(remove_signature(signed, PUBLIC_KEY), ciphered)

    def test_remove_signature_missing_raises_error(self):
        code = run_expecting_exit(remove_signature, CIPHERED, PUBLIC_KEY)
        self.assertEqual(code, EXIT_ERROR_CODE)

    def test_remove_signature_invalid_raises_error(self):
        signed = add_signature(CIPHERED, PRIVATE_KEY)
        tampered = signed.replace("744c", "744d", 1)
        code = run_expecting_exit(remove_signature, tampered, PUBLIC_KEY)
        self.assertEqual(code, EXIT_ERROR_CODE)

    @patch('src.Asymmetric.RSA.signature.add_signature')
    @patch('src.Asymmetric.RSA.signature.rsa_process')
    def test_rsa_signed_process_cipher(self, mock_rsa_process, mock_add):
        mock_rsa_process.return_value = "mock_ciphered"
        mock_add.return_value = "mock_ciphered\nmock_signature"
        result = rsa_signed_process("my_message", "11-ab", "22-cd", True)
        mock_rsa_process.assert_called_once_with("my_message", "11-ab", True)
        mock_add.assert_called_once_with("mock_ciphered", "22-cd")
        self.assertEqual(result, "mock_ciphered\nmock_signature")

    @patch('src.Asymmetric.RSA.signature.remove_signature')
    @patch('src.Asymmetric.RSA.signature.rsa_process')
    def test_rsa_signed_process_decipher(self, mock_rsa_process, mock_remove):
        mock_remove.return_value = "mock_ciphered"
        mock_rsa_process.return_value = "mock_clear_message"
        result = rsa_signed_process("ciphered\nsignature", "11-ab", "22-cd",
                                    False)
        mock_remove.assert_called_once_with("ciphered\nsignature", "22-cd")
        mock_rsa_process.assert_called_once_with("mock_ciphered", "11-ab",
                                                 False)
        self.assertEqual(result, "mock_clear_message")

    @patch('src.Asymmetric.RSA.signature.rsa_process')
    def test_rsa_signed_process_decipher_stops_on_bad_signature(self, mock_rsa):
        code = run_expecting_exit(rsa_signed_process, CIPHERED + "\n00",
                                  PRIVATE_KEY, PUBLIC_KEY, False)
        self.assertEqual(code, EXIT_ERROR_CODE)
        mock_rsa.assert_not_called()

    def test_rsa_signed_process_full_round_trip(self):
        message = "The night is dark and full of terrors"
        signed = rsa_signed_process(message, PUBLIC_KEY, PRIVATE_KEY, True)
        self.assertTrue(signed.startswith("445b349e7318ad6af16b0bbb718be88b"))
        result = rsa_signed_process(signed, PRIVATE_KEY, PUBLIC_KEY, False)
        self.assertEqual(result, message)


if __name__ == '__main__':
    unittest.main()