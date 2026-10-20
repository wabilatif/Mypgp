##
## EPITECH PROJECT, 2026
## test_rsa.py
## File description:
## Unit tests for rsa.py
##

import unittest
from unittest.mock import patch
from src.Asymmetric.RSA.rsa import parse_rsa_key, rsa_process, EXIT_ERROR_CODE

class TestRSA(unittest.TestCase):

    def test_parse_rsa_key_invalid_raises_error(self):
        invalid_keys = [
            "missing_dash",
            "too-many-dashes-123",
            "invalid_hex-format"
        ]
        for key in invalid_keys:
            with self.assertRaises(SystemExit) as cm:
                parse_rsa_key(key)
            self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

    @patch('src.Asymmetric.RSA.rsa.rsa_encrypt')
    def test_rsa_process_cipher(self, mock_rsa_encrypt):
        mock_rsa_encrypt.return_value = "mock_encrypted_hex"
        result = rsa_process("my_message", "11-ab", is_cipher=True)
        mock_rsa_encrypt.assert_called_once_with(message="my_message", key_hex="11-ab")
        self.assertEqual(result, "mock_encrypted_hex")

    @patch('src.Asymmetric.RSA.rsa.rsa_decrypt')
    def test_rsa_process_decipher(self, mock_rsa_decrypt):
        mock_rsa_decrypt.return_value = "mock_decrypted_msg"
        result = rsa_process("my_ciphertext", "11-ab", is_cipher=False)
        mock_rsa_decrypt.assert_called_once_with(message="my_ciphertext", key_hex="11-ab")
        self.assertEqual(result, "mock_decrypted_msg")


if __name__ == '__main__':
    unittest.main()
