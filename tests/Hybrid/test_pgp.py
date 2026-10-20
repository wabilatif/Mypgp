##
## EPITECH PROJECT, 2026
## test_pgp.py
## File description:
## Unit tests for pgp.py
##

import unittest
from unittest.mock import patch
from src.Hybrid.pgp import split_pgp_key, pgp_process

class TestPGP(unittest.TestCase):

    def test_split_pgp_key_valid(self):
        key = "sym_key_123:rsa_key_456"
        sym, rsa = split_pgp_key(key)
        self.assertEqual(sym, "sym_key_123")
        self.assertEqual(rsa, "rsa_key_456")

    def test_split_pgp_key_invalid_raises_error(self):
        invalid_keys = [
            "missing_colon",
            ":rsa_key_only",
            "sym_key_only:",
            "too:many:colons:here"
        ]
        for key in invalid_keys:
            with self.assertRaises(SystemExit):
                split_pgp_key(key)
    @patch('src.Hybrid.pgp.rsa_encrypt_hex')

    def test_pgp_process_cipher(self, mock_rsa_encrypt):
        mock_rsa_encrypt.return_value = "encrypted_sym_key_hex"
        def dummy_symmetric_process(message, key, is_block_mode, is_cipher):
            return "ciphered_" + message
        key = "my_sym_key:my_rsa_key"
        result = pgp_process("my_message", key, is_block_mode=False, is_cipher=True, symmetric_process=dummy_symmetric_process)
        mock_rsa_encrypt.assert_called_once_with("my_sym_key", "my_rsa_key")
        self.assertEqual(result, "encrypted_sym_key_hex\nciphered_my_message")
    @patch('src.Hybrid.pgp.rsa_decrypt_hex')

    def test_pgp_process_decipher(self, mock_rsa_decrypt):
        mock_rsa_decrypt.return_value = "decrypted_sym_key"
        def dummy_symmetric_process(message, key, is_block_mode, is_cipher):
            return "deciphered_" + message
        key = "encrypted_sym_key:my_rsa_private_key"
        result = pgp_process("ciphertext_data", key, is_block_mode=False, is_cipher=False, symmetric_process=dummy_symmetric_process)
        mock_rsa_decrypt.assert_called_once_with("encrypted_sym_key", "my_rsa_private_key")
        self.assertEqual(result, "deciphered_ciphertext_data")

if __name__ == '__main__':
    unittest.main()
