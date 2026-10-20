##
## EPITECH PROJECT, 2026
## test_xor.py
## File description:
## Unit tests for xor.py
##

import unittest
from src.Symmetric.XOR.xor import xor_bytes, xor_process, EXIT_ERROR_CODE

class TestXor(unittest.TestCase):

    def test_xor_bytes_basic(self):
        data = b"ABC"
        key = b"\x01"
        expected = bytes([65 ^ 1, 66 ^ 1, 67 ^ 1])
        self.assertEqual(xor_bytes(data, key), expected)

    def test_xor_bytes_repeating_key(self):
        data = b"ABCD"
        key = b"\x01\x02"
        expected = bytes([65 ^ 1, 66 ^ 2, 67 ^ 1, 68 ^ 2])
        self.assertEqual(xor_bytes(data, key), expected)

    def test_xor_process_invalid_key_raises_error(self):
        with self.assertRaises(SystemExit) as cm:
            xor_process("Hello", "invalid_hex_string", is_block_mode=False, is_cipher=True)
        self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

    def test_xor_process_block_mode_size_mismatch(self):
        with self.assertRaises(SystemExit) as cm:
            xor_process("ABC", "01", is_block_mode=True, is_cipher=True)
        self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

    def test_xor_process_invalid_decipher_hex_raises_error(self):
        with self.assertRaises(SystemExit) as cm:
            xor_process("not_hex!", "01", is_block_mode=False, is_cipher=False)
        self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)


if __name__ == '__main__':
    unittest.main()
