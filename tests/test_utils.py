##
## EPITECH PROJECT, 2026
## test_utils.py
## File description:
## Unit tests for utils.py
##

import unittest
from src.utils import (
    str_to_ltendian,
    bring_together,
    ltendian_to_str,
    bigendian_to_ltendian,
    split_blocks,
    cut_str,
    hex_to_bytes_le,
    bytes_to_hex_le,
    pad_zeros,
    swap_words,
)

class TestUtils(unittest.TestCase):

    def test_str_to_ltendian(self):
        self.assertEqual(str_to_ltendian("WF"), ['46', '57'])

    def test_str_to_ltendian_empty(self):
        with self.assertRaises(SystemExit):
            str_to_ltendian("")

    def test_bring_together(self):
        self.assertEqual(bring_together("1234"), ['34', '12'])

    def test_ltendian_to_str(self):
        self.assertEqual(ltendian_to_str(['46', '57']), "WF")

    def test_ltendian_to_str_empty(self):
        with self.assertRaises(SystemExit):
            ltendian_to_str([])

    def test_bigendian_to_ltendian(self):
        self.assertEqual(bigendian_to_ltendian(['57', '46']), ['57', '46'])

    def test_split_blocks(self):
        data = b"ABCDE"
        blocks = split_blocks(data, 2)
        self.assertEqual(blocks, [b"AB", b"CD", b"E"])

    def test_cut_str(self):
        res = cut_str("hi", 4)
        self.assertEqual(res, [[104, 105, 0, 0]])

    def test_hex_and_bytes_le_roundtrip(self):
        original_bytes = b"\x01\x02\x03\x04"
        le_hex = bytes_to_hex_le(original_bytes)
        back_bytes = hex_to_bytes_le(le_hex)
        self.assertEqual(original_bytes, back_bytes)

    def test_pad_zeros(self):
        data = b"AB"
        padded = pad_zeros(data, 4)
        self.assertEqual(padded, b"AB\x00\x00")

    def test_swap_words(self):
        data = b"\x01\x02\x03\x04"
        swapped = swap_words(data)
        self.assertEqual(swapped, b"\x04\x03\x02\x01")

if __name__ == '__main__':
    unittest.main()
