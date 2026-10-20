##
## EPITECH PROJECT, 2026
## test_aes.py
## File description:
## Unit tests for aes.py
##

import unittest
from src.Symmetric.AES.aes import (aes_encrypt, aes_decrypt, aes_process, key_expansion, encrypt_block, decrypt_block)

KEY_128_HEX = "000102030405060708090a0b0c0d0e0f"
KEY_192_HEX = "000102030405060708090a0b0c0d0e0f1011121314151617"
KEY_256_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

FIPS_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS_VECTORS = {
    16: "69c4e0d86a7b0430d8cdb78070b4c55a",
    24: "dda97ca4864cdfe06eaf70a0ec0d7191",
    32: "8ea2b7ca516745bfeafc49904b496089",
}

class TestAES(unittest.TestCase):

    def test_aes_round_trip_block_mode(self):
        key_hex = "000102030405060708090a0b0c0d0e0f"
        message = "Hello AES World!"
        ciphertext = aes_encrypt(message, key_hex, is_block_mode=True)
        decrypted = aes_decrypt(ciphertext, key_hex, is_block_mode=True)
        self.assertEqual(message, decrypted)

    def test_aes_process_wrapper(self):
        key_hex = "000102030405060708090a0b0c0d0e0f"
        message = "TestMessage12345"
        ciphered = aes_process(message, key_hex, is_block_mode=True, is_cipher=True)
        deciphered = aes_process(ciphered, key_hex, is_block_mode=True, is_cipher=False)
        self.assertEqual(message, deciphered)

    def test_aes_invalid_key_raises_error(self):
        with self.assertRaises(SystemExit):
            aes_encrypt("TestMessage12345", "invalid_key_hex", is_block_mode=True)

    def test_aes_invalid_message_length_block_mode(self):
        key_hex = "000102030405060708090a0b0c0d0e0f"
        with self.assertRaises(SystemExit):
            aes_encrypt("TooShort", key_hex, is_block_mode=True)

    def test_aes_invalid_decrypt_hex_raises_error(self):
        key_hex = "000102030405060708090a0b0c0d0e0f"
        with self.assertRaises(SystemExit):
            aes_decrypt("not_a_hex_string_at_all!!", key_hex, is_block_mode=True)

    def test_aes_192_round_trip_block_mode(self):
        message = "Hello AES World!"
        ciphertext = aes_encrypt(message, KEY_192_HEX, is_block_mode=True)
        decrypted = aes_decrypt(ciphertext, KEY_192_HEX, is_block_mode=True)
        self.assertEqual(message, decrypted)

    def test_aes_256_round_trip_block_mode(self):
        message = "Hello AES World!"
        ciphertext = aes_encrypt(message, KEY_256_HEX, is_block_mode=True)
        decrypted = aes_decrypt(ciphertext, KEY_256_HEX, is_block_mode=True)
        self.assertEqual(message, decrypted)

    def test_aes_192_round_trip_stream_mode(self):
        message = "A message longer than one block, to test stream mode."
        ciphertext = aes_encrypt(message, KEY_192_HEX, is_block_mode=False)
        decrypted = aes_decrypt(ciphertext, KEY_192_HEX, is_block_mode=False)
        self.assertEqual(message, decrypted)

    def test_aes_256_round_trip_stream_mode(self):
        message = "A message longer than one block, to test stream mode."
        ciphertext = aes_encrypt(message, KEY_256_HEX, is_block_mode=False)
        decrypted = aes_decrypt(ciphertext, KEY_256_HEX, is_block_mode=False)
        self.assertEqual(message, decrypted)

    def test_aes_process_wrapper_192_and_256(self):
        message = "TestMessage12345"
        for key_hex in (KEY_192_HEX, KEY_256_HEX):
            ciphered = aes_process(message, key_hex, is_block_mode=True, is_cipher=True)
            deciphered = aes_process(ciphered, key_hex, is_block_mode=True, is_cipher=False)
            self.assertEqual(message, deciphered)

    def test_aes_key_size_changes_ciphertext(self):
        message = "Hello AES World!"
        results = {
            aes_encrypt(message, key_hex, is_block_mode=True)
            for key_hex in (KEY_128_HEX, KEY_192_HEX, KEY_256_HEX)
        }
        self.assertEqual(len(results), 3)

    def test_aes_wrong_key_size_raises_error(self):
        for size in (15, 17, 20, 31, 33):
            with self.subTest(key_size=size):
                with self.assertRaises(SystemExit):
                    aes_encrypt("TestMessage12345", "00" * size, is_block_mode=True)
                with self.assertRaises(SystemExit):
                    aes_decrypt("00" * 16, "00" * size, is_block_mode=True)

    def test_aes_decrypt_with_other_key_size_fails_to_recover(self):
        message = "Hello AES World!"
        ciphertext = aes_encrypt(message, KEY_192_HEX, is_block_mode=True)
        try:
            decrypted = aes_decrypt(ciphertext, KEY_256_HEX, is_block_mode=True)
        except SystemExit:
            return
        self.assertNotEqual(message, decrypted)

    def test_key_expansion_round_keys_count(self):
        for size, expected in ((16, 11), (24, 13), (32, 15)):
            with self.subTest(key_size=size):
                self.assertEqual(len(key_expansion(bytes(range(size)))), expected)

    def test_fips_197_vectors(self):
        for size, expected_hex in FIPS_VECTORS.items():
            with self.subTest(key_size=size):
                round_keys = key_expansion(bytes(range(size)))
                cipher = encrypt_block(FIPS_PLAINTEXT, round_keys)
                self.assertEqual(cipher.hex(), expected_hex)
                self.assertEqual(decrypt_block(cipher, round_keys), FIPS_PLAINTEXT)

if __name__ == '__main__':
    unittest.main()
