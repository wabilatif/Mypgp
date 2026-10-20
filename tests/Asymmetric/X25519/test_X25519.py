##
## EPITECH PROJECT, 2026
## test_x25519.py
## File description:
## Unit tests for X25519.py
##

import unittest
from unittest.mock import patch
from io import StringIO

from src.Asymmetric.X25519.X25519 import (
    EXIT_ERROR_CODE,
    KEY_SIZE,
    PRIME,
    BASE_POINT,
    fail,
    decode_key,
    encode_key,
    clamp,
    ladder_step,
    x25519,
    public_key,
    shared_key,
    x25519_cipher,
    x25519_decipher,
    generate_x25519_keys,
    x25519_process,
)


class TestX25519(unittest.TestCase):

    # Known test vectors from RFC 7748

    ALICE_PRIVATE = (
        "77076d0a7318a57d3c16c17251b26645"
        "df4c2f87ebc0992ab177fba51db92c2a"
    )

    ALICE_PUBLIC = (
        "8520f0098930a754748b7ddcb43ef75a"
        "0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )

    BOB_PRIVATE = (
        "5dab087e624a8a4b79e17f8b83800ee6"
        "6f3bb1292618b6fd1c2f8b27ff88e0eb"
    )

    BOB_PUBLIC = (
        "de9edb7d7b7dc1b4d35b61c2ece43537"
        "3f8343c85b78674dadfc7e146f882b4f"
    )

    SHARED_SECRET = (
        "4a5d9d5ba4ce2de1728e3bf480350f25"
        "e07e21c947d19e3376f09b3c1e161742"
    )

    # Key encoding tests

    def test_decode_key_valid(self):
        result = decode_key("09" + "00" * 31)
        self.assertEqual(result, 9)

    def test_encode_key_valid(self):
        result = encode_key(9)
        self.assertEqual(result, "09" + "00" * 31)

    def test_encode_decode_key_roundtrip(self):
        value = 123456789
        result = decode_key(encode_key(value))
        self.assertEqual(result, value)

    def test_decode_key_invalid_hex(self):
        with self.assertRaises(SystemExit) as cm:
            decode_key("zz" * KEY_SIZE)

        self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

    def test_decode_key_invalid_length(self):
        invalid_keys = [
            "",
            "00",
            "00" * 31,
            "00" * 33,
        ]

        for key in invalid_keys:
            with self.subTest(key_length=len(key)):
                with self.assertRaises(SystemExit) as cm:
                    decode_key(key)

                self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

    # Clamp tests

    def test_clamp_clears_three_lowest_bits(self):
        result = clamp(0b111)

        self.assertEqual(result & 7, 0)

    def test_clamp_clears_highest_bit(self):
        result = clamp((1 << 255) - 1)

        self.assertEqual((result >> 255) & 1, 0)

    def test_clamp_sets_bit_254(self):
        result = clamp(0)

        self.assertEqual((result >> 254) & 1, 1)

    # X25519 algorithm tests

    def test_public_key_alice_rfc7748(self):
        result = public_key(self.ALICE_PRIVATE)

        self.assertEqual(result, self.ALICE_PUBLIC)

    def test_public_key_bob_rfc7748(self):
        result = public_key(self.BOB_PRIVATE)

        self.assertEqual(result, self.BOB_PUBLIC)

    def test_x25519_shared_secret_rfc7748(self):
        result = x25519(self.ALICE_PRIVATE, self.BOB_PUBLIC)

        self.assertEqual(result, self.SHARED_SECRET)

    def test_shared_secret_is_symmetric(self):
        secret_alice = x25519(
            self.ALICE_PRIVATE,
            self.BOB_PUBLIC
        )

        secret_bob = x25519(
            self.BOB_PRIVATE,
            self.ALICE_PUBLIC
        )

        self.assertEqual(secret_alice, secret_bob)

    def test_public_key_length(self):
        result = public_key(self.ALICE_PRIVATE)

        self.assertEqual(len(result), KEY_SIZE * 2)

    def test_public_key_is_hexadecimal(self):
        result = public_key(self.ALICE_PRIVATE)

        self.assertEqual(len(bytes.fromhex(result)), KEY_SIZE)

    # Shared key tests

    def test_shared_key_is_symmetric(self):
        key_alice = shared_key(
            self.ALICE_PRIVATE,
            self.BOB_PUBLIC
        )

        key_bob = shared_key(
            self.BOB_PRIVATE,
            self.ALICE_PUBLIC
        )

        self.assertEqual(key_alice, key_bob)

    def test_shared_key_is_sha256(self):
        result = shared_key(
            self.ALICE_PRIVATE,
            self.BOB_PUBLIC
        )

        self.assertEqual(len(result), 64)
        self.assertEqual(len(bytes.fromhex(result)), 32)

    def test_shared_key_invalid_public_key(self):
        invalid_public_key = "00" * KEY_SIZE

        with self.assertRaises(SystemExit) as cm:
            shared_key(self.ALICE_PRIVATE, invalid_public_key)

        self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

    # Cipher and decipher tests

    def test_cipher_decipher_roundtrip(self):
        message = "Hello X25519!"

        # Encrypt with Bob's public key.
        with patch("sys.stdout", new_callable=StringIO):
            ciphered = x25519_cipher(message, self.BOB_PUBLIC)

        # Decrypt with Bob's private key.
        with patch("sys.stdout", new_callable=StringIO):
            deciphered = x25519_decipher(
                ciphered,
                self.BOB_PRIVATE
            )

        self.assertEqual(deciphered, message)

    def test_cipher_single_character(self):
        message = "A"

        with patch("sys.stdout", new_callable=StringIO):
            ciphered = x25519_cipher(message, self.BOB_PUBLIC)

        with patch("sys.stdout", new_callable=StringIO):
            deciphered = x25519_decipher(
                ciphered,
                self.BOB_PRIVATE
            )

        self.assertEqual(deciphered, message)

    def test_cipher_generates_ephemeral_key(self):
        ephemeral_private = self.ALICE_PRIVATE

        with patch(
            "src.Asymmetric.X25519.X25519.secrets.token_hex",
            return_value=ephemeral_private
        ):
            with patch("sys.stdout", new_callable=StringIO):
                result = x25519_cipher("Hello", self.BOB_PUBLIC)

        expected_public = public_key(ephemeral_private)

        self.assertTrue(result.startswith(expected_public + " "))
        
    def test_decipher_invalid_format(self):
        invalid_messages = [
            "",
            "invalid",
            "one two three",
        ]

        for message in invalid_messages:
            with self.subTest(message=message):
                with self.assertRaises(SystemExit) as cm:
                    x25519_decipher(
                        message,
                        self.BOB_PRIVATE
                    )

                self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

    # Process tests

    def test_process_cipher(self):
        with patch(
            "src.Asymmetric.X25519.X25519.x25519_cipher",
            return_value="mock_ciphered"
        ) as mock_cipher:
            result = x25519_process(
                "Hello",
                self.BOB_PUBLIC,
                True
            )

        mock_cipher.assert_called_once_with(
            "Hello",
            self.BOB_PUBLIC
        )
        self.assertEqual(result, "mock_ciphered")

    def test_process_decipher(self):
        with patch(
            "src.Asymmetric.X25519.X25519.x25519_decipher",
            return_value="mock_deciphered"
        ) as mock_decipher:
            result = x25519_process(
                "mock_ciphertext",
                self.BOB_PRIVATE,
                False
            )

        mock_decipher.assert_called_once_with(
            "mock_ciphertext",
            self.BOB_PRIVATE
        )
        self.assertEqual(result, "mock_deciphered")

    def test_process_missing_key(self):
        with self.assertRaises(SystemExit) as cm:
            x25519_process("Hello", None, True)

        self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

    # Key generation tests

    def test_generate_x25519_keys(self):
        with patch(
            "src.Asymmetric.X25519.X25519.secrets.token_hex",
            return_value=self.ALICE_PRIVATE
        ):
            with patch("sys.stdout", new_callable=StringIO) as output:
                generate_x25519_keys()

        lines = output.getvalue().splitlines()

        self.assertEqual(len(lines), 2)
        self.assertEqual(
            lines[0],
            "public key: " + self.ALICE_PUBLIC
        )
        self.assertEqual(
            lines[1],
            "private key: " + self.ALICE_PRIVATE
        )


if __name__ == "__main__":
    unittest.main()