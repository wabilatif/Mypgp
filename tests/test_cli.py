##
## EPITECH PROJECT, 2026
## test_cli.py
## File description:
## Unittest for cli
##

import unittest
from unittest.mock import patch
import io
from src.cli import parse_cli, EXIT_ERROR_CODE, EXIT_SUCCESS_CODE

class TestCLI(unittest.TestCase):

    @patch('sys.argv', ['cli.py', '-h'])
    @patch('src.cli.help_message')
    def test_help_flag(self, mock_help_message):
        with self.assertRaises(SystemExit) as cm:
            parse_cli()
        self.assertEqual(cm.exception.code, EXIT_SUCCESS_CODE)
        mock_help_message.assert_called_once()

    @patch('sys.argv', ['cli.py', 'xor', '-c', 'my_secret_key'])
    @patch('sys.stdin', io.StringIO('hello world\n'))
    def test_valid_xor_args(self):
        args = parse_cli()
        self.assertEqual(args.crypto_system, 'xor')
        self.assertEqual(args.mode, '-c')
        self.assertFalse(args.is_block_mode)
        self.assertEqual(args.key, 'my_secret_key')
        self.assertEqual(args.message, 'hello world')

    @patch('sys.argv', ['cli.py', 'rsa', '-g', '61', '53'])
    def test_valid_rsa_generate_args(self):
        args = parse_cli()
        self.assertEqual(args.crypto_system, 'rsa')
        self.assertEqual(args.mode, 'g')
        self.assertEqual(args.rsa_p, '61')
        self.assertEqual(args.rsa_q, '53')
        self.assertIsNone(args.key)

    @patch('sys.argv', ['cli.py', 'invalid_system', '-c', 'key'])
    def test_invalid_crypto_system(self):
        with self.assertRaises(SystemExit) as cm:
            parse_cli()
        self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

    @patch('sys.argv', ['cli.py', 'xor', '-x', 'key'])
    def test_invalid_mode_flag(self):
        with self.assertRaises(SystemExit) as cm:
            parse_cli()
        self.assertEqual(cm.exception.code, EXIT_ERROR_CODE)

if __name__ == '__main__':
    unittest.main()
