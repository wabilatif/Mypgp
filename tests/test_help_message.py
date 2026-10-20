##
## EPITECH PROJECT, 2026
## test_help_message.py
## File description:
## Unittest for help_message
##

import unittest
from io import StringIO
from unittest.mock import patch
from src.help_message import help_message

class TestHelpMessage(unittest.TestCase):
  @patch("sys.stdout", new_callable=StringIO)
  def test_help_message_output(self, mock_stdout):
    help_message()
    output = mock_stdout.getvalue()
    self.assertIn("USAGE", output)
    self.assertIn("./my_pgp CRYPTO_SYSTEM MODE", output)
    self.assertIn("CRYPTO SYSTEM", output)
    self.assertIn("xor", output)

if __name__ == "__main__":
  unittest.main()
