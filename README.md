# my\_pgp

my\_pgp is a third-year cryptography project at Epitech. It implements custom cryptographic algorithms in standard Python without external dependencies, including XOR, AES-128, RSA, X25519, and a hybrid PGP-like cryptosystem (RSA combined with XOR or AES).

## Features

* **Zero External Dependencies**: Built entirely with standard Python libraries. All cryptographic primitives are written from scratch.
* **Symmetric Encryption**: Support for basic XOR stream/block encryption and AES-128 (Advanced Encryption Standard).
* **Asymmetric Encryption**: RSA key pair generation, public key encryption, and private key decryption.
* **Second Asymmetric Cryptosystem (X25519)**: Elliptic-curve key exchange on Curve25519 (RFC 7748), with key pair generation and a hybrid ciphering mode built on top of it.
* **Hybrid Cryptosystem (PGP)**: Combines the speed of symmetric encryption (XOR/AES) with the key-exchange security of asymmetric encryption (RSA).
* **Flexible Processing Modes**:
  * Block mode (`-b`): Processes fixed-size single blocks where key and message length match.
  * Stream mode (default): Processes messages of arbitrary length block by block using zero-padding.
* **Custom Key Format**: Supports hex-encoded values in little-endian format.

## Use Cases

* **Secure Document Exchange**: Encrypt large files or messages efficiently with AES-128 using a randomly generated symmetric key, then safely transmit the symmetric key encrypted via RSA.
* **Key Pair Generation**: Fast local creation of RSA public/private key pairs from selected prime numbers `P` and `Q`, or of X25519 key pairs from random bytes.
* **Educational Cryptanalysis & Verification**: Trace and verify low-level cryptographic primitives (S-Box substitutions, MixColumns, Montgomery exponentiation, Montgomery ladder, bitwise XOR) step by step.

## Getting Started

### Prerequisites

* Python 3.x installed on your machine.
* No external libraries or pip packages required.

### 1. Setup

Clone the repository and ensure the executable script has execution permissions:

```bash
chmod +x my_pgp
```

### 2. Usage Syntax

```bash
./my_pgp CRYPTO_SYSTEM MODE [OPTIONS] [KEY]
```

#### Supported Cryptosystems (`CRYPTO_SYSTEM`)

| CRYPTO\_SYSTEM | Description                                  |
| -------------- | -------------------------------------------- |
| `xor`        | computation using XOR algorithm              |
| `aes`        | computation using AES-128 algorithm          |
| `rsa`        | computation using RSA algorithm              |
| `x25519`     | computation using X25519 (Curve25519)        |
| `pgp-xor`    | computation using both RSA and XOR algorithm |
| `pgp-aes`    | computation using both RSA and AES algorithm |

| MODE       | Description                                                                                                                                 |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `-c`     | the message is clear, we want to cipher it                                                                                                  |
| `-d`     | the message is ciphered, we want to decipher it                                                                                             |
| -s         | RSA only : To add a signature to the message, you will need to use your private key to sign it and your public key to verify the signature |
| `-g P Q` | RSA only: don't read a MESSAGE, but instead generate a public and private key pair from the prime number P and Q                            |
| `-g`     | X25519 only: don't read a MESSAGE, but instead generate a random public and private key pair (no argument)                                  |

| OPTION | Description                                                                                            |
| ------ | ------------------------------------------------------------------------------------------------------ |
| `-b` | for XOR, AES and PGP, only works on one block. The MESSAGE and the symmetric key must be the same size |

> **Notes on Data Formats:**
>
> * Numbers (keys, ciphertexts, RSA parameters) are formatted as hexadecimal values in little-endian byte order.
> * X25519 keys are 32 bytes (64 hexadecimal characters).
> * Without `-b`, the program runs in stream mode, padding the final block with zero bytes (`0x00`) if needed.
> * Error Handling: On error, an error message is printed to stderr and the program exits with code 84 (0 on success).

### 3. Usage Examples

#### XOR Encryption / Decryption

```bash
echo "You know nothing, Jon Snow" > message
./my_pgp xor -c -b 576861742069732064656164206d6179206e6576657220646965 < message > ciphered
./my_pgp xor -d -b 576861742069732064656164206d6179206e6576657220646965 < ciphered
```

#### AES-128

```bash
echo "All men must die" > message
./my_pgp aes -c -b 57696e74657220697320636f6d696e67 < message > ciphered
./my_pgp aes -d -b 57696e74657220697320636f6d696e67 < ciphered
```

Encrypt / decrypt with these keys:

Generate a key pair from two primes:

#### RSA Keygen & Encryption & Signature

```bash
./my_pgp rsa -g d3 e3
public key: 0101-19bb
private key: 9d5b-19bb
```

```bash
echo "WF" | ./my_pgp rsa -c 0101-19bb
echo "8f84" | ./my_pgp rsa -d 9d5b-19bb

echo "The night is dark and full of terrors" | ./my_pgp rsa -c clé_public_du_destinatiare -s clé_privé_expéditeur
echo "Message_encrypter Message_signer" | ./my_pgp rsa -d clé_privé_du_destinatiare -s clé_public_expéditeur
```

#### X25519 Keygen & Encryption

Generate a random key pair (`-g` takes no argument for X25519):

```bash
./my_pgp x25519 -g
public key: 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
private key: 77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a
```



Cipher with the **public** key, decipher with the **private** key:

```bash
echo "All men must die" | ./my_pgp x25519 -c PUBLIC_KEY > ciphered
cat ciphered | ./my_pgp x25519 -d PRIVATE_KEY
```

> The ciphered output is different every time, because a new ephemeral key pair is drawn at each ciphering. It is made of two lines (see the [X25519 specification](#5-x25519-asymmetric)), so the whole file must be given to `-d`.

#### PGP Hybrid Encryption

The key parameter format is `SYMMETRIC_KEY:RSA_KEY`.

* **Encryption output:** The first line contains the RSA-encrypted symmetric key, followed by the symmetric-encrypted payload message.

```bash
echo "All men must die" | ./my_pgp pgp-aes -c -b SYMMETRIC_KEY:RSA_PUBLIC_KEY
echo "CIPHERED_MESSAGE" | ./my_pgp pgp-aes -d -b CIPHERED_SYMMETRIC_KEY:RSA_PRIVATE_KEY
```

## Cryptographic Specifications & Architecture

### Implemented Cryptosystems

#### 1. XOR (Symmetric)

* **Concept:** Applies a bitwise XOR operation (\$\\oplus\$) between the plaintext block \$M\$ and the symmetric key \$K\$: \$C = M \\oplus K\$
* **Symmetry:** Decryption follows the exact same mathematical transformation (\$M = C \\oplus K\$).

#### 2. AES-128 (Symmetric)

* **Block Size:** 128 bits (16 bytes), formatted as a \$4 \\times 4\$ state matrix of bytes.
* **Key Size:** 128 bits (10 transformation rounds).
* **Rounds Structure:**
  * Initial Round: `AddRoundKey`
  * Rounds 1 to 9: `SubBytes` (S-Box lookup), `ShiftRows`, `MixColumns` (Galois Field \$GF(2^8)\$ multiplication), and `AddRoundKey`.
  * Final Round (Round 10): `SubBytes`, `ShiftRows`, and `AddRoundKey` (omits `MixColumns`).
* **Decryption:** Reverses operations using inverse S-Boxes, `InvShiftRows`, `InvMixColumns`, and round keys in reverse order.

#### 3. RSA (Asymmetric)

* **Key Generation:** Given primes \$P\$ and \$Q\$:
  * Modulus \$N = P \\times Q\$
  * Euler's totient \$\\phi(N) = (P - 1)(Q - 1)\$
  * Public exponent \$e\$ chosen such that \$\\gcd(e, \\phi(N)) = 1\$
  * Private exponent \$d\$ calculated as modular multiplicative inverse: \$d \\equiv e^{-1} \\pmod{\\phi(N)}\$
* **Operations:**
  * Encryption: \$C \\equiv M^e \\pmod N\$
  * Decryption: \$M \\equiv C^d \\pmod N\$

#### 4. PGP Hybrid Scheme

Because RSA is computationally expensive for large messages and AES/XOR require key sharing, the PGP (Pretty Good Privacy) scheme combines both:

* **Encryption (`pgp-xor` / `pgp-aes`):**
  * A symmetric key \$K\_{sym}\$ is used to encrypt the payload \$M\$ using XOR or AES.
  * The recipient's RSA public key \$K\_{pub}\$ is used to encrypt \$K\_{sym}\$.
  * Output format:
    * Line 1: \$RSAEncrypt(K\_{pub}, K\_{sym})\$
    * Remaining lines: \$SymmetricEncrypt(K\_{sym}, M)\$
* **Decryption:**
  * The recipient decrypts \$K\_{sym}\$ using their RSA private key \$K\_{priv}\$.
  * The decrypted \$K\_{sym}\$ is then used to decipher the main payload message \$M\$.

#### 5. X25519 (Asymmetric)

X25519 is an elliptic-curve Diffie-Hellman function on Curve25519, defined in [RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748). It is a **key exchange** primitive and not an encryption algorithm, so ciphering a message with it relies on the same hybrid idea as PGP.

* **Keys:** 32 bytes each (64 hexadecimal characters), in little-endian, which is the native X25519 encoding.

  * Private key \$k\$: 32 random bytes (drawn with Python's `secrets` module). The bits required by the algorithm are forced on use ("clamping").
  * Public key: \$k \\cdot 9\$, the scalar multiplication of the curve base point \$u = 9\$ by \$k\$.
* **Scalar multiplication:** computed with the Montgomery ladder over the prime field \$p = 2^{255} - 19\$, using only additions and multiplications modulo \$p\$.
* **Shared secret:** for two key pairs, \$k\_A \\cdot (k\_B \\cdot 9) = k\_B \\cdot (k\_A \\cdot 9)\$. Both parties obtain the same value without ever sending it.
* **Encryption (`-c`, with the recipient's public key):**

  1. An ephemeral key pair is generated.
  2. The shared secret is computed from the ephemeral private key and the recipient's public key.
  3. The symmetric key is derived with SHA-256 of the shared secret.
  4. The message is ciphered with the XOR cryptosystem of the project, using this key.

  * Output format:
    * Line 1: the ephemeral public key
    * Line 2: the ciphered message
* **Decryption (`-d`, with the recipient's private key):**

  1. The ephemeral public key is read from line 1.
  2. The same shared secret and symmetric key are recomputed with the private key.
  3. The ciphered message is deciphered with XOR.
* **Limits:** the XOR step reuses the same 32-byte key for every block, and the ciphered message carries no integrity check: deciphering with a wrong key returns unreadable text instead of an error.

## Project Structure

```
.
├── my_pgp                         # Executable entry point
├── src/
│   ├── Asymmetric/
│   │   ├── RSA/
│   │   │   ├── generate_key.py    # Generate RSA key
│   │   │   └── rsa.py             # RSA implementation
│   │   │   └── signature.py             # RSA signature implementation
│   │   └── X25519/
│   │       └── X25519.py          # X25519 implementation (keygen, cipher, decipher)
│   ├── Hybrid/pgp.py              # Hybrid engine orchestrating RSA and symmetric ciphers
│   ├── Symmetric/
│   │   ├── AES/aes.py             # AES implementation
│   │   └── XOR/xor.py             # XOR implementation
│   ├── cli.py                     # Parsing
│   ├── help_message.py            # display usage
│   ├── main.py                    # main file
│   └── utils.py                   # Hex conversion, little-endian formatting, padding helpers
└── tests/                         # Unit tests
```

## Testing

Run unit tests and cryptosystem validation tests:

```bash
python3 -m unittest discover tests/
```

## License

Epitech.
