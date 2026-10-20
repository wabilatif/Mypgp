##
## EPITECH PROJECT, 2026
## utils.py
## File description:
## Utils basic functions
##

# --- Conversions texte <-> hexadécimal little-endian (usage: RSA) ---
# Le message entier est traité comme UN SEUL grand nombre : l'ordre de
# TOUS les octets est inversé (little-endian global du message).


import sys

def exit_error(msg="Error"):
    """Écrit le message sur stderr et quitte le programme avec le code 84."""
    sys.stderr.write(f"{msg}\n")
    sys.exit(84)

def str_to_ltendian(text: str) -> list:
    """
    Convertit une chaine de caracteres en une liste d'octets (chacun
    represente par une chaine hexa de 2 caracteres), dans l'ordre
    little-endian (octet de poids faible en premier).

    A utiliser quand le message doit etre traite comme un seul grand
    nombre (ex: RSA), pas pour un decoupage en blocs (voir cut_str).

    Exemple:
        >>> str_to_ltendian("WF")
        ['46', '57']
        # "WF" -> octets 0x57 0x46 -> ordre inverse -> ['46', '57']

    Erreur:
        Renvoie None et affiche un message sur stdout si text est vide.
    """
    if not text:
        exit_error("Error: empty input.")
    new_text = text.encode('utf-8').hex()
    result = []
    index = 0
    while index < (len(new_text) - 1):
        result.append(new_text[index] + new_text[index + 1])
        index += 2
    result = result[::-1]

    return result

def bring_together(text: str) -> list:
    """
    Convertit une chaine de caracteres hexa en une liste d'octets (chacun
    represente par une chaine hexa de 2 caracteres), dans l'ordre
    little-endian (octet de poids faible en premier).

    A utiliser quand le message doit etre traite comme un seul grand
    nombre (ex: RSA), pas pour un decoupage en blocs (voir cut_str).

    Exemple:
        >>> str_to_ltendian("WF")
        ['46', '57']
        # "WF" -> octets 0x57 0x46 -> ordre inverse -> ['46', '57']

    Erreur:
        Renvoie None et affiche un message sur stdout si text est vide.
    """
    if not text:
        exit_error("Error: empty input.")
    if len(text) % 2 != 0 :
        text = "0" + text
    new_text = text
    result = []
    index = 0
    while index < (len(new_text) - 1):
        result.append(new_text[index] + new_text[index + 1])
        index += 2
    result = result[::-1]

    return result


def ltendian_to_str(the_list: list) -> str:
    """
    Fait l'operation inverse de str_to_ltendian: prend une liste
    d'octets (chaines hexa de 2 caracteres) en ordre little-endian,
    et reconstruit la chaine de caracteres d'origine.

    Exemple:
        >>> ltendian_to_str(['46', '57'])
        'WF'

    Erreur:
        Renvoie None et affiche un message sur stdout si the_list
        est vide.
    """
    if not the_list:
        exit_error("Error: empty list.")
    the_list = the_list[::-1]
    message = "".join(the_list)
    try:
        return bytes.fromhex(message).decode('utf-8')
    except Exception:
        exit_error("Error: invalid hex/utf-8 conversion.")

# --- Inversion d'ordre generique (usage: RSA) ---

def bigendian_to_ltendian(the_list: list) -> list:
    """
    Inverse l'ordre des elements d'une liste deja groupee par octets
    (chaines hexa de 2 caracteres). Utile pour passer d'une
    representation big-endian a little-endian (ou l'inverse, puisque
    l'operation est symetrique).

    Exemple:
        >>> bigendian_to_ltendian(['57', '46'])
        ['46', '57']

    Erreur:
        Renvoie None et affiche un message sur stdout si the_list
        est vide.
    """
    if not the_list:
        exit_error("Error: empty input.")
    return the_list[::1]


# --- Decoupage en blocs + padding par zeros (usage: XOR / AES) ---
# Contrairement a str_to_ltendian, ici on NE reordonne PAS le message
# entier: on garde l'ordre naturel de lecture, on decoupe en blocs de
# taille fixe, et seul le DERNIER bloc est complete par des zeros
# s'il est trop court.

def split_blocks(data: bytes, size: int) -> list[bytes]:
    """Découpe un objet bytes en blocs de taille `size`."""
    if not data or size <= 0:
        exit_error("Error: invalid data or block size.")
    return [data[i:i + size] for i in range(0, len(data), size)]

def cut_block(block: list, size: int) -> list:
    """
    Decoupe une liste DEJA CONVERTIE en octets (chaines hexa de 2
    caracteres, ex: sortie de str_to_ltendian ou bigendian_to_ltendian)
    en blocs de taille "size" octets. Le dernier bloc est complete
    avec des zeros s'il est plus court que "size".

    A utiliser quand tu as deja une liste d'octets sous forme de
    chaines hexa (pas une string brute -> voir cut_str pour ce cas).

    Exemple:
        >>> cut_block(['57', '69', '6e'], 4)
        [[0x57, 0x69, 0x6e, 0]]  # dernier octet paddé a 0
    """
    if not block or size <= 0:
        exit_error("Error: invalid block or size.")

    new_block = []
    number_of_block = (len(block) + size - 1) // size
    index = 0
    while index < number_of_block:
        liste = [0] * size
        little_block = block[(index * size): ((index * size) + (size))]
        num = 0
        for x in little_block:
            liste[num] = int(x, 16) if isinstance(x, str) else x
            num += 1
        new_block.append(liste)
        index += 1
    return new_block


def cut_str(block: str, size: int) -> list:
    """
    Decoupe directement une chaine de caracteres BRUTE (pas encore
    convertie) en blocs de "size" octets (entiers 0-255), dans
    l'ordre naturel de lecture (aucune inversion globale, contrairement
    a str_to_ltendian). Le dernier bloc est complete avec des zeros
    s'il est plus court que "size".

    A utiliser directement sur un texte brut pour XOR/AES en mode
    stream (voir sujet: "you must encrypt/decrypt data by chunks of
    blocks... If the last block is smaller than the KEY, you must
    pad it with zeros.").

    Exemple:
        >>> cut_str("hi", 4)
        [[104, 105, 0, 0]]  # 'h'=104, 'i'=105, puis padding
    """
    if not block or size <= 0:
        exit_error("Error: empty string or invalid size.")
    hex_data = block.encode('utf-8').hex()
    new_block = []
    number_of_block = (len(hex_data) + (size * 2) - 1) // (size * 2)
    index = 0
    while index < number_of_block:
        liste = [0] * size
        little_block = hex_data[(index * (size * 2)): ((index * (size * 2)) + (size * 2))]
        num = 0
        position = 0
        while num < len(little_block):
            if num + 1 < len(little_block):
                liste[position] = int(little_block[num] + little_block[num + 1], 16)
            num += 2
            position += 1
        new_block.append(liste)
        index += 1
    return new_block

def hex_to_bytes_le(hex_str: str) -> bytes:
    """
    Prend une chaîne hexadécimale en little-endian, inverse l'ordre
    des octets pour retrouver la séquence brute de bytes.
    """
    raw_bytes = bytes.fromhex(hex_str)
    return raw_bytes[::-1]

def bytes_to_hex_le(data: bytes) -> str:
    """
    Prend des bytes et renvoie leur représentation hexadécimale en little-endian.
    """
    return data[::-1].hex()

def pad_zeros(data: bytes, size: int) -> bytes:
    """
    Complete un bloc de bytes avec des zeros ('\\x00') a la fin
    s'il est plus court que la taille 'size' demandee.
    """
    if len(data) < size:
        return data + b'\x00' * (size - len(data))
    return data

def bytes_to_state(block: bytes) -> list:
    return [[block[r + 4 * c] for c in range(4)] for r in range(4)]

def state_to_bytes(state: list) -> bytes:
    return bytes(state[r][c] for c in range(4) for r in range(4))

def swap_words(data: bytes) -> bytes:
    return b"".join(data[i:i + 4][::-1] for i in range(0, len(data), 4))
