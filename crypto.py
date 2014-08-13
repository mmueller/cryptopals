#!/usr/bin/env python3
#
# General purpose crypto routines developed for crypto challenge:
# http://cryptopals.com/
#
# While this is a coding exercise, I try not to reinvent basic wheels like
# hex encoding and rely on Python builtins instead. However, I split out
# everything into very primitive (but nicely-named) methods because I keep
# coming across cases where I need these small transformations and Python's
# stdlib is really inconsistent about names and return types.

import base64
import binascii
from itertools import combinations, cycle, starmap
import textutil
from util import compose

def hex_to_bytes(hexstr):
    "For consistency's sake; this is just a wrapper."
    return bytes.fromhex(hexstr)

def hex_to_str(hexstr, encoding='utf-8'):
    "Decode the given hex as if it is a plaintext string."
    return binascii.a2b_hex(hexstr).decode(encoding=encoding)

def bytes_to_base64(b):
    "Return an ASCII-encoded base64 text representing the given bytes."
    return base64.b64encode(b).decode()

hex_to_base64 = compose(bytes_to_base64, hex_to_bytes)

def bytes_to_hex(b):
    return binascii.b2a_hex(b).decode()

def str_to_bytes(text):
    return bytes(text, encoding='utf-8')

str_to_hex = compose(bytes_to_hex, str_to_bytes)

def base64_to_bytes(b):
    return base64.b64decode(b)

def crypt_xor(plainbytes, keybytes):
    """
    Take a plaintext bytes object and xor it with the given key bytes. Key
    will be cycled if it is shorter than plaintext. Returns bytes.
    """
    return bytes([b1 ^ b2 for b1, b2 in zip(plainbytes, cycle(keybytes))])

def brute_xor(cipherbytes, keyiter):
    """
    Take a cipher bytes object and xor it with every key bytes object in the
    given iterable. Returns a tuple of the best key (bytes) and the decoded
    text (string), assuming English plaintext.
    """
    best = (0.0, None, None)
    for keybytes in keyiter:
        try:
            text = crypt_xor(cipherbytes, keybytes).decode()
            score = textutil.english_probability(text)
            if score > best[0]:
                best = (score, keybytes, text)
        except UnicodeDecodeError:
            pass
    return best[1:]

def brute_keysize(cipherbytes):
    """
    Use statistical analysis to try to determine the length (in bytes) of a
    repeating key that was used to encrypt the given cipher text. Returns a
    list of the best 5 guesses, in descending order of likelihood.
    """
    distances = []
    for keysize in range(2, 100):
        chunks = [cipherbytes[keysize*n:keysize*(n+1)] for n in range(0,4)]
        if len(chunks[-1]) < keysize:
            # Cipher text isn't long enough to discover a key this big.
            break
        ds = list(starmap(textutil.hamming_distance, zip(chunks, chunks[1:])))
        # Normalized distance to keysize
        avg_distance = float(sum(ds))/len(ds)/keysize
        distances.append((keysize, avg_distance))
    distances = sorted(distances, key=lambda item: item[1])
    return [item[0] for item in distances[:5]]

def split_every_n_bytes(cipherbytes, n):
    """
    Break up the given bytes into n byte arrays using a kind of round robin
    approach. For example:

      split_every_n_bytes(b'abcdefg', 3)
      ==> [b'adg', b'be', b'cf']
    """
    results = [b''] * n
    for index, byte in enumerate(cipherbytes):
        results[index % n] += bytes([byte])
    return results
