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
from random import randrange
import textutil
from util import compose

# Use sparingly. :)
from Crypto.Cipher import AES

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

def pkcs7_pad(somebytes, blocksize):
    """
    Return a copy of somebytes with PKCS #7 padding added, bringing the length
    up to an even multiple of blocksize.
    """
    result = bytes(somebytes)
    pad_bytes = blocksize - (len(somebytes) % blocksize)
    result += bytes([pad_bytes] * pad_bytes)
    return result

def pkcs7_unpad(somebytes):
    """
    Return a copy of somebytes with PKCS #7 padding removed.
    """
    return bytes(somebytes[:-somebytes[-1]])

def decrypt_aes_ecb(cryptbytes, keybytes):
    "For now, just a wrapper around Pycrypto AES."
    cipher = AES.new(keybytes)
    return cipher.decrypt(cryptbytes)

def encrypt_aes_ecb(plainbytes, keybytes):
    "For now, just a wrapper around Pycrypto AES."
    cipher = AES.new(keybytes)
    return cipher.encrypt(plainbytes)

def decrypt_aes_cbc(cryptbytes, iv, keybytes):
    """
    Decrypt a CBC-mode AES encryption with the given key. Blocksize
    is assumed to be len(keybytes) (which == len(iv)).
    """
    assert len(iv) == len(keybytes)
    blocksize = len(iv)
    plainbytes = b''
    for i in range(0, len(cryptbytes), blocksize):
        cryptblock = cryptbytes[i:i+blocksize]
        plainbytes += crypt_xor(decrypt_aes_ecb(cryptblock, keybytes), iv)
        iv = cryptblock
    return pkcs7_unpad(plainbytes)

def encrypt_aes_cbc(plainbytes, iv, keybytes):
    """
    Encrypt a CBC-mode AES encryption with the given key. Blocksize
    is assumed to be len(keybytes) (which == len(iv)).
    """
    assert len(iv) == len(keybytes)
    blocksize = len(iv)
    cryptbytes = b''
    for i in range(0, len(plainbytes), blocksize):
        plainblock = plainbytes[i:i+blocksize]
        if len(plainblock) < blocksize:
            plainblock = pkcs7_pad(plainblock, blocksize)
        cryptblock = encrypt_aes_ecb(crypt_xor(plainblock, iv), keybytes)
        cryptbytes += cryptblock
        iv = cryptblock
    return cryptbytes

def junk(length):
    return bytes([randrange(0, 256) for i in range(0, length)])

def make_key():
    return junk(16)

def encryption_oracle(plainbytes):
    """
    As described in challenge 11, generates a random key, some random padding
    around the plaintext, and then encrypts with ECB or CBC mode (randomly),
    returning the encrypted bytes that result.
    """
    key = make_key()
    plainbytes = junk(randrange(5,11)) + plainbytes + junk(randrange(5,11))
    plainbytes = pkcs7_pad(plainbytes, 16)
    if randrange(0, 2):
        cryptbytes = encrypt_aes_ecb(plainbytes, key)
    else:
        iv = junk(16)
        cryptbytes = encrypt_aes_cbc(plainbytes, iv, key)
    return cryptbytes

def encryption_oracle_2(plainbytes):
    """
    As described in challenge 12, very similar to the previous oracle
    function, but always uses ECB mode, the same encryption key. It also
    appends a specific plaintext (base64-encoded so the developer doesn't
    know what it contains).
    """
    b64text = ('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc' +
               '28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZG' +
               'J5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5' +
               'vLCBJIGp1c3QgZHJvdmUgYnkK')
    key = b'CONSTANT CRAVING'
    plainbytes += base64_to_bytes(b64text)
    plainbytes = pkcs7_pad(plainbytes, 16)
    return encrypt_aes_ecb(plainbytes, key)

def identify_aes_mode(cryptbytes, blocksize=16):
    chunks = [cryptbytes[i:i+blocksize]
              for i in range(0, len(cryptbytes), blocksize)]
    duplicates = len(chunks) - len(set(chunks))
    if duplicates:
        return 'ECB'
    else:
        return 'CBC'

def break_ecb(crypt_method):
    """
    Implementation of the solution of challenge 12. It's here because I
    thought it might be somewhat reusable.
    """
    # Step 1: Discover the block size.
    blocksize = brute_ecb_blocksize(crypt_method)
    print('Detected block size: %d' % blocksize)
    # Step 2: Detect ECB.
    testcase = b'x' * blocksize * 2
    mode = identify_aes_mode(crypt_method(testcase), blocksize)
    print('Detected mode: %s' % mode)
    if mode != 'ECB':
        print('Cannot proceed.')
        return
    # Step 3: Get crackin'.
    known = b''
    while True:
        result = crack_byte(crypt_method, blocksize, known)
        if not result:
            break
        known += result
    return known

def brute_ecb_blocksize(crypt_method):
    """
    Throw a bunch of cases at a crypto method until the block size is
    discovered via a repeat in the output.
    """
    blocksize = 0
    # Start guessing at 4... any smaller, seems like we might accidentally
    # identify a block size by chance duplication.
    guess = 4
    # Send twice the guessed block size and look for duplicates.
    testcase = b'x' * guess * 2
    while not blocksize:
        cryptbytes = crypt_method(testcase)
        chunks = [cryptbytes[i:i+guess]
                  for i in range(0, len(cryptbytes), guess)]
        if len(chunks) > len(set(chunks)):
            blocksize = guess
            break
        testcase += b'xx'
        guess += 1
    return blocksize

def crack_byte(crypt_method, blocksize, known):
    """
    Pretty specific to challenge 12: calls crypt_method 256 times to figure
    out the byte that follows the given 'known' bytes. Returns None if it
    can't determine a next byte.
    """
    # This could probably be prettier.
    result = None
    if len(known) < blocksize:
        # Breaking the first block
        plainbytes = b'A' * (blocksize-len(known)-1)
        table = build_lookup_table(crypt_method, blocksize, plainbytes+known)
        result = bytes([table[crypt_method(plainbytes)[:blocksize]]])
    else:
        # Breaking subsequent blocks is a little trickier. Build a lookup
        # table as usual, then force the target text to align with a block so
        # that we can look it up.
        plainbytes = known[-blocksize+1:]
        table = build_lookup_table(crypt_method, blocksize, plainbytes)
        # In this case, padding exists only to align the target block correctly
        padding = b'A' * (blocksize - (len(known) % blocksize) - 1)
        # Offset to the encrypted block we care about
        offset = len(padding) + len(known) - blocksize + 1
        cryptbytes = crypt_method(padding)
        chunk = cryptbytes[offset:offset+blocksize]
        if chunk in table:
            result = bytes([table[chunk]])
    return result

def build_lookup_table(crypt_method, blocksize, prefix):
    """
    Build a lookup table by adding one byte onto prefix. Returned table maps
    encrypted blocks to the single byte that was appended to create them.
    """
    assert len(prefix) == blocksize - 1
    table = {}
    for x in range(0, 256):
        testcase = prefix + bytes([x])
        crypt_chunk = crypt_method(testcase)[:blocksize]
        table[crypt_chunk] = x
    return table
