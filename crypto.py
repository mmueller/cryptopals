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
from random import randrange, sample
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
    pad_bytes = blocksize - (len(somebytes) % blocksize)
    result = somebytes + bytes([pad_bytes] * pad_bytes)
    return result

def pkcs7_unpad(somebytes):
    """
    Return a copy of somebytes with PKCS #7 padding removed.
    """
    assert pkcs7_is_padded(somebytes)
    return somebytes[:-somebytes[-1]]

def pkcs7_is_padded(somebytes):
    """
    Returns True if the given bytes have valid PKCS #7 padding at the end,
    otherwise False.
    """
    padding = somebytes[-somebytes[-1]:]
    return all([padding[b] == len(padding) for b in range(0, len(padding))])

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

def encryption_oracle_3(plainbytes):
    """
    As described in challenge 14, this modifies encryption_oracle_2 to prepend
    a random amount of junk at the beginning, so that the plaintext fed to the
    encryption function is: (random junk) + (plainbytes) + (target to decrypt)
    """
    b64text = ('SSB0aGluayBvZiBDaGluZXNlIGZvb2Qgd2hlbiBJIHRoaW5rIG9mI' +
               'GxpZmUKSXQncyBzd2VldCBhbmQgc291cgpNeSBsaWZlIGlzIHN3ZW' +
               'V0IGFzIHNhY2NoYXJpbmUKWW91IGtub3cgdGhyZWUtd2Vlay1vbGQ' +
               'gbWlsayBhbmQgZ3JhcGVzIGFyZSBub3QKTm90IHRoZSBzYW1lLCBu' +
               'bwpJIGFtIHRoZSBvbmUgSm9obm55IENhcmNpbm9nZW4=')
    key = b'THE LONGEST LINE'
    plainbytes = junk(randrange(0,64)) + plainbytes + base64_to_bytes(b64text)
    return encrypt_aes_ecb(pkcs7_pad(plainbytes, len(key)), key)

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
    General purpose AES ECB thing. Takes crypt_methods that take a plaintext
    and then append a secret message prior to encrypting, and discovers that
    secret message. Does not depend on any particular alignment; as a result,
    makes a LOT of calls to the crypt_method.

    Solves challenges #12 and #14.
    """
    blocksize = brute_ecb_blocksize(crypt_method)
    if not blocksize:
        print('Unable to determine block size. :(')
        return None
    print('Found blocksize: %d' % blocksize)

    known = b''
    while True:
        prefix = b''
        if len(known) < blocksize:
            prefix = bytes(sample(range(0, 256), blocksize-len(known)-1))
        table = build_lookup_table(crypt_method, blocksize,
                                   prefix+known[-blocksize+1:])
        byte = None
        while byte is None:
            # Don't rely on the crypt method to be evenly distributed with its
            # randomness, pad the input a random amount first.
            plainbytes = bytes(sample(range(0, 256), randrange(0, blocksize)))
            plainbytes += prefix
            cryptbytes = crypt_method(plainbytes)
            chunks = [cryptbytes[i:i+blocksize]
                      for i in range(0, len(cryptbytes), blocksize)]
            for chunk in chunks:
                if chunk in table:
                    byte = table[chunk]
                    known += bytes([byte])
                    print('\rDecrypted %d bytes...' % len(known),
                          end='', flush=True)
                    break
        if pkcs7_is_padded(known):
            known = pkcs7_unpad(known).decode()
            break
    print(' Done!')
    return known

def brute_ecb_blocksize(crypt_method):
    """
    Determine blocksize by throwing repeating strings with a period of
    [guessed blocksize] at the encryption routine and look for repeating
    motifs in the result. This doesn't require us to know where (exactly) our
    input text will be inserted.
    """
    REPEATS = 20
    for blocksize in range(4, 128):
        motif = sample(range(0, 256), blocksize)
        plainbytes = bytes(motif) * REPEATS
        cryptbytes = crypt_method(plainbytes)
        max_repeats, _ = find_longest_repeat(cryptbytes, blocksize)
        # If aligned on a block boundary, we'll see n repeats, otherwise n-1
        if max_repeats in [REPEATS-1, REPEATS]:
            return blocksize
    return None

def build_lookup_table(crypt_method, blocksize, prefix):
    """
    Build a lookup table by adding one byte onto prefix. Returned table maps
    encrypted blocks to the single byte that was appended to create them.
    """
    assert len(prefix) == blocksize - 1
    table = {}
    for x in range(0, 256):
        testcase = prefix + bytes([x])
        crypt_chunk = block_oracle(crypt_method, blocksize, testcase)
        table[crypt_chunk] = x
    return table

def block_oracle(crypt_method, blocksize, plainbytes):
    """
    Return the encrypted bytes for the given plainbytes and block size,
    regardless of where the plaintext might appear. (So any random amount
    of padding before the plainbytes will not cause a problem.)
    """
    assert len(plainbytes) == blocksize
    # Lower is faster, but increases possibility of a false positive.
    REPEATS = 10
    repeated_bytes = plainbytes * REPEATS
    inbytes = b'\x00'.join([repeated_bytes] * blocksize)
    cryptbytes = crypt_method(inbytes)
    max_repeats, cryptbytes = find_longest_repeat(cryptbytes, blocksize)
    # If aligned on a block boundary, we should find a case with n REPEATS
    if max_repeats == REPEATS:
        return cryptbytes
    raise Exception('Failed to find the encrypted bytes.')

def find_longest_repeat(data, blocksize):
    """
    Break up data into chunks of blocksize and look for the longest continuous
    string of repeated chunks. Returns a tuple (max_repeats, repeated_content).
    """
    chunks = [data[i:i+blocksize] for i in range(0, len(data), blocksize)]
    prev = None
    count = 1
    max_result = (0, None)
    for chunk in chunks:
        if chunk == prev:
            count += 1
        else:
            count = 1
        if count > max_result[0]:
            max_result = (count, chunk)
        prev = chunk
    return max_result
