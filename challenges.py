#!/usr/bin/env python3
#
# My personal solutions for the cryptography challenges posted at:
# http://cryptopals.com/
#
# Usage: ./challenges.py [n]
#
# If n is supplied, run that challenge. Otherwise, run all.

import crypto
import operator
import sys
import textutil

# Register methods as challenges with this decorator.
challenges = {}
def challenge(n):
    def decorator(f):
        def wrapper(*args, **kwargs):
            print('Executing challenge %d...' % n)
            f(*args, **kwargs)
        challenges[n] = wrapper
        return wrapper
    return decorator

def expect(actual, expected):
    if actual != expected:
        print('Failed.')
        print('  Expected: %r' % expected)
        print('  Actual:   %r' % actual)

@challenge(1)
def c1():
    EXAMPLE_INPUT = \
        ('49276d206b696c6c696e6720796f757220627261696e206c' +
         '696b65206120706f69736f6e6f7573206d757368726f6f6d')
    EXAMPLE_OUTPUT = \
        'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    result = crypto.hex_to_base64(EXAMPLE_INPUT)
    print(result)
    expect(result, EXAMPLE_OUTPUT)

@challenge(2)
def c2():
    EXAMPLE_INPUT = ('1c0111001f010100061a024b53535009181c',
                     '686974207468652062756c6c277320657965')
    EXAMPLE_OUTPUT = '746865206b696420646f6e277420706c6179'
    plainbytes, keybytes = map(crypto.hex_to_bytes, EXAMPLE_INPUT)
    crypt_bytes = crypto.crypt_xor(plainbytes, keybytes)
    result = crypto.bytes_to_hex(crypt_bytes)
    print(result)
    expect(result, EXAMPLE_OUTPUT)

@challenge(3)
def c3():
    INPUT = ('1b37373331363f78151b7f2b783431333d' +
             '78397828372d363c78373e783a393b3736')
    inputbytes = crypto.hex_to_bytes(INPUT)
    keyrange = [[byte] for byte in range(0, 255)]
    keybytes, text = crypto.brute_xor(inputbytes, keyrange)
    print('Decoded text: %r' % text)

@challenge(4)
def c4():
    texts = []
    keyrange = [[byte] for byte in range(0, 255)]
    for line in open('inputs/4.txt').readlines():
        line = line.strip()
        if not line:
            continue
        key, text = crypto.brute_xor(crypto.hex_to_bytes(line), keyrange)
        if text: texts.append(text)
    best_text = max(texts, key=textutil.english_probability)
    print('Decoded text: %r' % best_text)

@challenge(5)
def c5():
    PLAINTEXT = ("Burning 'em, if you ain't quick and nimble\n" +
                 "I go crazy when I hear a cymbal")
    KEY = "ICE"
    EXPECTED = ('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c' +
                '2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b' +
                '2027630c692b20283165286326302e27282f')
    result = crypto.bytes_to_hex(crypto.crypt_xor(
                                          crypto.str_to_bytes(PLAINTEXT),
                                          crypto.str_to_bytes(KEY)))
    print(result)
    expect(result, EXPECTED)

@challenge(6)
def c6():
    b64text = open('inputs/6.txt').read()
    cipherbytes = crypto.base64_to_bytes(b64text)
    keysizes = crypto.brute_keysize(cipherbytes)
    keyrange = [[byte] for byte in range(0, 255)]
    # Identify key candidates by trying single byte keys, spaced keysize
    # bytes apart.
    key_candidates = []
    for keysize in keysizes:
        chunks = crypto.split_every_n_bytes(cipherbytes, keysize)
        key = b''
        for chunk in chunks:
            k, text = crypto.brute_xor(chunk, keyrange)
            key += bytes(k)
        key_candidates.append(key)
    # Now run the key candidates and find the winner.
    key, text = crypto.brute_xor(cipherbytes, key_candidates)
    print('Decrypted with key: %s' % key.decode())
    print('%s' % text)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        try:
            n = int(sys.argv[1])
        except ValueError:
            print('Usage: ./challenges.py [n] (where n is an integer)')
            sys.exit(1)
        if not n in challenges:
            print('No such challenge: %d' % n)
            sys.exit(1)
        challenges[n]()
    else:
        for n in sorted(challenges.keys()):
            challenges[n]()
