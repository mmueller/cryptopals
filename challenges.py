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
from random import randrange
import sys
import textutil
import util

from Crypto.Cipher import AES

# Register methods as challenges with this decorator.
challenges = {}
def challenge(n):
    def decorator(f):
        def wrapper(*args, **kwargs):
            print('')
            print('-----------------------')
            print(' Begin challenge %d...' % n)
            print('-----------------------')
            print('')
            f(*args, **kwargs)
        challenges[n] = wrapper
        return wrapper
    return decorator

def expect(actual, expected):
    if actual != expected:
        print('Failed.')
        print('  Expected: %r' % expected)
        print('  Actual:   %r' % actual)
        return False
    return True

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

@challenge(7)
def c7():
    b64text = open('inputs/7.txt').read()
    cryptbytes = crypto.base64_to_bytes(b64text)
    text = crypto.decrypt_aes_ecb(cryptbytes, b'YELLOW SUBMARINE').decode()
    print('Decrypted:')
    print('%s' % text)

@challenge(8)
def c8():
    for line_no, line in enumerate(open('inputs/8.txt').readlines()):
        crypthex = line.strip()
        chunks = [crypthex[i:i+32] for i in range(0, len(crypthex), 32)]
        duplicates = len(chunks) - len(set(chunks))
        if duplicates > 0:
            print('Line %d: probable block cipher (%d repeated blocks)' %
                  (line_no, duplicates))
            # Are we supposed to decrypt it?

@challenge(9)
def c9():
    INPUT = 'YELLOW SUBMARINE'
    EXPECT = b'YELLOW SUBMARINE\x04\x04\x04\x04'
    result = crypto.pkcs7_pad(crypto.str_to_bytes(INPUT), 20)
    print(result)
    expect(result, EXPECT)

@challenge(10)
def c10():
    # My own test data
    message = 'The crow flies from the chicken coop at dawn.'
    key = b'YeLlOw SuBmArInE'
    blocksize = len(key)
    iv = bytes([randrange(0, 256) for i in range(0, blocksize)])
    cryptbytes = crypto.encrypt_aes_cbc(crypto.str_to_bytes(message), iv, key)
    print('Encrypted: %r' % cryptbytes)
    plainbytes = crypto.decrypt_aes_cbc(cryptbytes, iv, key)
    print('Decrypted: %r' % plainbytes.decode())
    expect(plainbytes.decode(), message)

    # Decrypt the example from Cryptopals
    key = b'YELLOW SUBMARINE'
    blocksize = len(key)
    iv = bytes([0]*blocksize)
    cryptbytes = crypto.base64_to_bytes(open('inputs/10.txt').read())
    decrypted = crypto.decrypt_aes_cbc(cryptbytes, iv, key)
    print(decrypted.decode())

@challenge(11)
def c11():
    # Need to provoke a duplicate encrypted block, so let's include at least
    # 32 bytes of redundant input, plus another 32 just to compensate for any
    # padding.
    inputbytes = bytes([0]*64)
    ecb_count = 0
    cbc_count = 0
    # Run a lot of trials and expect about a 1:1 ratio of ECB:CBC detected.
    trials = 10000
    for i in range(0, trials):
        mode = crypto.identify_aes_mode(crypto.encryption_oracle(inputbytes))
        if mode == 'ECB': ecb_count += 1
        elif mode == 'CBC': cbc_count += 1
        else: raise Exception('Unexpected mode string: %s' % mode)
    print('ECB count: %d' % ecb_count)
    print('CBC count: %d' % cbc_count)
    if abs(1 - float(ecb_count)/cbc_count) < 0.1:
        print('Looks good to me.')
    else:
        print('Might not be working very well.')

@challenge(12)
def c12():
    plaintext = crypto.break_ecb(crypto.encryption_oracle_2)
    print('Discovered plaintext:')
    print(plaintext)

@challenge(13)
def c13():
    # Using only the user input to encrypted_profile_for() (as an oracle to
    # generate "valid" ciphertexts) and the ciphertexts themselves, make a
    # role=admin profile.
    # 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    # email=XXXXXXXXXXadmin&uid=10&role=user
    # email=u@trustme.com&uid=10&role=user
    crypted_admin = util.encrypted_profile_for('XXXXXXXXXXadmin')[16:32]
    temp = util.encrypted_profile_for('u@trustme.com')
    crypted_email_uid = temp[0:32]
    crypted_trail= temp[32:]
    # This ends up: email=u@trustme.com&uid=10&role=admin&uid=10&roluser
    # uid is repeated and there is a trailing 'roluser' parameter not assigned
    # to any value.  Depending how the server is implemented, it may work.
    # It's possible there is an even cleaner solution.
    evil_profile = crypted_email_uid + crypted_admin + crypted_trail
    print(util.decrypt_profile(evil_profile))

@challenge(14)
def c14():
    message = crypto.break_ecb(crypto.encryption_oracle_3)
    print('Message:')
    print(message)

@challenge(15)
def c15():
    EXAMPLES = [
        (b'ICE ICE BABY\x04\x04\x04\x04', True),
        (b'ICE ICE BABY\x05\x05\x05\x05', False),
        (b'ICE ICE BABY\x01\x02\x03\x04', False),
    ]
    result = True
    for buf, expected_result in EXAMPLES:
        result = result and expect(crypto.pkcs7_is_padded(buf), expected_result)
    if result:
        print('All padding tests passed.')

if __name__ == '__main__':
    to_run = sorted(challenges.keys())
    if len(sys.argv) > 1:
        try:
            n = int(sys.argv[1])
        except ValueError:
            print('Usage: ./challenges.py [n] (where n is an integer)')
            sys.exit(1)
        if not n in challenges:
            print('No such challenge: %d' % n)
            sys.exit(1)
        to_run = [n]
    for n in to_run:
        challenges[n]()
