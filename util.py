# Some uncategorized utilities used throughout.

import crypto
import functools

def compose(*functions):
    "Compose n functions and return the resulting function."
    return functools.reduce(lambda f, g: lambda x: f(g(x)), functions)

def partition(pred, iterable):
    "Return a pair of lists; elements that satisfy pred, and those that don't."
    # No cuteness because I only want to inspect each element once.
    sat = []
    unsat = []
    for e in iterable:
        if pred(e):
            sat.append(e)
        else:
            unsat.append(e)
    return sat, unsat

PROFILE_FIELDS = ['email', 'uid', 'role']

def parse_key_values(line):
    """
    As requested in #13, parses strings like 'foo=bar&baz=qux&zap=zazzle'
    into a dictionary representing the key-value pairs. Does not do any
    sanitization or unhappy path handling. :)
    """
    print('parsing: %s' % line)
    result = {}
    for pair in line.split('&'):
        kv = pair.split('=')
        if len(kv) == 2:
            key, value = kv
            result[key] = value
    return result

def encode_profile(d):
    """
    Inverse of the previous method.
    """
    # Note: The hack really counts on preserving the order here.
    return '&'.join(['%s=%s' % (k, d[k]) for k in PROFILE_FIELDS])

# TODO: These aren't utilities so much as examples. Find a new home?
PROFILE_KEY = b'dontstopbelievin'

def profile_for(email):
    assert '&' not in email and '=' not in email
    return {
        'email': email,
        'uid': 10,
        'role': 'user',
    }

def encrypted_profile_for(email):
    return crypto.encrypt_aes_ecb(
             crypto.pkcs7_pad(
               crypto.str_to_bytes(encode_profile(profile_for(email))),
               len(PROFILE_KEY)),
             PROFILE_KEY)

def decrypt_profile(crypt):
    plainbytes = crypto.decrypt_aes_ecb(crypt, PROFILE_KEY)
    return parse_key_values(crypto.pkcs7_unpad(plainbytes).decode())
