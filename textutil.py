# Text examination and manipulation utilities.

from collections import Counter
from util import partition
import crypto

# Source:
# http://www.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html
ENGLISH_FREQUENCIES = {
    'E': .1202,
    'T': .0910,
    'A': .0812,
    'O': .0768,
    'I': .0731,
    'N': .0695,
    'S': .0628,
    'R': .0602,
    'H': .0592,
    'D': .0432,
    'L': .0398,
    'U': .0288,
    'C': .0271,
    'M': .0261,
    'F': .0230,
    'Y': .0211,
    'W': .0209,
    'G': .0203,
    'P': .0182,
    'B': .0149,
    'V': .0111,
    'K': .0069,
    'X': .0017,
    'Q': .0011,
    'J': .0010,
    'Z': .0007,
}

# TODO: This is hacky and is not even close to perfect. I look forward to
# improving this to ngrams or even markov chains, using some seed text.
def english_probability(text):
    """
    Returns a float representing the likelihood that the given text is a
    plaintext written in English. Range: (0.0 - 1.0), higher is better.
    """
    # Ignore whitespace (revisit this later).
    text = text.upper()
    letters, other = partition(lambda c: c in ENGLISH_FREQUENCIES, text)
    if not letters: return 0.0
    # Expect roughly 15% of text to be spaces.
    spaces, other = partition(lambda c: c.isspace(), other)
    space_error = abs(float(len(spaces))/len(text) - 0.15)
    # As a rough approximation, expect 2% of characters to be punctuation.
    punc_error = abs(float(len(other))/len(text) - 0.02)
    counts = Counter(text)
    letter_error = 0.0
    for c, target_freq in ENGLISH_FREQUENCIES.items():
        letter_error += (target_freq *
                        abs(float(counts.get(c, 0))/len(letters) - target_freq))
    return max(1.0 - (punc_error + letter_error + space_error), 0.0)

def hamming_weight(value):
    "Compute the Hamming weight of an integer (number of set bits)."
    # Cheesy but effective.
    return bin(value)[2:].count('1')

def hamming_distance(a, b):
    "Compute the eponymous distance function between the two given byte arrays."
    if len(a) != len(b):
        raise Exception('I thought you could only compare equal lengths.')
    return sum([hamming_weight(x^y) for x, y in zip(a, b)])

