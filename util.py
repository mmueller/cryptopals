# Some uncategorized utilities used throughout.

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

