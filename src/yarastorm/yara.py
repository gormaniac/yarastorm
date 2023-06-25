"""Fake yara module to continue testing"""


class Error(Exception):
    pass


class SyntaxError(Exception):
    pass


class Rules:
    def match(*args, **kwargs):
        return True

def compile(*args, **kwargs):
    return Rules()
