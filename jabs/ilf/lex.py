# Ip Log Filter - lexer

import re
import ply.lex as lex

keywords = (

    # include statement
    'INCLUDE',

    # action terminals
    'PERMIT', 'DENY', 'DROP', 'DISCARD'
)


tokens = keywords + (
    # basic filter building blocks
    'IP', 'PORTSTR', 'STR',

    # a rule name is (rule name string)
    'PARENSTR',

    # any string after '=' is taken as a json string
    'JSON',

    # a newline terminates a statement
    'NEWLINE',

    # terminals
    'COMMA', 'DIR', 'AT', 'TILDE', 'PLUS', 'COLON'
)


# - the order of token definitions (regexp's and funcs) is important
t_ignore = ' \t'   # same as r' 0x0c'; ignore whitespace
t_COMMA = r'\,'
t_AT = r'\@'
t_TILDE = r'~'
t_PLUS = r'\+'
t_COLON = r':'


def t_COMMENT(t):
    r'\#.*'
    pass  # discards token


def t_NEWLINE(t):
    r'\n+'
    t.lexer.lineno += len(t.value)
    return t


# PORTSTR comes before IP


def t_PORTSTR(t):
    r'\d+(-\d+)?/[a-zA-Z]+'
    t.type = 'PORTSTR'
    t.value = t.value.lower()
    t.value = (t.type, t.value)
    return t

def t_IP(t):
    r'([Hh][Oo][Ss][Tt]_|[Nn][Ee][Tt]_)?\d+(\.\d+(\.\d+(\.\d+)?)?)?(/\d+)?'
    # r'(?i)(HOST_|NET_)?\d+(\.\d+(\.\d+(\.\d+)?)?)?(/\d+)?'
    t.type = 'IP'
    t.value = re.sub(r'(?i)HOST_|NET_', '', t.value)
    t.value = (t.type, t.value)
    return t


def t_PARENSTR(t):
    r'\(.*?\)'
    t.value = t.value[1:-1].strip()
    t.type = 'PARENSTR'
    return t


def t_STR(t):
    r'\".*?\"|[^~><@:,+)(}{=\s]+'
    value = t.value.upper()
    if t.value[0] == '"' and t.value[-1] == '"':
        t.value = t.value[1:-1].strip()
    t.type = value if value in keywords else 'STR'
    if t.type in keywords:
        t.type = value
    elif t.type == 'STR' and value == 'ANY':
        t.type = 'IP'
        t.value = (t.type, t.value.lower())
    elif t.type == 'STR' and value == 'ANY/ANY':
        t.type = 'PORTSTR'
        t.value = (t.type, t.value.lower())
    else:
        t.value = (t.type, t.value.lower())  # case insensitive names

    return t


def t_DIR(t):
    r'<>|<|>'
    t.type = 'DIR'
    return t


def t_JSON(t):
    r'=.*'
    # the '=' sign starts a json string which includes the rest of the line
    t.type = 'JSON'
    t.value = t.value[1:].strip()  # remove '=' leading character
    if len(t.value):
        return t
    pass  # donot return an empty json string


def t_error(t):
    t.lexer.skip(1)

# build the lexer
lexer = lex.lex()  # used by parse to reset lineno to 1
