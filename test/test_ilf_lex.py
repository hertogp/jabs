'''
test lexer
'''

import sys
sys.path.insert(0, '..')
sys.path.insert(0, '.')
import jabs.ilf.lex as lex


# -- IP tokens


def test_ip1():
    'IP bare address'
    lexr = lex.lexer
    lexr.input('1.1.1.1 HOST_1.1.1.1 NET_1.1.1.1')
    toks = [t for t in lexr]
    assert len(toks) == 3
    for tok in toks:
        assert tok.type == 'IP'
        assert tok.value == ('IP', '1.1.1.1')


def test_ip2():
    'IP with prefix length'
    lexr = lex.lexer
    lexr.input('1.1.1.1/8 HOST_1.1.1.1/8 NET_1.1.1.1/8')
    toks = [t for t in lexr]
    assert len(toks) == 3
    for tok in toks:
        assert tok.type == 'IP'
        assert tok.value == ('IP', '1.1.1.1/8')


def test_ip3():
    'IP shorthand'
    lexr = lex.lexer
    lexr.input('1/8 HOST_1/8 NET_1/8')
    toks = [t for t in lexr]
    assert len(toks) == 3
    for tok in toks:
        assert tok.type == 'IP'
        assert tok.value == ('IP', '1/8')


def test_ip4():
    'IP has no error checks at lexing time'
    lexr = lex.lexer
    lexr.input('1.1.1.900 HOST_1.1.1.900 NET_1.1.1.900')
    toks = [t for t in lexr]
    assert len(toks) == 3
    for tok in toks:
        assert tok.type == 'IP'
        assert tok.value == ('IP', '1.1.1.900')


def test_ip5():
    'IP case insensitive'
    lexr = lex.lexer
    lexr.input('1.1.1.1 HoSt_1.1.1.1 nEt_1.1.1.1')
    toks = [t for t in lexr]
    assert len(toks) == 3
    for tok in toks:
        assert tok.type == 'IP'
        assert tok.value == ('IP', '1.1.1.1')


# -- PORTSTR tokens


def test_portstr1():
    'PORTSTR in 2 forms'
    lexr = lex.lexer
    lexr.input('80/tcp 80-81/tcp')
    toks = [t for t in lexr]
    assert len(toks) == 2
    assert toks[0].type == 'PORTSTR'
    assert toks[0].value == ('PORTSTR', '80/tcp')
    assert toks[1].type == 'PORTSTR'
    assert toks[1].value == ('PORTSTR', '80-81/tcp')


def test_portstr2():
    'PORTSTR case insensitive'
    lexr = lex.lexer
    lexr.input('80/tCp 80-81/TCP')
    toks = [t for t in lexr]
    assert len(toks) == 2
    assert toks[0].type == 'PORTSTR'
    assert toks[0].value == ('PORTSTR', '80/tcp')
    assert toks[1].type == 'PORTSTR'
    assert toks[1].value == ('PORTSTR', '80-81/tcp')


# -- PARENSTR


def test_parenstr1():
    'PARENSTR matches anything inside parens'
    text = '(match:ALL:"inside"@parens!/"see?)'
    lexr = lex.lexer
    lexr.input(text)
    toks = [t for t in lexr]
    assert len(toks) == 1
    assert toks[0].type == 'PARENSTR'
    assert toks[0].value == text[1:-1]


# -- JSON

def test_json1():
    'JSON matches all after a equal sign'
    text = '= this is not json'
    lexr = lex.lexer
    lexr.input(text)
    toks = [t for t in lexr]
    assert len(toks) == 1
    assert toks[0].type == 'JSON'
    assert toks[0].value == text[1:].strip()

def test_json2():
    'match json object'
    text = '= {"string": "str", "number": 29, "object": {"1": "1", "2":2, "3":[1,2,3]}, "array": [1,2,3]}'
    lexr = lex.lexer
    lexr.input(text)
    toks = [t for t in lexr]
    assert len(toks) == 1
    assert toks[0].type == 'JSON'
    assert toks[0].value == text[1:].strip()

def test_json3():
    'JSON matches all after a equal sign, including any comments'
    text = '= this is not # json'
    lexr = lex.lexer
    lexr.input(text)
    toks = [t for t in lexr]
    assert len(toks) == 1
    assert toks[0].type == 'JSON'
    assert toks[0].value == 'this is not # json'

# -- STRing


def test_str1():
    'STR matches anything inside ".."'
    text = '"these are include @:(){}<>~ in string"'
    lexr = lex.lexer
    lexr.input(text)
    toks = [t for t in lexr]
    assert len(toks) == 1
    assert toks[0].type == 'STR'
    assert toks[0].value == ('STR', text[1:-1])


def test_str2():
    'STR matches bare words'
    text = 'word word'
    lexr = lex.lexer
    lexr.input(text)
    toks = [t for t in lexr]
    assert len(toks) == 2
    for tok in toks:
        assert tok.type == 'STR'
        assert tok.value == ('STR', 'word')


def test_str3():
    'STR separators'
    seps = '~<>@:,+'
    lexr = lex.lexer
    for sep in seps:
        text = "word{}word".format(sep)
        lexr.input(text)
        toks = [t.value for t in lexr]
        assert len(toks) == 3
        assert toks == [('STR', 'word'), sep, ('STR', 'word')]


# -- DIRECTION


def test_dir():
    'DIR matches <, > and <>'
    dirs = ['<', '>', '<>']
    lexr = lex.lexer
    for angle in dirs:
        lexr.input(angle)
        toks = [t for t in lexr]
        assert len(toks) == 1
        assert toks[0].type == 'DIR'
        assert toks[0].value == angle


def test_dir2():
    'DIR matches <> as 1 DIR token and >< as 2 DIR tokens'
    text = '<> ><'
    lexr = lex.lexer
    lexr.input(text)
    toks = [(t.type, t.value) for t in lexr]
    assert len(toks) == 3
    assert toks == [('DIR', '<>'), ('DIR', '>'), ('DIR', '<')]
