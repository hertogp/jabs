'''
Ip Log Filter - parser
'''

import os

import ply.yacc as yacc

from . import lex

tokens = lex.tokens

# -- AST helpers


def _stmt(p, stmt):
    'a statement is (pos, stmt)-tuple'
    # column is start of error token or 1 (if stmt is ok)
    linenr = p.lineno(1)
    err_tok = next((t for t in p if isinstance(t, lex.lex.LexToken)), None)
    column = err_tok.lexpos - p.lexpos(1) if err_tok else 1
    position = (p.parser.ilf_filename, linenr, column)
    return (position, stmt)

# -- productions


def p_error(tok):
    'global error handling'
    if not tok:
        print('Unexpected EOF reached')


def p_filter(p):
    '''filter : filter statement
              | statement'''
    if len(p) == 2 and p[1]:
        p[0] = [p[1]]
    elif len(p) == 3:
        p[0] = p[1] if p[1] else []
        p[0].append(p[2])


def p_statement(p):
    '''statement : include-stmt
                 | definition-stmt
                 | rule-stmt'''
    p[0] = p[1]


def p_statement_newline(p):
    '''statement : NEWLINE'''
    p[0] = _stmt(p, ('BLANK'))


def p_include(p):
    '''include-stmt : INCLUDE PARENSTR NEWLINE'''
    p[0] = _stmt(p, ('INCLUDE', p[2]))


def p_include_error(p):
    '''include-stmt : INCLUDE error NEWLINE'''
    p[0] = _stmt(p, ('ERROR', 'INCLUDE', 'parse error'))


def p_definition(p):
    '''definition-stmt : STR group NEWLINE'''
    if p[1][1].lower() == 'any':
        p[0] = _stmt(p, ('ERROR', 'GROUP', 'reserved name ANY'))
    else:
        p[0] = _stmt(p, ('GROUP', p[1][1], p[2]))


def p_definition_error(p):
    '''definition-stmt : STR error NEWLINE'''
    p[0] = _stmt(p, ('ERROR', 'GROUP', '{!r} parse error'.format(p[1][1])))


def p_group(p):
    '''group : group COMMA item
                 | item'''
    if len(p) > 2:
        p[0] = p[1]
        p[0].append(p[3])
    else:
        p[0] = [p[1]]


def p_item(p):
    ''' item : IP
             | PORTSTR
             | STR'''
    p[0] = p[1]


def p_rule(p):
    #  0           1     2   3     4   5     6     7     8   9      10
    'rule-stmt : TILDE tag group DIR group AT group COLON action json NEWLINE'
    # rule = [type tag addrs dir addrs srvs action tag json]
    p[0] = _stmt(p, ('RULE', p[2], p[3], p[4], p[5], p[7], p[9], p[10]))


def p_rule_json_error(p):
    'rule-stmt : TILDE tag group DIR group AT group COLON action error NEWLINE'
    p[0] = _stmt(p, ('ERROR', 'RULE', 'JSON parse error'))


def p_rule_action_error(p):
    '''rule-stmt : TILDE tag group DIR group AT group COLON error NEWLINE'''
    p[0] = _stmt(p, ('ERROR', 'RULE', 'ACTION parse error'))


def p_rule_service_error(p):
    '''rule-stmt : TILDE tag group DIR group AT error NEWLINE'''
    p[0] = _stmt(p, ('ERROR', 'RULE', 'SERVICE parse error'))


def p_rule_dest_error(p):
    '''rule-stmt : TILDE tag group DIR error NEWLINE'''
    p[0] = _stmt(p, ('ERROR', 'RULE', 'DESTINATION parse error'))


def p_rule_src_error(p):
    '''rule-stmt : TILDE tag error NEWLINE'''
    p[0] = _stmt(p, ('ERROR', 'RULE', 'SOURCE parse error'))


def p_rule_tag_error(p):
    '''rule-stmt : TILDE error NEWLINE'''
    p[0] = _stmt(p, ('ERROR', 'RULE', 'TAG parse error'))


def p_ruleadd(p):
    '''rule-stmt : PLUS DIR group NEWLINE
                 | PLUS AT group NEWLINE'''
    p[0] = _stmt(p, ('RULEPLUS', p[2], p[3]))


def p_ruleadd_error(p):
    '''rule-stmt : PLUS DIR error NEWLINE
                 | PLUS AT error NEWLINE'''
    err_elm = {'@': 'SERVICE',
               '>': 'DESTINATION',
               '<': 'SOURCE',
               '<>': 'SRC/DST'
               }

    p[0] = _stmt(p, ('ERROR', 'RULEPLUS',
                     '{} error'.format(err_elm.get(p[2], ''))))


def p_tag(p):
    '''tag : PARENSTR
           | empty'''
    p[0] = p[1]


def p_action(p):
    '''action : PERMIT
              | DENY
              | DROP
              | DISCARD'''
    p[0] = p[1]


def p_json(p):
    '''json : BRACKSTR
            | empty'''
    p[0] = p[1]


def p_empty(p):
    '''empty : '''
    pass

parser = yacc.yacc()


def parse(fhdl):
    'parse a filter definition file'
    name = fhdl.name if hasattr(fhdl, 'name') else '__string__'
    realfname = os.path.realpath(os.path.normpath(name))
    try:
        text = fhdl.read()
    except (IOError, OSError) as e:
        print('fatal: error', repr(e))
        raise SystemExit(1)

    parser.ilf_filename = realfname  # part of position in statements
    lex.lexer.lineno = 1          # reset lineno when parsing a new file
    ast = parser.parse(text)

    return ast
