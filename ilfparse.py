#!/usr/bin/env python3

'''
IP Log Filter

filter file defines a filter using 3 types of statements:
- include statements
- group statements
- rule statements

Nested includes are allowed and infinite recursion is caught as a fatal error.
Network, service group statements may include other group names, but you can't
mix the different types of groups.

-- Example filter definition
# includes
# --------
include standard-netgroups.ipf            # used frequently, eg rfc1918 netgroup
include standard-services.ipf             # ditto, eg. web, dns, ad-trust

# net groups
# ----------
partner 100.100.100/24 101.101.101/24     # list of shorthands allowed
partner NET_102.102.102/24                # NET_pfx becomes just the pfx
partner HOST_103.103.103.103              # HOST_ipaddr becomes just the ipaddr
partner HOST_104.104.104.104/32           # /32 is optional
partner 105.105.105.105                   # a regular addr
partner 106.106.106.106/32                # /32 is optional

webservers 10.10.10/24 10.10.11/25        # web servers segments
dns        10.10.10/27                    # dns segment

# services groups
# ---------------
web 80/tcp 8080/tcp 443/tcp 3128/tcp      # our webservices
dns 53/tcp                                # each line defines a group
dns 53/udp                                #  or adds to an existing group
rpc-static 5200-5300/tcp                  # port-range start-stop/proto

#rules

include header-rules                      # these are not to be overridden

~ (webtraffic) rfc1918, partner > webservers @ web -> permit; tag(a-ok), json(asf)

~ (partner-rules) partner > dns  @ dns : permit, tag ok
+ @ dns2 # add to srv group
+ rfc1918                                     # add to src group
+ > dns2                             # add to dst group
+ rfc1918 > dns2                             # two above as 1 statement

~ partner <> dns @ web: deny tag(!-ok)      # deny
~ 10/8    <> 11/8    @ dns, web drop tag silently ignore [(color,grey)]
~ any      > partner @ any drop tag drop-partner json [(color,purple)]

~ ( drop-rule ) any       <> any drop tag drop-rule json [(color,red)]

[ trailer ]

include trailer-rules warn                   # include these, warn of conflicts

# testing proposed changes
include proposed-changes nowarn              # possibly modify existing rules

--- end

A filter is a series of statements and is represented as a list of tuples

filter : filter statement
       | statement
       | error

statement : include NEWLINE
          | definition NEWLINE
          | rule NEWLINE

include : INCLUDE PARENSTR

definition : STR group

group : group COMMA item
        | item

item : IP
     | PORTSTR
     | STR

rule : TILDE tag group DIR group AT group COLON action json
     | PLUS DIR group
     | PLUS AT group

tag : PARENSTR
    | empty

action : PERMIT
       | DENY
       | DROP
       | DISCARD

json : BRACKSTR
     | empty
'''

import os
import re
import ply.lex as lex
import ply.yacc as yacc

#-- LEXER
# turn input stream into series of tokens (type, value)
keywords = (
    'INCLUDE', 'PERMIT', 'DENY', 'DROP', 'DISCARD'
)

tokens = keywords + (
    'IP', 'PORTSTR', 'STR', 'NEWLINE', 'PARENSTR', 'COMMA', 'DIR', 'AT',
    'TILDE', 'PLUS', 'COLON', 'BRACKSTR'
)

# - the order of token definitions (regexp's and funcs) is important
# 
t_ignore = ' \t'   # same as r' 0x0c'
t_PLUS = r'\+'
t_TILDE = r'~'
t_COMMA = r'\,'
t_AT = r'\@'
t_COLON = r':'

def t_COMMENT(t):
    r'\#.*'
    pass  # discards token

def t_NEWLINE(t):
    r'\n+'
    t.lexer.lineno += len(t.value)
    return t

def t_IP(t):
    r'(?i)(HOST_|NET_)?\d+\.\d+\.\d+\.\d+(/\d+)?'
    t.type = 'IP'
    t.value = re.sub(r'(?i)HOST_|NET_', '', t.value)
    t.value = (t.type, t.value)
    return t

def t_PORTSTR(t):
    r'\d+(-\d+)?/[a-zA-Z]+'
    t.type = 'PORTSTR'
    t.value = t.value.lower()
    t.value = (t.type, t.value)
    return t

def t_PARENSTR(t):
    r'\(.*?\)'
    t.value = t.value[1:-1].strip()
    t.type = 'PARENSTR'
    return t

def t_BRACKSTR(t):
    r'{.*?}'
    t.type = 'BRACKSTR'
    return t  # keep brackets, interpreted as a json string

# ~><@:,+}{
def t_STR(t):
    r'\".*?\"|[^~><@:,+)(}{\s]+'
    value = t.value.upper()
    if t.value[0] == '"' and t.value[-1] == '"':
        t.value = t.value[1:-1].strip()
    t.type = value if value in keywords else 'STR'
    if t.type in keywords:
        t.type = value
    else:
        t.type = 'STR'
        t.value = (t.type, t.value)

    return t

def t_DIR(t):
    r'<|>'
    t.type = 'DIR'
    return t

def t_error(t):
    print("Illegal character %s" % t.value[0])
    t.lexer.skip(1)

#-- PARSER
# syntactic actions to turn tokens into ast
# filter = list of (linenr, statement) tuples

def p_error(p):
    if p:  # delme later
        print('offending token', p)
    if not p:
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
    '''statement : include NEWLINE
                 | definition NEWLINE
                 | rule NEWLINE'''
    p[0] = (p.parser._filename,p.lineno(2), p[1])

def p_statement_error(p):
    '''statement : error NEWLINE'''
    p[0] = (p.parser._filename, p.lineno(2), ('ERROR', 'statement failure'))

def p_statement_newline(p):
    '''statement : NEWLINE'''
    p[0] = (p.parser._filename, p.lineno(1), ('BLANK',))

def p_include(p):
    '''include : INCLUDE PARENSTR'''
    p[0] = ('INCLUDE', p[2])

def p_include_error(p):
    '''include : INCLUDE error'''
    p[0] = ('ERROR', 'include error')

def p_definition(p):
    '''definition : STR group'''
    if p[1][1].lower() == 'any':
        p[0] = ('ERROR', 'group statetement redefines ANY')
    else:
        p[0] = ('GROUP', p[1][1], p[2])

def p_definition_error(p):
    '''definition : STR error'''
    p[0] = ('ERROR', 'group statement failure for {}'.format(p[1][1]))

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
    #  0      1     2   3     4   5     6     7     8   9      10
    '''rule : TILDE tag group DIR group AT group COLON action json'''
    # rule = (type tag addrs dir addrs srvs action tag json)
    p[0] = ('RULE', p[2], p[3], p[4], p[5], p[7], p[9], p[10])

def p_ruleadd(p):
    '''rule : PLUS DIR group
            | PLUS AT group'''
    # rule+ = (type dir/at group)
    p[0] = ('RULEPLUS', p[2], p[3])

def p_ruleadd_error(p):
    '''rule : PLUS DIR error
            | PLUS AT error'''
    p[0] = ('ERROR', 'rule addition failure')

def p_tag(p):
    '''tag : PARENSTR
           | empty'''
    p[0] = p[1]

def p_action(p):
    '''action : PERMIT
              | DENY
              | DROP
              | DISCARD'''
    p[0] = ('ACTION', p[1])

def p_json(p):
    '''json : BRACKSTR
            | empty'''
    p[0] = p[1]

def p_empty(p):
    '''empty : '''

def parse(text, filename=None, expand=True):
    lexer = lex.lex()
    parser = yacc.yacc()
    parser._filename = '<text>' if filename is None else filename
    ast = parser.parse(text, lexer=lexer)
    if expand:
        ast = ast_expand(ast)
    return ast

def parsefile(filename, expand=True):
    'parse a file on disk'
    realfname = os.path.realpath(filename)
    if not os.path.isfile(realfname):
        print('fatal: {!r} doesnt look like a file'.format(filename))
        raise SystemExit(1)
    try:
        with open(realfname, 'r') as fp:
            text = fp.read()
    except (IOError, OSError) as e:
        print('fatal: error', repr(e))
        raise SystemExit(1)
    return parse(text=text, filename=filename, expand=expand)

# AST helpers
# AST is [(fname, linenr, ('STMT_TYPE', ..)), ..], including ('ERROR', errmsg)
# - expanding an included file, replaces that statement
def ast_includes(ast):
    'return list of includes'
    rv = []
    for idx, (fname, linenr, stmt) in enumerate(ast):
        if stmt[0] == 'INCLUDE':
            rv.append((idx, linenr, stmt[0], stmt[1]))
    return rv

def ast_expand(ast):
    'expand include-statements in-place'
    # replace include(file) with its ast, in-place and continue expanding
    # in case of error, replace include-statement with (ERROR, msg)-statement
    seen = set([])
    idx = -1

    while idx+1 < len(ast):
        idx += 1
        srcfname, linenr, stmt = ast[idx]
        if stmt[0] != 'INCLUDE':
            continue

        fname = stmt[1]
        realfname = os.path.realpath(fname)
        if realfname in seen:
            ast[idx] = (srcfname, linenr,
                        ('ERROR', '{} included more than once'.format(fname)))
            continue

        seen.add(realfname)
        if not os.path.isfile(realfname):
            ast[idx] = (srcfname, linenr,
                        ('ERROR', '{} include file not found'.format(fname)))
            continue

        try:
            with open(realfname, 'r') as fp:
                ilf = fp.read()
        except (IOError, OSError):
            ast[idx] = (srcfname, linenr,
                        ('ERROR', '{} include file not readable'.format(fname)))
            continue

        try:
            ilf_ast = parse(ilf, fname, expand=False)  # expansion is done here
        except Exception as e:
            ast[idx] = (srcfname, linenr,
                        ('ERROR', '{} parse err: {}'.format(fname, repr(e))))
            continue

        ast[idx:idx+1] = ilf_ast  # replace include(file) with its stmts

    return ast


def ast_groups(ast):
    'return dict of all groups'
    rv = {}
    for fname, linenr, stmt in ast:
        if stmt[0] == 'GROUP':
            if stmt[1] in rv:
                for item in stmt[2]:
                    rv[stmt[1]].add(item)
            else:
                rv[stmt[1]] = set(stmt[2])
    return rv

def ast_group(ast, group, _seen=set([])):
    'expand group to its members'
    # _seen={} as default is initialized only once (func def time)
    _seen.add(group)
    coll = set([])
    lowgroup = group.lower()
    for fname, linenr, stmt in ast:
        if stmt[0] != 'GROUP':
            continue
        name, items = stmt[1], stmt[2]
        if name.lower() != lowgroup:
            continue

        for item in items:
            if item[0] == 'STR':
                gname = item[1]
                if gname in _seen:
                    print('warn: circular ref for {!r} via {!r}'.format(gname, group))
                    continue
                elif gname.lower() == 'any':
                    coll.add(('ANY', '0.0.0.0/0'))
                else:
                    additions = ast_group(ast, gname)
                    if len(additions) == 0:
                        print('warn: group {!r} appears empty!'.format(gname))
                    for addition in additions:
                        coll.add(addition)
            else:
                coll.add(item) # either IP or PORTSTR

    return list(coll)

def ast_group_org(ast, group, _seen=None):
    'expand group to its members'
    # _seen={} as default is initialized only once (func def time)
    _seen = set([]) if _seen is None else _seen
    _seen.add(group)
    coll = set([])
    lowgroup = group.lower()
    for fname, linenr, stmt in ast:
        if stmt[0] != 'GROUP':
            continue
        name, items = stmt[1], stmt[2]
        if name.lower() != lowgroup:
            continue

        for item in items:
            if item[0] == 'STR':
                gname = item[1]
                if gname in _seen:
                    print('warn: circular ref for {!r} via {!r}'.format(gname, group))
                    continue
                elif gname.lower() == 'any':
                    coll.add(('ANY', '0.0.0.0/0'))
                else:
                    additions = ast_group(ast, gname, _seen)
                    if len(additions) == 0:
                        print('warn: group {!r} appears empty!'.format(gname))
                    for addition in additions:
                        coll.add(addition)
            else:
                coll.add(item) # either IP or PORTSTR

    return list(coll)

# SEMANTICS
# check validity of statements in the AST & check semantics
# TODO:
# - any is reserved group name, refers to 0/0
# - allow shorthand notation for IP
# - 
#


if __name__ == '__main__':

    ast = parsefile('my.ilf')
    for stmt in ast:
        print(stmt)

    print()
    print('groups', ast_groups(ast).keys())
    print()

    for k,v in ast_groups(ast).items():
        print(k, v, '->', ast_group(ast, k))
        print()


