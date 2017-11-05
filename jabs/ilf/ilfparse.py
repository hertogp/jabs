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
    r'(?i)(HOST_|NET_)?\d+(\.\d+(\.\d+(\.\d+)?)?)?(/\d+)?'
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
    r'<>|<|>'
    t.type = 'DIR'
    return t

def t_error(t):
    print("Illegal character %s" % t.value[0])
    t.lexer.skip(1)

#-- PARSER
# syntactic actions to turn tokens into ast
# A filter program is a list of statements.
# - a statement is a tuple (filename, linenr, column, stmt-tuple)
# Productions that yield a top-level statement need to adhere to that format
# - we terminate statements with NEWLINE, used to determine lineno of statement
# - we don't do that in the 'statement' production, because we want to use the
#   NEWLINE token as anchor when defining error-productions ... that way, no
#   SEMI's are needed to terminate a statement.

def p_error(t):
    if not t:
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
    p[0] = p[1] # (p.parser._filename,p.lineno(2), p[1])

def p_statement_newline(p):
    '''statement : NEWLINE'''
    p[0] = ast_statement(p, ('BLANK',))

def p_include(p):
    '''include-stmt : INCLUDE PARENSTR NEWLINE'''
    p[0] = ast_statement(p, ('INCLUDE', p[2]))

def p_include_error(p):
    '''include-stmt : INCLUDE error NEWLINE'''
    p[0] = ast_statement(p, ('ERROR', 'INCLUDE parse error'))

def p_definition(p):
    '''definition-stmt : STR group NEWLINE'''
    if p[1][1].lower() == 'any':
        p[0] = ast_statement(p, ('ERROR', 'GROUP redefines ANY'))
    else:
        p[0] = ast_statement(p, ('GROUP', p[1][1], p[2]))

def p_definition_error(p):
    '''definition-stmt : STR error NEWLINE'''
    p[0] = ast_statement(p,
                         ('ERROR', 'GROUP {!r} parse error'.format(p[1][1])))

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
    '''rule-stmt : TILDE tag group DIR group AT group COLON action json NEWLINE'''
    # rule = (type tag addrs dir addrs srvs action tag json)
    p[0] = ast_statement(p,
                         ('RULE', p[2], p[3], p[4], p[5], p[7], p[9], p[10]))

def p_rule_json_error(p):
    '''rule-stmt : TILDE tag group DIR group AT group COLON action error NEWLINE'''
    print('json error', [type(x) for x in p])
    p[0] = ast_statement(p, ('ERROR', 'JSON parse error'))

def p_rule_action_error(p):
    '''rule-stmt : TILDE tag group DIR group AT group COLON error NEWLINE'''
    print('action error', [x for x in p])
    p[0] = ast_statement(p, ('ERROR', 'ACTION parse error'))

def p_rule_service_error(p):
    '''rule-stmt : TILDE tag group DIR group AT error NEWLINE'''
    print('action error', [x for x in p])
    p[0] = ast_statement(p, ('ERROR', 'SERVICE parse error'))

def p_rule_dest_error(p):
    '''rule-stmt : TILDE tag group DIR error NEWLINE'''
    # rule = (type tag addrs dir addrs srvs action tag json)
    print('action error', [x for x in p])
    p[0] = ast_statement(p, ('ERROR', 'DESTINATION parse error'))

def p_rule_src_error(p):
    '''rule-stmt : TILDE tag error NEWLINE'''
    # rule = (type tag addrs dir addrs srvs action tag json)
    print('action error', [x for x in p])
    p[0] = ast_statement(p, ('ERROR', 'SOURCE parse error'))

def p_rule_tag_error(p):
    '''rule-stmt : TILDE error NEWLINE'''
    # rule = (type tag addrs dir addrs srvs action tag json)
    print('action error', [x for x in p])
    p[0] = ast_item(p, ('ERROR', 'TAG parse error'))

def p_ruleadd(p):
    '''rule-stmt : PLUS DIR group NEWLINE
                 | PLUS AT group NEWLINE'''
    # rule+ = (type dir/at group)
    p[0] = ast_statement(p, ('RULEPLUS', p[2], p[3]))

def p_ruleadd_error(p):
    '''rule-stmt : PLUS DIR error NEWLINE
                 | PLUS AT error NEWLINE'''
    err_elm = {'@': 'SERVICE',
               '>': 'DESTINATION',
               '<': 'SOURCE',
               '<>': 'SRC/DST'
               }

    p[0] = ast_statement(p, ('ERROR',
                             'RULEPLUS {} error'.format(err_elm.get(p[2],''))))

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
    lexer.lastnewlinepos = 0
    parser = yacc.yacc()
    parser._filename = filename if filename else '<text>'
    ast = parser.parse(text, lexer=lexer)
    if expand:
        ast = ast_expand(ast)
    return ast

def parsefile(filename, expand=True):
    'parse a file on disk'
    realfname = os.path.realpath(os.path.normpath(filename))
    if not os.path.isfile(realfname):
        print('fatal: {!r} doesnt look like a file'.format(filename))
        raise SystemExit(1)
    try:
        with open(realfname, 'r') as fp:
            text = fp.read()
    except (IOError, OSError) as e:
        print('fatal: error', repr(e))
        raise SystemExit(1)
    return parse(text=text, filename=realfname, expand=expand)

# -- AST
# A filter's AST is a list of 2 element tuples: [(position, statement), ...]
# - position = tuple (filename, linenr, colnr)
# - statement = tuple ('STMT_TYPE', <specific fields> ..)
# - when expanding, include statements are replaced with their expansion text

def ast_statement(p, stmt):
    'a statement is (pos, stmt)-tuple'
    # automatically sets column to start of error token (if any), 1 otherwise
    linenr = p.lineno(1)
    err_tok = next((t for t in p if isinstance(t, lex.LexToken)), None)
    column = err_tok.lexpos - p.lexpos(1) if err_tok else 1
    return ((p.parser._filename, linenr, column), stmt)

def ast_includes(ast):
    'return list of includes'
    rv = []
    for idx, (fname, linenr, stmt) in enumerate(ast):
        if stmt[0] == 'INCLUDE':
            rv.append((idx, linenr, stmt[0], stmt[1]))
    return rv

def ast_expand(ast):
    'expand include-statements in-place'
    # - Expand, in-place, any include(file) statements & continue expanding
    # - In case of an error, include-statement := (ERROR, msg)-statement
    # - An included file's path is relative to the path of the including file.
    seen = {}
    idx = -1

    while idx+1 < len(ast):
        idx += 1
        (fname, linenr, col), stmt = ast[idx]
        if stmt[0] != 'INCLUDE':
            continue

        absname = os.path.realpath(os.path.normpath(
            os.path.join(os.path.dirname(fname), stmt[1])))
        if absname in seen:
            ast[idx] = ((fname, linenr, 1),
                        ('ERROR', '{} already included by: {}'.format(
                            absname, seen[absname])))
            continue

        seen[absname] = '{}:{}'.format(fname, linenr)  # record the inclusion
        if not os.path.isfile(absname):
            ast[idx] = ((fname, linenr, 1),
                        ('ERROR', '{} include file not found'.format(absname)))
            continue

        try:
            with open(absname, 'r') as fp:
                include_data = fp.read()
        except (IOError, OSError):
            ast[idx] = ((fname, linenr, 1),
                        ('ERROR', '{} include file unreadable'.format(absname)))
            continue

        try:
            include_ast = parse(include_data, absname, expand=False)  # expansion done here
        except Exception as e:
            ast[idx] = ((fname, linenr, 1),
                        ('ERROR', '{} parse err: {}'.format(absname, repr(e))))
            continue

        ast[idx:idx+1] = include_ast  # replace include(file) with its stmts

    return ast

def ast_groups(ast):
    'return dict of all groups'
    rv = {}  # {name} -> set([elements])
    for (fname, linenr, col), stmt in ast:
        if stmt[0] == 'GROUP':
            if stmt[1] in rv:
                for item in stmt[2]:
                    rv[stmt[1]].add(item)
            else:
                rv[stmt[1]] = set(stmt[2])
    return rv

def ast_group(ast, group, _seen=None):
    'expand group to its members'
    # cannot use _seen=set([]) in func signature -> is initialized only once
    # (GROUP, group_name, [items, ..])
    _seen = set([]) if _seen is None else _seen
    _seen.add(group)
    coll = set([])
    target_group = group.lower()
    for (fname, linenr, col), stmt in ast:
        if stmt[0] != 'GROUP':
            continue
        stmt_type, name, items = stmt
        if name.lower() != target_group:
            continue

        for item in items:
            if item[0] in ['IP', 'PORTSTR']:
                coll.add(item)

            elif item[0] == 'STR':
                gname = item[1]
                if gname in _seen:
                    print('warn: circular ref for {!r} via {!r}'.format(gname,
                                                                        group))
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
                raise ValueError('illegal item {} in group {}'.format(item,
                                                                      group))

    return list(coll)

# SEMANTICS
# check validity of statements in the AST & check semantics
# TODO:
# - any is reserved group name, refers to 0/0
# - warn when a group is turned into an alias for ANY
# - error when a group is referenced but not defined ...
# - validate networks, services
# - NB: GROUP may mix IP's, PORTSTR's; relevant parts determined by context
#   eg dns NET_10.10.10.0/24, 53/udp, 53/tcp; and a rule using it:
#      ~ (dns-services) any > dns @ dns : permit
#        - service -> yields 53/udp, 53/tcp
#        - network -> yields NET_10.10.10.0/25
# - RULEPLUS without a preciding, valid RULE stmt
# - no ERROR's allowed inbetween RULE and RULEPLUS

