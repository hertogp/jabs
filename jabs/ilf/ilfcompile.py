# Ip Log Filter - compiler

import os

from .ilfparse import parse
from .ilfilter import Ip4Filter
from .helpers import Ival

#-- GLOBALS
NETS = {'any': set([Ival.from_pfx('any')])}      # name -> set(IP's)
SRVS = {'any': set([Ival.from_portstr('any')])}  # name -> set(PORTSTR's)

#-- AST = [(pos, stmt), ..]
def ast_iter(ast, types=[]):
    'iterate across statements of requested types'
    for pos, stmt in ast:
        if stmt[0] in types:
            yield (pos, stmt)
def ast_enum(ast, types=[]):
    'enumerate across statements of requested types'
    for idx, (pos, stmt) in enumerate(ast):
        if stmt[0] in types:
            yield (idx, pos, stmt)

def ast_error(pos, err_type, stmt_type, msg):
    'small helper to easily create ERROR/WARNING stmts'
    return (pos, (err_type, stmt_type, msg))

def ast_add(ast, pos, err_type, stmt_type, msg):
    'append an ERR_TYPE message to ast'
    ast.append((pos, (err_type, stmt_type, msg)))

def ast_includes(ast):
    'expand include-statements in-place'
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
                        ('ERROR', 'INCLUDE', '{}: already includes {}'.format(
                            seen[absname], absname)))
            continue

        seen[absname] = '{}:{}:{}'.format(fname, linenr, col)  # record the inclusion

        try:
            with open(absname, 'r') as fp:
                include_ast = parse(fp)
        except (IOError, OSError):
            ast[idx] = ((fname, linenr, 1),
                        ('ERROR', 'INCLUDE', 'cannot find/read {}'.format(absname)))
            continue

        ast[idx:idx+1] = include_ast  # replace include(file) with its stmts

    return ast
def _ivalify(lst):
    'return same list with IP, PORTSTR - values turned into Ivals'
    rv = []
    errs = []
    for elm in lst:
        try:
            if elm[0] == 'IP':
                rv.append((elm[0], Ival.from_pfx(elm[1])))
            elif elm[0] == 'PORTSTR':
                rv.append((elm[0], Ival.from_portstr(elm[1])))
            else:
                rv.append(elm)
        except ValueError:
            errs.append(elm[1])

    if len(errs):
        s = '' if len(errs) == 1 else 's'
        msg = 'Invalid item{}: {}'.format(s, ', '.join(errs))
        raise ValueError(msg)
    return rv

def ast_ivalify(ast):
    'replace IP and PORTSTR values with their Ival-values'
    # in case of errors, replace stmt with ERROR stmt
    for idx, pos, stmt in ast_enum(ast, ['GROUP', 'RULE', 'RULEPLUS']):
        try:
            if stmt[0] == 'GROUP':
                ast[idx] = (pos, (stmt[0], stmt[1], _ivalify(stmt[2])))
            elif stmt[0] == 'RULEPLUS':
                ast[idx] = (pos, (stmt[0], stmt[1], _ivalify(stmt[2])))
            elif stmt[0] == 'RULE':
                ast[idx] = (pos, (stmt[0], stmt[1], _ivalify(stmt[2]), stmt[3],
                                  _ivalify(stmt[4]), _ivalify(stmt[5]),
                                  *stmt[6:]))
            else:
                raise ValueError('{} invalid stmt for ast_ivalify'.format(
                    stmt[0]))
        except ValueError as e:
            print(dir(e))
            ast[idx] = ast_error(pos, 'ERROR', stmt[0], '{}'.format((e)))

    return ast

def ast_groups(ast):
    'return set of unique group definitions in ast'
    names = [stmt[1] for pos, stmt in ast_iter(ast, ['GROUP'])]
    return set(names)

def ast_group(ast, group, _seen=None):
    'return a list of unique members of a group'
    # adds warnings to ast, this is after ast_ivalify
    _seen = set([]) if _seen is None else _seen
    _seen.add(group)
    coll = set([])
    target_group = group.lower()

    for idx, pos, stmt in ast_enum(ast, ['GROUP']):
        stmt_type, name, items = stmt
        if name.lower() != target_group:
            continue

        for item in items:
            if item[0] == 'IP':
                if item[1].is_any():
                    ast_add(ast, pos, 'WARNING', 'GROUP',
                            '{!r} is an alias for ANY'.format(group))
                coll.add(item)
            elif item[0] == 'PORTSTR':
                if item[1].is_any():
                    ast_add(ast, pos, 'WARNING', 'GROUP',
                            '{!r} is an alias for ANY'.format(group))
                coll.add(item)
            elif item[0] == 'STR':
                gname = item[1]
                if gname in _seen:
                    ast_add(ast, pos, 'WARNING', 'GROUP',
                             'circular ref for {!r} via {!r}'.format(gname,
                                                                     group))
                    continue
                elif gname.lower() == 'any':
                    coll.add(('ANY', '0.0.0.0/0'))
                    ast_add(ast, pos, 'WARNING', 'GROUP',
                             '{!r} is an alias for ANY'.format(group))
                else:
                    # empty groups are caught by chk_ast_norefs
                    for addition in ast_group(ast, gname, _seen):
                        coll.add(addition)
            else:
                raise ValueError('illegal item {} in group {}'.format(item,
                                                                      group))

    return list(coll)

def ast_build_symbols(ast):
    'fill NETS and SRVS symbol tables'
    for grp in ast_groups(ast):
        for typ, value in ast_group(ast, grp):
            if typ == 'IP':
                NETS.setdefault(grp, set()).add(value)
            elif typ == 'PORTSTR':
                SRVS.setdefault(grp, set()).add(value)
            elif typ == 'ANY':
                NETS.setdefault(grp, set()).add(Ival.from_pfx('any')) # any())
                SRVS.setdefault(grp, set()).add(Ival.from_portstr('any'))
            else:
                raise ValueError('Illegal item {} in group {}'.format(typ,
                                                                      grp))
    return ast

def ast_rules(ast):
    'expand elements of the defined rules'
    for pos, stmt in ast_iter(ast, ['RULE']):
        print('expand', stmt)
    for pos, stmt in ast_iter(ast, ['RULEPLUS']):
        print('expand', stmt)

    return ast

def ast_troubles(ast):
    'return list of printable errors and warnings, if any'
    rv = []
    for pos, stmt in ast_iter(ast, ['ERROR', 'WARNING']):
        position = '{}:{}:{}:'.format(*pos)
        msg = '{}:{}: {}'.format(*stmt)
        rv.append((position, msg))
    return rv

def ast_score(ast):
    'return (num_errors, num_warnings) in ast'
    errs = len(list(ast_iter(ast, ['ERROR'])))
    warn = len(list(ast_iter(ast, ['WARNING'])))
    return (errs, warn)

#-- SEMANTICS
# check validity of statements in the AST & check semantics
# TODO:
# - validate networks, services

def ast_semantics(ast):
    'run defined checks, chk_xyz, on ast and return ast'
    # all chk_xyz(ast) -> must return an (un)modified, valid ast
    for check in [x for x in globals() if x.startswith('chk_')]:
        semantics = globals()[check]
        # XXX: log on informational level to console
        print('semantics:', semantics.__doc__)
        ast = semantics(ast)
    return ast

def chk_ast_dangling(ast):
    'check for dangling RULEPLUS statements'
    idx = -1
    max_ = len(ast) - 1
    parent = None  # last parent stmt with scope for ruleplus
    while idx < max_:
        idx += 1
        pos, stmt = ast[idx]
        stype = stmt[0]
        if stype == 'BLANK':
            continue
        if stype == 'RULEPLUS' and parent not in ['RULE', 'RULEPLUS']:
                ast[idx] = (pos, ('ERROR', 'RULEPLUS',
                                  'not in scope of a RULE'))

        # only allow intermediate ERRORs for RULE[PLUS] as a parent

        parent = stmt[1] if stype in ['ERROR', 'WARNING'] else stype

    return ast

def chk_ast_norefs(ast):
    'ensure references to networks, services are valid'
    no_net = lambda x: x[1] not in NETS
    no_srv = lambda x: x[1] not in SRVS
    no_ref = lambda x: x[1] not in NETS and x[1] not in SRVS
    for idx, pos, stmt in ast_enum(ast, ['GROUP', 'RULE', 'RULEPLUS']):
        unrefs = []
        if stmt[0] in ['GROUP']:
            unrefs = [x[1] for x in stmt[2] if x[0] == 'STR' and no_ref(x)]
        elif stmt[0] == 'RULEPLUS':
            if stmt[1] == '@':
                unrefs = [x[1] for x in stmt[2] if x[0] == 'STR' and no_srv(x)]
            else:
                unrefs = [x[1] for x in stmt[2] if x[0] == 'STR' and no_net(x)]
        elif stmt[0] == 'RULE':
            unrefs = [x[1] for x in stmt[2] if x[0] == 'STR' and no_net(x)]
            unrefs = [x[1] for x in stmt[4] if x[0] == 'STR' and no_net(x)]
            unrefs = [x[1] for x in stmt[5] if x[0] == 'STR' and no_srv(x)]
        else:
            raise ValueError('ref-check: unknown stmt type {}'.format(stmt[0]))

        if len(unrefs):
            msg = 'undefined group{} {}'.format('s' if len(unrefs)>1 else '',
                                                 ', '.join(unrefs))
            ast[idx] = (pos, ('ERROR', stmt[0], msg))

    return ast


#-- Compile
# - return an IP4Filter by compiling a script
def print_ast(ast):
    for pos, stmt in ast:
        print(pos, stmt)

def compile(filename):
    'compile file into IP4Filter object'
    with open(filename, 'rt') as fh:
        ast = parse(fh)            # parse master file
    ast = ast_includes(ast)        # parse included files
    ast = ast_ivalify(ast)         # turn IP, PORTSTR strings into Ival's
    ast = ast_build_symbols(ast)   # build NETS and SRVS tables
    ast = ast_semantics(ast)       # check validity of ast
    errors, warnings = ast_score(ast)
    print('Score: E{}, W{}'.format(errors, warnings))
    print_ast(ast)

    # XXX
    print('NETWORKS')
    for grp, lst in NETS.items():
        print('-', grp, [x.to_pfx() for x in lst])
    print()
    print('SERVICES')
    for grp, lst in SRVS.items():
        print('-', grp, [x.to_portstr() for x in lst])

    # end XXX

    trouble = ast_troubles(ast)  # get any errors/warnings
    if trouble:
        for pos, msg in trouble:
            print('{}{}'.format(pos, msg))
        print('E{}, W{}'.format(errors, warnings))
        raise SystemExit(1)

    return ast

