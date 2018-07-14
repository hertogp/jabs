'''
ilf - compiler
'''

import os
import json

from jabs.ilf.parse import parse
from jabs.ilf.core import Ip4Filter, Ival


# -- GLOBALS
# (re)initialized by compile_file
GROUPS = {}  # grp-name -> set([networks,.. , services, ..])

# -- AST = [(pos, [type, id, value]), ..]


def ast_iter(ast, types=None):
    'iterate across statements of requested types'
    types = [] if types is None else types
    yield_all = len(types) == 0
    for pos, stmt in ast:
        if yield_all or stmt[0] in types:
            yield (pos, stmt)


def ast_enum(ast, types=None):
    'enumerate across statements of requested types'
    types = [] if types is None else types
    yield_all = len(types) == 0
    for idx, (pos, stmt) in enumerate(ast):
        if yield_all or stmt[0] in types:
            yield (idx, pos, stmt)


def ast_errmsg(pos, err_type, stmt_type, msg):
    'small helper to easily create ERROR/WARNING stmts'
    return (pos, [err_type, stmt_type, msg])


def ast_includes(ast):
    'expand include-statements in-place'
    seen = {}
    idx = -1
    while idx+1 < len(ast):  # while loop since ast is expanding
        idx += 1
        (fname, linenr, col), stmt = ast[idx]
        if stmt[0] != 'INCLUDE':
            continue

        absname = os.path.realpath(os.path.normpath(
            os.path.join(os.path.dirname(fname), stmt[1])))
        if absname in seen:
            ast[idx] = ast_errmsg(
                (fname, linenr, 1),
                'ERROR', stmt[0],
                '{} already included at {}'.format(absname, seen[absname]))
            continue

        seen[absname] = '{}:{}:{}'.format(fname, linenr, col)  # record include
        try:
            with open(absname, 'r') as fhdl:
                include_ast = parse(fhdl)  # possibly includes new includes(..)
        except (IOError, OSError):
            ast[idx] = ast_errmsg(
                (fname, linenr, 1),
                'ERROR', stmt[0],
                'cannot find/read {}'.format(absname))
            continue

        ast[idx:idx+1] = include_ast  # replace include(file) with its stmts

    return ast


def _ivalify(lst, *types):
    'turn a list of tokens (IP, PORTSTR, STR) into a list of Ivals'
    global GROUPS
    rv, errs = [], []  # in case of errors
    for elm in lst:
        try:
            if elm[0] == 'IP':
                rv.append(Ival.ip_pfx(elm[1]))
            elif elm[0] == 'PORTSTR':
                rv.append(Ival.port_str(elm[1]))
            elif elm[0] == 'STR':
                # rv.extend(GROUPS[elm[1]])
                rv.extend(GROUPS.get(elm[1], []))
        except (ValueError, KeyError):
            errs.append(elm[1])

    if len(errs):
        msg = 'Invalid item(s): {}'.format(', '.join(errs))
        raise ValueError(msg)
    return [i for i in rv if i.type in types]


def ast_ivalify(ast):
    'turn IP- and PORTSTR-values into Ival-s'
    for idx, pos, stmt in ast_enum(ast, ['GROUP', 'RULE', 'RULEPLUS']):
        try:
            if stmt[0] == 'GROUP':
                ivals = Ival.summary(_ivalify(stmt[2], Ival.IP, Ival.PORTSTR))
                ast[idx] = (pos, (stmt[0], stmt[1], ivals))
            elif stmt[0] == 'RULEPLUS':
                scope = Ival.PORTSTR if stmt[1] == '@' else Ival.IP
                ivals = Ival.summary(_ivalify(stmt[2]), scope)
                ast[idx] = (pos, (stmt[0], stmt[1], ivals))

            elif stmt[0] == 'RULE':
                srcs = Ival.summary(_ivalify(stmt[2], Ival.IP))
                dsts = Ival.summary(_ivalify(stmt[4], Ival.IP))
                srvs = Ival.summary(_ivalify(stmt[5], Ival.PORTSTR))
                ast[idx] = (pos, (stmt[0], stmt[1], srcs, stmt[3],
                                  dsts, srvs, *stmt[6:]))
            else:
                raise ValueError('{} invalid stmt for ast_ivalify'.format(
                    stmt[0]))
        except ValueError as e:
            ast[idx] = ast_errmsg(pos, 'ERROR', stmt[0], '{}'.format((e)))

    return ast


def ast_jsonify(ast):
    'turn a rule\'s json string into a python dict'
    # only RULE tuple's have json string (or None) as last element
    for idx, pos, stmt in ast_enum(ast, ['RULE']):
        try:
            dct = {} if stmt[-1] is None else json.loads(stmt[-1])
            ast[idx] = (pos, (*stmt[0:-1], dct))
        except (TypeError, json.decoder.JSONDecodeError) as e:
            ast[idx] = ast_errmsg(pos, 'ERROR', stmt[0],
                                  'json-error: {}'.format((e)))
        # if stmt[-1] is None:
        #     ast[idx] = (pos, (*stmt[0:-1], {})
        # try:
        #     # json string (if any) is the last element in a rule
        #     ast[idx] = (pos, (*stmt[0:-1], json.loads(stmt[-1])))
        # except (TypeError, json.decoder.JSONDecodeError) as e:
        #     ast[idx] = ast_errmsg(pos, 'ERROR', stmt[0],
        #                           'json-error: {}'.format((e)))
    return ast


def expand_refs(dct):
    'return an expanded member list from a, possibly, recursive definition'
    # dct is {name} -> set([name, ..]), which may refer to other names
    for target, mbrs in dct.items():
        heap = list(mbrs)  # mbrs name ('STR', name)
        seen, dct[target] = [target], set([])
        while heap:
            nxt = heap.pop()
            if nxt in seen:  # circular reference
                continue
            seen.append(nxt)
            if nxt in dct:
                heap.extend(list(dct[nxt]))
            dct[target].add(nxt)

    return dct


def ast_symbol_table(ast):
    'Build the symbol table for the ast'
    # need 2 passes, since forward referencing is allowed
    global GROUPS
    # (re-)initialise symbol table
    GROUPS = {'any': set([Ival.ip_pfx('any')]),
              'any/any': set([Ival.port_str('any/any')])}
    TODO = {}  # GROUP-name -> [group-names to include]

    # 1st pass, collect direct IP/PORTSTR's per groupname and
    #  defer group references till phase2
    for idx, pos, stmt in ast_enum(ast, ['GROUP']):
        _, grpname, mbrs = stmt
        refs = [t[1] for t in mbrs if t[0] == 'STR']  # only the name
        TODO.setdefault(grpname, set()).update(refs)  # defer named ref's
        grpdef = GROUPS.setdefault(grpname, set())    # always define symbol

        try:
            ivals = _ivalify([m for m in mbrs if m[0] != 'STR'],
                             Ival.IP, Ival.PORTSTR)
            grpdef.update(ivals)  # add straight IP/PORTSTR's to symbol def.
        except ValueError as e:
            ast[idx] = (pos, ('ERROR', 'GROUP', e.args[0]))
            print('dir ValueError as e', e, dir(e), e.args)

    # 2nd pass, expand delayed references
    for name, mbrs in expand_refs(TODO).items():
        for mbr in mbrs:
            xtra = GROUPS.get(mbr, [])
            if len(xtra) == 0:
                print('empty ref', mbr, 'for group', name)
            GROUPS.setdefault(name, set()).update(xtra)

    return GROUPS


def ast_rules(ast):
    'expand elements of the defined rules'
    # ('RULE', <name>, [src], DIR, [dst], [srv], ('ACTION',act), <json-str>)
    rules = []
    for pos, stmt in ast_iter(ast, ['RULE', 'RULEPLUS']):
        if stmt[0] == 'RULE':
            rules.append(list(stmt[1:]))
        elif stmt[0] == 'RULEPLUS':
            if len(rules) == 0:
                raise ValueError('dangling:{}'.format(str(stmt)))
            if '@' == stmt[1]:
                rules[-1][4].extend(stmt[2])
            if '<' in stmt[1]:
                rules[-1][1].extend(stmt[2])
            if '>' in stmt[1]:
                rules[-1][3].extend(stmt[2])
        else:
            raise ValueError('ast_rules cannot handle stmt {!r}'.format(stmt))

    # proces direction of rules
    # rule := [name, src, dst, srv, action, json-str]
    rv = []
    for rule in rules:
        direction = rule[2]     # capture direction and remove field
        del rule[2]
        rule[1] = Ival.summary(rule[1])  # summarize src
        rule[2] = Ival.summary(rule[2])  # summarize dst
        rule[3] = Ival.summary(rule[3])  # summarize srv
        if direction == '>':
            rv.append(rule)
        elif direction == '<':
            rule[1], rule[2] = rule[2], rule[1]
            rv.append(rule)
        else:
            rv.append(rule.copy())
            if rule[1] != rule[2]:
                rule[1], rule[2] = rule[2], rule[1]
                rv.append(rule)

    return rv


# -- SEMANTICS


def ast_semantics(ast):
    'run all chk_ast_funcs on ast'
    # all chk_xyz(ast) -> must return an (un)modified, valid ast
    for check in [x for x in globals() if x.startswith('chk_')]:
        semantics = globals()[check]
        # XXX: log on informational level to console
        print('semantics:', semantics.__doc__)
        ast = semantics(ast)
    return ast


def chk_ast_dangling(ast):
    'checking RULE(PLUS) scopes'
    scope = None  # determines current scope (if any)
    for idx, pos, stmt in ast_enum(ast):
        if stmt[0] == 'BLANK':
            continue
        if stmt[0] == 'RULEPLUS' and scope not in ['RULE', 'RULEPLUS']:
            ast[idx] = (pos, ('ERROR', 'RULEPLUS',
                              'not in scope of a RULE'))
        scope = stmt[1] if stmt[0] in ['ERROR', 'WARNING'] else stmt[0]

    return ast


def chk_ast_refs(ast):
    'check group references'
    global GROUPS

    def undefined_refs(lst):
        return [x[1] for x in lst if x[0] == 'STR' and x[1] not in GROUPS]

    def empty_refs(lst):
        return [x[1] for x in lst if x[0] == 'STR' and x[1] in GROUPS and len(
            GROUPS.get(x[1], [])) == 0]

    for idx, pos, stmt in ast_enum(ast, ['GROUP', 'RULE', 'RULEPLUS']):
        unrefs = undefined_refs(stmt[2])  # unknown group-references
        emptyrefs = empty_refs(stmt[2])   # undefined group-references
        if stmt[0] == 'RULE':
            unrefs += undefined_refs(stmt[4])  # add unknown dsts
            emptyrefs += empty_refs(stmt[4])
            unrefs += undefined_refs(stmt[5])  # add unknown srvs
            emptyrefs += empty_refs(stmt[5])

        if len(unrefs) and len(emptyrefs):
            msg = 'has empty ref: {} and undefined refs: {}'.format(
                ', '.join(emptyrefs), ', '.join(unrefs))
        elif len(unrefs):
            msg = 'has undefined references: {}'.format(unrefs)
        elif len(emptyrefs):
            msg = 'has empty references: {}'.format(emptyrefs)
        else:
            continue  # all is ok

        ast[idx] = (pos, ('ERROR', stmt[0], msg))

    return ast


def chk_ast_args(ast):
    'checking argument validity'
    # RULEPLUS @ has STR's or PORTSTR's, else its an ERROR
    # RULEPLUS <,>,<> has STR's or IP's, else its an ERROR
    # RULE, same checks for src, dst and services
    NETARGS = ('IP', 'STR')
    SRVARGS = ('PORTSTR', 'STR')
    ALLARGS = set([*NETARGS, *SRVARGS])

    for idx, pos, stmt in ast_enum(ast, ['GROUP', 'RULE', 'RULEPLUS']):
        illegal = []

        if stmt[0] == 'GROUP':
            illegal = [x[1] for x in stmt[2] if x[0] not in ALLARGS]

        elif stmt[0] == 'RULE':
            illegal = [x[1] for x in stmt[2] if x[0] not in NETARGS]
            illegal.extend(x[1] for x in stmt[4] if x[0] not in NETARGS)
            illegal.extend(x[1] for x in stmt[5] if x[0] not in SRVARGS)

        elif stmt[0] == 'RULEPLUS':
            if stmt[1] == '@':
                illegal = [x[1] for x in stmt[2] if x[0] not in SRVARGS]
            else:
                illegal = [x[1] for x in stmt[2] if x[0] not in NETARGS]

        else:
            raise ValueError('stmt args check: unknown stmt type {}'.format(
                stmt[1]))

        if len(illegal):
            msg = 'illegal args: {}'.format(', '.join(str(i) for i in illegal))
            ast[idx] = (pos, ('ERROR', stmt[0], msg))

    return ast


# -- Compile

def print_ast(ast):
    'print out the abstract syntax tree'
    for pos, stmt in ast:
        print('{}:{}:{}'.format(os.path.relpath(pos[0]), pos[1], pos[2]),
              *(elm for elm in stmt))


def compile(src):
    'compile file into IP4Filter object'
    global GROUPS

    try:
        fhdl = open(src, "rt")     # src is a readable filename
    except (IOError, OSError):
        import io                  # otherwise, treat it as text
        fhdl = io.StringIO(src)

    ast = parse(fhdl)
    ast = ast_includes(ast)        # include & parse include(files)
    GROUPS = ast_symbol_table(ast) # create new symbol table
    ast = ast_semantics(ast)       # check validity of ast
    ast = ast_ivalify(ast)         # turn IP, PORTSTR strings into Ival's
    ast = ast_jsonify(ast)         # turn json str into python object

    errors = list(ast_iter(ast, 'ERROR'))
    warnings = list(ast_iter(ast, 'WARNING'))
    for pos, msg in errors:
        print('Error:{}:{}'.format(pos, msg))
    for pos, msg in warnings:
        print('Warning:{}:{}'.format(pos, msg))
    print('Score: E{}, W{}'.format(len(errors), len(warnings)))
    if len(errors):
        print_ast(ast)
        raise SystemExit(1)


    # TODO:
    # - check consistency of Ival methods throughout the code
    # - perhaps rename Ival alt constructors to from_pfx, from_portstr, from_ival etc
    rules = ast_rules(ast)
    print('\n')
    print('-'*35, 'RULES')
    for rule in rules:
        print(rule)
    print('\n')
    ip4f = Ip4Filter()
    print('-'*35, 'ADDing rules')
    for rid, (tag, srcs, dsts, ports, action, dta) in enumerate(rules):
        dta['tag'] = tag if tag else rid
        print(rid, tag, '|', srcs, '|', dsts, '|', ports, '>', action, dta)
        ip4f.add(rid, srcs, dsts, ports, action, dta)
    return ip4f


