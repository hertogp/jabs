'''
ilf - compiler
'''

import os
import json

from .parse import parse
from .core import Ival, Ip4Filter

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


def ast_error(pos, err_type, stmt_type, msg):
    'small helper to easily create ERROR/WARNING stmts'
    return (pos, [err_type, stmt_type, msg])


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

        seen[absname] = '{}:{}:{}'.format(fname, linenr, col)  # record include
        try:
            with open(absname, 'r') as fhdl:
                include_ast = parse(fhdl)
        except (IOError, OSError):
            ast[idx] = ((fname, linenr, 1),
                        ('ERROR', 'INCLUDE', 'cannot find/read {}'.format(
                            absname)))
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
                ast[idx] = (pos, [stmt[0], stmt[1], _ivalify(stmt[2],
                                                             Ival.IP,
                                                             Ival.PORTSTR)])
            elif stmt[0] == 'RULEPLUS':
                scope = Ival.PORTSTR if stmt[1] == '@' else Ival.IP
                ast[idx] = (pos, [stmt[0], stmt[1], _ivalify(stmt[2], scope)])

            elif stmt[0] == 'RULE':
                srcs = _ivalify(stmt[2], Ival.IP)
                dsts = _ivalify(stmt[4], Ival.IP)
                srvs = _ivalify(stmt[5], Ival.PORTSTR)
                ast[idx] = (pos, [stmt[0], stmt[1], srcs, stmt[3],
                                  dsts, srvs, *stmt[6:]])
            else:
                raise ValueError('{} invalid stmt for ast_ivalify'.format(
                    stmt[0]))
        except ValueError as e:
            ast[idx] = ast_error(pos, 'ERROR', stmt[0], '{}'.format((e)))

    return ast


def ast_jsonify(ast):
    'turn a rule\'s json string into python object or None'
    for idx, pos, stmt in ast_enum(ast, ['RULE']):
        if stmt[-1] is None:
            continue
        try:
            stmt[-1] = json.loads(stmt[-1])
        except (TypeError, json.decoder.JSONDecodeError) as e:
            ast[idx] = ast_error(pos, 'ERROR', stmt[0],
                                 'json-error: {}'.format((e)))
    return ast


def ast_groups(ast):
    'return set of unique group definitions in ast'
    names = [stmt[1] for pos, stmt in ast_iter(ast, ['GROUP'])]
    return set(names)


def ast_members(ast, group, _seen=None):
    'return a list of unique members of a group'
    _seen = set([]) if _seen is None else _seen
    _seen.add(group)
    coll = set([])
    target_group = group.lower()
    for pos, stmt in ast_iter(ast, ['GROUP']):
        _, name, items = stmt
        if name.lower() != target_group:
            continue

        for item in items:
            if item[0] in ['IP', 'PORTSTR']:
                coll.add(item)
            elif item[0] == 'STR':
                gname = item[1]
                if gname in _seen:
                    fmt = 'circular ref for {!r} via {!r}'
                    ast.append((pos, ['WARNING', 'GROUP', fmt.format(gname,
                                                                     group)]))
                    continue

                # in group statements 'any' == 0/0, 'any/any' == ALL-ports
                gname = gname.lower()
                if gname.lower() == 'any':
                    coll.add(('IP', '0.0.0.0/0'))
                elif gname.lower() == 'any/any':
                    coll.add(('PORTSTR', 'any'))
                else:
                    # empty groups are caught by chk_ast_norefs
                    for addition in ast_members(ast, gname, _seen):
                        coll.add(addition)
            else:
                raise ValueError('illegal item {} in group {}'.format(item,
                                                                      group))

    return list(coll)


def ast_build_symbols(ast):
    'initialize and fill group-symbol table'
    global GROUPS
    GROUPS = {'any': set([Ival.ip_pfx('any')]),
              'any/any': set([Ival.port_str('any/any')])}

    for grp in ast_groups(ast):
        try:
            for typ, value in ast_members(ast, grp):
                if typ == 'IP':
                    GROUPS.setdefault(grp, set()).add(Ival.ip_pfx(value))
                elif typ == 'PORTSTR':
                    GROUPS.setdefault(grp, set()).add(Ival.port_str(value))
                else:
                    raise ValueError('Illegal item {} in group {}'.format(typ,
                                                                          grp))
        except ValueError as e:
            print(type, value)
            print('Err', e, repr(e))
    return ast


def member_refs(dct):
    'return a flat, expanded member list from, possible, recursive definition'
    # dct is {name} -> set([name, ..]), which may refer to other names
    for target, mbrs in dct.items():
        heap = list(mbrs)  # mbrs name ('STR', name)
        seen, dct[target] = [target], set([])
        while heap:
            nxt = heap.pop()
            if nxt in seen:
                continue
            seen.append(nxt)
            if nxt in dct:
                heap.extend(list(dct[nxt]))
            dct[target].add(nxt)

    return dct


def ast_symbol_table(ast):
    'Build the symbol table for the ast'
    # need 2 passes, since forward referencing is allowed
    GROUPS = {'any': set([Ival.ip_pfx('any')]),
              'any/any': set([Ival.port_str('any/any')])}
    TODO = {}  # GROUP-name -> [group-names to include]

    # 1st pass, assemble IP/PORTSTR into groupname table and
    #  defer group references till later
    for idx, pos, stmt in ast_enum(ast, ['GROUP']):
        _, grpname, mbrs = stmt
        refs = [t[1] for t in mbrs if t[0] == 'STR']  # only the name
        noref = [t for t in mbrs if t[0] != 'STR']    # entire token
        ivals = []
        try:
            ivals = _ivalify(noref, Ival.IP, Ival.PORTSTR)
        except ValueError as e:
            ast[idx] = (pos, ('ERROR', 'GROUP', repr(e)))
            continue
        GROUPS.setdefault(grpname, set()).update(ivals)
        TODO.setdefault(grpname, set()).update(refs)

    # 2nd pass, expand references
    for name, mbrs in member_refs(TODO).items():
        for mbr in mbrs:
            xtra = GROUPS.get(mbr, [])
            if len(xtra) == 0:
                print('empty ref', mbr, 'for group', name)
            GROUPS[name] = GROUPS.setdefault(name, set()).union(xtra)

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


def chk_ast_norefs(ast):
    'checking group references'
    global GROUPS

    def no_refs(lst):
        return [x[1] for x in lst if x[0] == 'STR' and x[1] not in GROUPS]

    for idx, pos, stmt in ast_enum(ast, ['GROUP', 'RULE', 'RULEPLUS']):
        unrefs = no_refs(stmt[2])  # unknown group-refs, srcs, dsts or srvs
        if stmt[0] == 'RULE':
            unrefs += no_refs(stmt[4])  # add unknown dsts
            unrefs += no_refs(stmt[5])  # add unknown srvs

        if len(unrefs):
            msg = 'undefined reference(s): {}'.format(', '.join(unrefs))
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


def compile_file(filename):
    'compile file into IP4Filter object'
    with open(filename, 'rt') as fhdl:
        ast = parse(fhdl)          # parse master file
    ast = ast_includes(ast)        # include & parse include(files)
    print_ast(ast)
    grps = ast_symbol_table(ast)
    import pprint
    pprint.pprint(grps, indent=3)
    print_ast(ast)
    raise SystemExit(0)
    ast = ast_build_symbols(ast)   # build the GROUPS symbol table
    ast = ast_semantics(ast)       # check validity of ast
    ast = ast_ivalify(ast)         # turn IP, PORTSTR strings into Ival's
    ast = ast_jsonify(ast)         # turn json str into python object

    errors = list(ast_iter(ast, 'ERROR'))
    warnings = list(ast_iter(ast, 'WARNING'))
    print('Score: E{}, W{}'.format(len(errors), len(warnings)))
    for pos, msg in errors:
        print('{}{}'.format(pos, msg))
    for pos, msg in warnings:
        print('{}{}'.format(pos, msg))
    if len(errors):
        print_ast(ast)
        raise SystemExit(1)

    return ast_rules(ast)  # will become ilfilter
