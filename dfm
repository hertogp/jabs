#!/usr/bin/env python3

'''
dfm - dataframe manipulations

usage:  dfm -i input.csv command [command ...]
'''

# TODO
# add f1[,..]=fillna:value
#
import os
import sys
import time
import argparse
import re

from functools import wraps, partial

import pandas as pd
import numpy as np
import pytricia as pt

#-- Glob
__version__ = '0.1'

CMD_MAP = {}  # dfm func name -> func reference
IPT_MAP = {}  # ipt fname -> ip-table

#-- CMD Registry
def parse_args():
    'parse commandline arguments, return arguments Namespace'
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    padd = p.add_argument
    padd('-v', action='count', help='verbose flag', default=0)
    padd('-o', required=False, type=str, default='',
         help='output filename, if not given prints to stdout')
    padd('-i', required=True, type=str, default='',
         help='csv input filename to process')
    padd('-V', '--version', action='version',
         version='%(prog)s {}'.format(__version__))
    padd('commands', nargs='*')

    # parse & sanitize the arguments
    arg = p.parse_args()
    arg.o = arg.o or sys.stdout
    arg.prog = sys.argv[0]
    arg.cmds = []
    for cmd in arg.commands:
        arg.cmds.append(parse_cmd(cmd, verbose=arg.v))

    return arg


def register_cmd(func=None, *, name=None):
    'decorator that register_cmds cmd by name in global CMD_MAP dispatch dict'
    if func is None:
        return partial(register_cmd, name=name)     # @register_cmd(name=...) variant
    func.__name__ = name if name else func.__name__   # used by cmd_error
    CMD_MAP[func.__name__] = func
    return func


def parse_cmd(command, verbose=0):
    'syntax:  [fieldname=]funcname:arg,arg,.. or field~regex'
    try:
        if len(command) < 1:
            raise ValueError('empty command string!')
    except Exception as e:
        raise ValueError('parse_cmd failed {}'.format(repr(e)))

    parts = re.split('(=|:|,|~)', command)
    seps = parts[1::2] + ['']
    fields = parts[::2]
    cmd, lhs, rhs = None, [], []

    if len(seps) == 0:
        cmd = fields.pop()
        return [command, cmd, lhs, rhs]   # command without lhs or rhs

    ptr = lhs  # start collecting for lhs
    oldtok = None # previous separator
    for tok, val in zip(seps, fields):
        if tok == '=':
            ptr.append(val)      # last part for lhs
            ptr = rhs            # now collect for rhs
        elif tok == ',':
            ptr.append(val)      # collect an item for lhs/rhs
        elif tok == ':':
            ptr = rhs            # func w/ args, start collecting rhs
            if cmd is None:
                cmd = val
            else:
                raise ValueError('{} <- misplaced :'.format(command))
        elif tok == '~':
            if len(val):
                ptr.append(val)  # last for lhs
            if cmd is not None:
                print('error in', command)
            cmd = 'regex'        # only cmd without a name
            ptr = rhs
        elif len(tok) == 0:
            if oldtok == ',':
                ptr.append(val)
            elif oldtok == '=':
                if cmd is None:
                    cmd = val
                else:
                    ptr.append(val)
            else:
                if len(val):
                    ptr.append(val)
        oldtok = tok

    # default to keep command if it is None
    cmd = 'keep' if cmd is None else cmd
    return [command, cmd, lhs, rhs]


def cmd_str(cmd, lhs, rhs):
    'reconstruct factual cli command from basic fields'
    lhs = [] if lhs is None else lhs
    rhs = [] if rhs is None else rhs
    return '{}={}:{}'.format(','.join(lhs), cmd, ','.join(rhs))


def cmd_error(df, lhs, rhs, errors):
    'Report fatal error(s) and exit'
    caller_name = sys._getframe(1).f_code.co_name  # is real/org func name
    func = globals().get(caller_name, None)  # registered name may be different
    cmdstr = cmd_str(func.__name__, lhs, rhs)

    prn(0, '[{}] error in {!r}'.format(func.__name__, cmdstr))
    prn(0, '[{}] lhs {}'.format(func.__name__, lhs))
    prn(0, '[{}] rhs {}'.format(func.__name__, rhs))

    for error in errors:
        prn(0, '[{}] {}'.format(func.__name__, error))

    # list help when being verbose
    if args.v:
        prn(0, '[{}] doc'.format(func.__name__))
        prn(0, '---')
        prn(0, func.__doc__)
        prn(0, '---')

    sys.exit(1)


def cmd_unknown(df, lhs, rhs):
    prn(0, 'cannot handle', lhs, rhs)
    sys.exit(1)


#-- helpers
def prn(level, *words, output=sys.stderr):
    'possibly print stuff'
    if level > args.v:
        return
    print(' '.join(str(x) for x in words), file=output)


def load_csv(filename):
    'csv file to dataframe w/ normalized column names'
    prn(1, 'reading csv file {!r}'.format(filename))
    try:
        df = pd.read_csv(filename, skipinitialspace=True)
    except (IOError, OSError):
        prn(0, 'cannot read {}'.format(filename))
        return pd.DataFrame()  # empty dataframe

    prn(1, ' - columns names original  : {}'.format(df.columns.values))
    df.columns = [normalize(n) for n in df.columns]
    prn(1, ' - columns names normalized: {}'.format(df.columns.values))
    prn(1, ' - num of entries: {}'.format(len(df)))

    return df


def write_csv(df, output=sys.stdout):
    'output df to sys.stdout or a file'
    df.to_csv(output, index=False, mode='w')
    return 0


def normalize(name):
    'normalize a column name to something sane'
    name = name.replace('.', '_')     # no dots
    name = name.replace(' ', '_')     # no whitespace
    name = name.replace('\t', '_')
    name = name.replace('\r', '_')
    name = name.replace('\f', '_')
    return name


def unknown_fields(df, fields):
    'return list of unknown fields'
    return [x for x in fields if x not in df.columns]


def show_info(df=None):
    prn(0, '\n' + '-'*60, args.prog, 'info\n')

    prn(0, '-'*30, 'flags\n')
    prn(0, 'verbosity level (-v) ', args.v)
    prn(0, 'input file      (-i) ', args.i)
    prn(0, 'output file     (-o) ', args.o)

    if len(args.commands):
        prn(0, '\n' + '-'*30, 'cli commands\n')
        maxl = max(len(c) for c in args.commands)
        for idx, txt in enumerate(args.commands):
            org, cmd, dst, arg = args.cmds[idx]
            c = CMD_MAP.get(cmd, None)
            if c:
                prn(0, 'cmd {:02}'.format(idx),
                    '{:{w}}  => {}({},{}) '.format(txt, c.__name__, dst,
                                                  repr(arg), w=maxl))
            else:
                prn(0, 'cmd {:02}'.format(idx),
                    '{:{w}}  => ip lookup: {}({},{})'.format(txt, cmd, dst,
                                                            repr(arg), w=maxl))

    prn(0, '\n' + '-'*30, 'available cmds\n')
    for k, v in sorted(CMD_MAP.items()):
        prn(0, v.__doc__)

    if df is not None:
        prn(0, '\n' + '-'*30, 'DataFrame\n')
        prn(0, '{} rows by {} columns'.format(*df.shape))
        maxl = max(len(c) for c in df.columns.values)+2  # +2 for !r quotes
        prn(0, '{:{w}} - {}'.format('Column', 'DataType', w=maxl))
        for col in df.columns:
            prn(0, '{!r:{w}}   {}'.format(col, df[col].dtype, w=maxl))
        prn(0, '{:{w}}   {}'.format('<index>', df.index.dtype, w=maxl))
        prn(0, '\nFirst 3 rows')
        prn(0, df.head(3))

    prn(0, '\n' + '-'*60, 'info end', '\n')

#-- IP Table lookup
def load_ipt(filename, ip_field=None):
    'turn a dataframe into ip lookup table -> pd.Series'
    fname = filename if os.path.isfile(filename) else '{}.csv'.format(filename)
    try:
        df = load_csv(fname)
    except (OSError, IOError) as e:
        prn(0, 'error reading ip lookup file {}'.format(fname))
        sys.exit(1)

    if ip_field is None:
        # find suitable field
        tmp = pt.PyTricia()
        for field in df.columns:
            try:
                tmp[df[field].iloc[0]] = 'test'
                ip_field = field
                break
            except ValueError:
                continue

    elif ip_field not in df.columns:
        prn(0, 'field {!r} not available as lookup column'.format(ip_field))
        sys.exit(1)

    # tidy the ip_field lookup column (also remove leading zeros?)
    df[ip_field] = df[ip_field].str.replace(' ', '')

    ipt = pt.PyTricia()
    for idx, row in df.iterrows():
        try:
            ip_idx = row[ip_field]
            # ensure /32 for bare addresses
            ip_idx = ip_idx if '/' in ip_idx else '{}/{}'.format(ip_idx, 32)
            if ipt.has_key(ip_idx):  # noqa W601
                # has_key must be used to do an exact match, because
                # the "if ip_idx in ipt:" does a longest pfx match,
                # which is not what we want here...
                prn(0, '>> ignoring duplicate entry for {}'.format(ip_idx))
                prn(0, ' - already have', ','.join(str(x) for x in ipt[ip_idx]))
                prn(0, ' - ignoring data', ','.join(str(x) for x in row))
                continue
            ipt[ip_idx] = row  # stores reference to the Series
        except ValueError:
            prn(0, 'Fatal, cannot create ip lookup table from dataframe')
            prn(0, 'its index is not an ip address?')
            prn(0, df.index)
            prn(0, 'current index element: {}'.format(idx))
            prn(0, 'current row is', row)
            sys.exit(1)

    return ipt

#-- commands


@register_cmd
def lpf(df, lhs, rhs):
    'f1[,..]=lpf:table,f2,f3 - lookup f2 in table, get f3 and assign to f1[,..]'

    # sanity check lhs, rhs
    errors = []
    if len(lhs) < 1:
        errors.append('need 1+ lhs fields to assign to')
    if len(rhs) != 3:
        errors.append('need table, colname & resulting field in rhs')
    if not (os.path.isfile(rhs[0]) or os.path.isfile('{}.csv'.format(rhs[0]))):
        errors.append('cannot find lookup table {!r} on disk'.format(rhs[0]))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    # get cached table, or read from disk
    table, src, result = rhs
    ipt = IPT_MAP.setdefault(table, load_ipt(table))

    # sanity check ip lookup table
    if len(ipt) < 1:
        errors.append('lookup table appears empty')
    tmp = ipt[ipt.keys()[0]]   # get a sample row, must be Series or dict
    if result not in tmp.keys():
        errors.append('field {!r} not available in lookup table'.format(result))
    if src not in df.columns:
        errors.append('field {!r} not available in dataframe'.format(src))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    def lookup(key):
        'lookup func to apply to src column'
        try:
            return str(ipt[key][result])
        except KeyError:
            return 'n/a'
        except ValueError:
            return 'err'
        except Exception as e:
            cmd_error(df, lhs, rhs, [repr(e)])

    for dst in lhs:
        df[dst] = df[src].apply(lookup)

    return df


@register_cmd(name='copy')
def copyf(df, lhs, rhs):
    'f1[,..]=copy:f2[,..] - copy f2[..] to f1[..]'

    # sanity check lhs, rhs
    errors = []
    if len(rhs) < 1:
        errors.append('need 1+ rhs fields')
    if len(lhs) < 1:
        errors.append('need 1+ lhs fields')
    if len(lhs) != len(rhs):
        errors.append('need same number of lhs:rhs fields')
    for unknown in unknown_fields(df, rhs):
        errors.append('field {!r} not available'.format(repr(unknown)))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    try:
        for dst,src in zip(lhs, rhs):
            prn(1, '- df[{}] = df[{}]'.format(dst, src))
            df[dst] = df[src]
    except Exception as e:
        cmd_error(df, lhs, rhs, [repr(e)])

    return df


@register_cmd
def lower(df, lhs, rhs):
    'f1,f2=lower[:f] - lower-case fields or assign lower(f) to f1,..'

    # sanity check lhs, rhs
    errors = []
    if len(rhs) > 1:
        errors.append('only 1 rhs field allowed')
    if len(lhs) < 1:
        errors.append('need 1+ lhs fields')
    for unknown in unknown_fields(df, rhs):
        errors.append('unknown rhs field {}'.format(repr(unknown)))
    srcs = rhs * len(lhs) if rhs else lhs
    for unknown in unknown_fields(df, srcs):
        errors.append('field {} is not a valid source'.format(repr(unknown)))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    try:
        for dst,src in zip(lhs, srcs):
            prn(1, '- df[{}] = df[{}].str.lower()'.format(dst, src))
            df[dst] = df[src].str.lower()
    except KeyError:
        cmd_error(df, lhs, rhs, ['unknown error'])

    return df


@register_cmd
def upper(df, lhs, rhs):
    'f1,f2=upper[:f] - upper-case fields or assign upper(f) to f1,..'

    # sanity check lhs, rhs
    errors = []
    if len(rhs) > 1:
        errors.append('only 1 rhs field allowed')
    if len(lhs) < 1:
        errors.append('need 1+ lhs fields')
    for unknown in unknown_fields(df, rhs):
        errors.append('unknown rhs field {}'.format(repr(unknown)))
    srcs = rhs * len(lhs) if rhs else lhs
    for unknown in unknown_fields(df, srcs):
        errors.append('field {} is not a valid source'.format(repr(unknown)))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    try:
        for dst,src in zip(lhs, srcs):
            prn(1, '- df[{}] = df[{}].str.upper()'.format(dst, src))
            df[dst] = df[src].str.upper()
    except Exception as e:
        cmd_error(df, lhs, rhs, ['runtime error', repr(e)])

    return df


@register_cmd
def keep(df, lhs, rhs):
    'f1[,..][=keep] - keep only f1[,..] fields'

    # sanity check lhs, rhs
    errors = []
    if len(rhs) > 0:
        errors.append('no rhs fields allowed')
    if len(lhs) < 1:
        errors.append('need 1+ lhs fields to keep')
    for unknown in unknown_fields(df, lhs):
        errors.append("field '{}' not an existing column".format(unknown))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    try:
        df = df[lhs]

    except Exception as e:
        cmd_error(df, lhs, rhs, ['runtime error', repr(e)])

    return df


@register_cmd(name='del')
def delf(df, lhs, rhs):
    'f1[,..]=del - delete f1[,..] fields'

    # sanity check lhs, rhs
    errors = []
    if len(rhs) > 0:
        errors.append('no rhs fields allowed')
    if len(lhs) < 1:
        errors.append('need 1+ lhs fields')
    for unknown in unknown_fields(df, lhs):
        errors.append("field '{}' not an existing column".format(unknown))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    try:
        for field in lhs:
            df.drop(field, axis=1, inplace=True)
    except (KeyError, ValueError) as e:
        cmd_error(df, lhs, rhs, ['runtime error', repr(e)])

    return df


@register_cmd
def join(df, lhs, rhs):
    'f=join:sep,f1,f2[,f3,..] - join 2+ fields using sep'

    # sanity check lhs, rhs
    errors = []
    if len(rhs) < 3:
        errors.append('need 3+ fields in rhs: sep,f1,f2,...')
    if len(lhs) != 1:
        errors.append('need exactly 1 lhs field')
    for unknown in unknown_fields(df, rhs[1:]):
        errors.append("field '{}' not an existing column".format(unknown))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    dst = lhs[0]
    sep, srcs = rhs[0], rhs[1:]

    try:
        df[dst] = df[srcs].apply(lambda x: sep.join(str(f) for f in x), axis=1)
    except Exception as e:
        cmd_error(df, lhs, rhs, ['runtime error', repr(e)])

    return df

@register_cmd(name='map')
def mapf(df, lhs, rhs):
    'f1[,..]=map:fx - create fx map and apply to existing f1[,..]'

    # sanity check lhs, rhs
    errors = []
    if len(lhs) < 1:
        errors.append('need at least 1 lhs field to assign to')
    if len(rhs) != 1:
        errors.append('need exactly 1 rhs field as map source')
    for unknown in unknown_fields(df, lhs + rhs):
        errors.append("field '{}' not available".format(unknown))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    src = rhs[0]
    dst = [c for c in lhs if c != src]  # avoid source control column
    fix = df.set_index(src)             # src value mappings to other columns
    prn(2, '- control column {}'.format(src))
    for col in dst:
        dct = fix[[col]].dropna().to_dict()[col]  # null's should be NaNs!
        prn(1, '- mapping to', repr(col), 'with', len(dct), 'unique mappings')
        df[col] = df[src].map(dct)

    return df


@register_cmd
def nan(df, lhs, rhs):
    '[f=]nan:s1,.. - replace values s<x> with null value in dst/all fields'

    # sanity check lhs, rhs
    errors = []
    for unknown in unknown_fields(df, lhs):
        errors.append('field {!r} not available'.format(unknown))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    try:
        if len(lhs) == 0:
            for replacer in rhs:
                df.replace(replacer, np.nan, inplace=True)
        else:
            for dst in lhs:
                for replacer in rhs:
                    df[dst].replace(replacer, np.nan, inplace=True)

    except Exception as e:
        cmd_error(df, lhs, rhs, [repr(e)])

    return df


@register_cmd
def regex(df, lhs, rhs):
    '[f1=]f2~/abc/[ABC/][i] to create/modify fx or filter by fy'
    # regexp work on strings, not numbers. At the moment, str(x) is used to
    # ensure a column field value is a string.  Not needed when its already
    # string-like.  So a speed-up is handy by first checking if the field
    # being matched/search is already string-like (save str(x) on every
    # value in a column ....

    # sanity check lhs, rhs
    errors = []
    if len(lhs) < 1:
        errors.append('need at least 1 field to work with')
    if len(rhs) < 1:
        errors.append('missing field or regexp')
    for unknown in unknown_fields(df, rhs[:-1]):
        errors.append("field '{}' not available".format(unknown))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    expression, rhs = rhs[-1], rhs[0:-1]
    parts = re.split('(/)', expression)  # keep delim / in parts
    delim = parts[1::2]                  # either 2 or 3 /'s are valid!
    terms = list(parts[::2])

    if len(delim) not in [2,3]:
        errors.append('syntax error in {!r}'.format(expression))
        errors.append('- expected 2 or 3 /\'s in the expression ..')
        cmd_error(df, lhs, rhs, errors)

    flags = 0
    for f in terms[-1]:
        f = f.lower()
        if f == 'i':
            flags |= re.I
        elif f == 'a':
            flags |= re.A
        elif f == 's':
            flags |= re.S
        elif f == 'm':
            flags |= re.M
        else:
            errors.append('regexp, unknown flag in {!r}'.format(f))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    rgx = re.compile(terms[1], flags)
    prn(1, '-', rgx)

    if len(delim) == 2:
        if len(rhs) == 0:
            # f1[,f2,..]~/expr/ -> rows where expr matches 1 of f1[f2,..]

            for unknown in unknown_fields(df, lhs):
                errors.append('field {!r} not available'.format(unknown))
            if len(errors):
                cmd_err(df, lhs, rhs, errors)
            prn(1, "- filter rows by re.search on '{}'".format(lhs))
            n1 = len(df.index)
            df = df[df[lhs].apply(lambda r: any(rgx.search(str(f)) for f in r), axis=1)]
            n2 = len(df.index)
            fmt = 'filtering {!r}: {} -> {} rows (delta {})'
            prn(1, fmt.format(lhs, n1, n2, n1-n2))
        else:
            # f1[,f2,..]=f3~/expr/ -> if f3 matches, assign it to f1 [AND f2,..],
            #                         otherwise assign np.nan to f1 [AND f2,..]
            if len(rhs) != 1:
                cmd_error(df, lhs, rhs+[expression], ['too many rhs fields'])
            src = rhs[0]
            prn(1, '- {}={} when re.search matches'.format(lhs, src))
            nomatch = np.nan

            newcol = df[src].apply(lambda x: x if rgx.search(str(x)) else nomatch)
            for dst in lhs:
                df[dst] = newcol
                prn(1, '- {} new {} fields filled'.format(len(df[dst].dropna()), dst))

    elif len(delim) == 3:
        # [f1=]f2~/expr/repl/[flags]  to replace in f2 and/or assign to f1
        # f1,f2=f3~/expr/repl   vs  f1,f2~/expr/repl/
        repl = terms[2]
        if len(rhs) == 0:
            srcs = lhs
        elif len(rhs) == 1:
            srcs = rhs * len(lhs)
        else:
            cmd_error(df, lhs, rhs + [expression], ['max 1 rhs field allowed'])

        for unknown in unknown_fields(df, srcs):
            errors.append('field {!r} not available'.format(unknown))
        if len(errors):
            cmd_error(df, lhs, rhs + [expression], errors)

        print(df.dtypes)
        for src,dst in zip(srcs,lhs):
            prn(1, '- {}={}.sub({},{})'.format(dst, rgx, src, repr(repl)))
            df[dst] = df[src].apply(lambda x: rgx.sub(repl, str(x)))
    else:
        cmd_error(df, lhs, rhs + [expression], ['- dunno what to do with this'])

    return df


@register_cmd(name='in')
def inf(df, lhs, rhs):
    'f1[f2,..]=in:v1[v2,..] - select rows where f1 (or f2,..) are in value-list'

    # sanity check lhs, rhs
    errors = []
    if len(lhs) < 1:
        errors.append('need 1+ lhs fields')
    if len(rhs) < 1:
        errors.append('need 1+ rhs fields')
    for unknown in unknown_fields(df, lhs):
        errors.append('field {!r} not available'.format(unknown))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    prn(1, '- filter rows by range {!r} on fields {!r}'.format(rhs, lhs))
    n1 = len(df.index)
    df = df[df[lhs].apply(lambda r: any(str(f) in rhs for f in r), axis=1)]
    n2 = len(df.index)
    fmt = 'filtering {!r}: {} -> {} rows (delta {})'
    prn(1, fmt.format(lhs, n1, n2, n1-n2))

    return df

@register_cmd
def inrange(df, lhs, rhs):
    'f1[f2,..]=inrange:v1,v2 - select rows where v1 <= f1(or f2,..) <= v2'
    return df

@register_cmd
def lte(df, lhs, rhs):
    'f1[f2,..]=lte:v1 - rows where f1(or f2,..) <= v1'

    # sanity check lhs, rhs
    errors = []
    if len(lhs) < 1:
        errors.append('need 1+ lhs fields')
    if len(rhs) != 1:
        errors.append('need exactly 1 rhs field')
    for unknown in unknown_fields(df, lhs):
        errors.append('field {!r} not available'.format(unknown))
    if len(errors):
        cmd_error(df, lhs, rhs, errors)

    prn(1, 'filtering rows by {!r} <= {}'.format(lhs, rhs[0]))
    n1 = len(df.index)
    maxval = int(rhs[0])  # ensure this is an integer

    try:
        df = df[df[lhs].apply(lambda r: any(f <= maxval for f in r), axis=1)]
    except (TypeError, ValueError) as e:
        errors.append('{!r} contains non-numeric data: {}'.format(lhs, repr(e)))
        cmd_error(df, lhs, rhs, errors)

    n2 = len(df.index)
    prn(0, '{} -> {} rows ({} filtered)'.format(n1, n2, n1-n2))
    return df

@register_cmd
def gte(df, lhs, rhs):
    'f1[f2,..]=gte:v1 - rows where f1(or f2,..) >= v1'
    return df


@register_cmd(name='sum')
def sumf(df, lhs, rhs):
    'dst=sum:[f1,f2,..] - sums/counts across similar column groups or rows'
    return df


def main():
    'load csv and run it through the cli commands given'
    df = load_csv(args.i)

    for org, cmd, lhs, rhs in args.cmds:
        prn(1, 'running:', org)
        prn(3, '- parsed (lhs, func, rhs): {}, {}, {}'.format(repr(lhs),
                                                            repr(cmd),
                                                            repr(rhs)))
        try:
            func = CMD_MAP.get(cmd, None)
            if func is None:
                prn(0, "no function implementation for {}, {}".format(lhs, rhs))
                sys.exit(1)
            df = func(df, lhs, rhs)
        except ValueError as e:
            prn(0, 'fatal error', org)
            cmd_error(df, lhs, rhs, repr(e))
            sys.exit(1)

    write_csv(df)

    return 0


if __name__ == '__main__':
    args = parse_args()
    sys.exit(main())
