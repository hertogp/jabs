#!/usr/bin/env python3

'''
xcol - manipulate columns in a csv file

usage:  xcol -i input.csv command [command ...]

where command is:

  field=func:arg,arg,..  assign value to a (possibly new) field
  field~rgx              select rows where field matches the rgx
  func:arg,arg,...       do something to the entire dataset

  In the first form, a name from a file is understood to be an ip lookup
  request.  E.g. src_vpn=ip2vpn,src_ip,vpn_name means to lookup (longest
  prefix match) the src_ip value in the ip table given by ip2vpn.csv and return
  the value found in the vpn_name field in the table.

Apart from the ip table lookup, the following functions are implemented:

  delete:column         - deletes column 'column'
  sum:field             - sums 'field' across similar rows
  lower:field           - lowercase field
  upper:field           - uppercase field
  replace:str1[,str2]   - replaces str1 by str2 in fieldname



'''

import sys
import time
import argparse
import re

from functools import wraps, partial

import pandas as pd
import numpy as np

#-- Glob
__version__ = '0.1'

CMDS = {}

#-- decorator
def add_cmd(cmd=None, *, name=None):
    'decorator that add_cmds cmd by name in global CMDS dispatch dict'
    if cmd is None:
        return partial(add_cmd, name=name)  # @add_cmd(name=...) variant
    cmd.__name__ = name if name else cmd.__name__
    CMDS[cmd.__name__] = cmd
    return cmd

#-- helpers
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

def fatal_field_error(df, cmd, dst, fields):
    'generic message for cmds that run into trouble with some missing fields'
    msg(0, '-'*65, 'fatal')
    msg(0, 'exec:', cmd_str(cmd, dst, fields), '<< field failure')
    msg(0, '- available: [{}]'.format(','.join(df.columns.values)))
    unknowns = unknown_fields(df, fields)
    msg(0, '- unknown  : [{}]'.format(','.join(unknowns)))
    msg(0, '-'*65, 'bye, :(')
    sys.exit(1)


def load_csv(filename):
    'csv file to dataframe w/ normalized column names and perhaps an index'
    msg(1, 'reading csv file {!r}'.format(filename))
    try:
        df = pd.read_csv(filename, skipinitialspace=True)
    except (IOError, OSError):
        msg(0, 'cannot read {}'.format(filename))
        return pd.DataFrame()  # empty dataframe

    msg(1, ' - columns names original  : {}'.format(df.columns.values))
    df.columns = [normalize(n) for n in df.columns]
    msg(1, ' - columns names normalized: {}'.format(df.columns.values))
    msg(1, ' - num of entries: {}'.format(len(df)))

    return df


def write_csv(df, output=sys.stdout):
    'output df to sys.stdout or a file'
    df.to_csv(output, mode='w')
    return 0


def msg(level, *words):
    'possibly print stuff'
    if level > args.v:
        return
    print(' '.join(str(x) for x in words), file=sys.stdout)


def parsecmd(command):
    'syntax:  [fieldname=]funcname:arg,arg,.. or field~rgx'
    parts = re.split('(=|:|,|~)', command)
    seps = parts[1::2]
    fields = list(reversed(parts[::2]))
    cmd, dst, cmd_args = None, None, []

    if len(seps) == 0:
        cmd = fields.pop()

    for s in seps:
        if s == '=':
            dst = fields.pop()
        elif s == '~':
            # src_name~/hvwn/i
            # src_host=src_name~s/\(-KPN\|-VOD\)//
            cmd = 'rgx'
            dst = dst or fields.pop()
            cmd_args = list(reversed(fields))
        elif s == '@':
            cmd = 'fwr'
            dst = fields.pop()
            cmd_args = list(reversed(fields))
        elif s == ':':
            cmd = fields.pop()
            cmd_args = list(reversed(fields))

    return [cmd, dst, cmd_args]


def cmd_str(cmd, dst, fields):
    'reconstruct actual command from basic fields'
    if dst is None:
        return '{}:{}'.format(cmd, ','.join(fields))
    else:
        return '{}={}:{}'.format(dst, cmd, ','.join(fields))

def parseargs():
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
        arg.cmds.append(parsecmd(cmd))

    return arg

def show_info():
    msg(0, '\n' + '-'*30, args.prog, 'invocation')
    msg(0, 'verbosity level (-v) ', args.v)
    msg(0, 'input file      (-i) ', args.i)
    msg(0, 'output file     (-o) ', args.o)
    msg(0, '\n' + '-'*30, 'commands')
    maxl = max(len(c) for c in args.commands)
    for idx, txt in enumerate(args.commands):
        cmd, dst, arg = args.cmds[idx]
        c = CMDS.get(cmd, None)
        if c:
            msg(0, 'cmd {:02}'.format(idx),
                '{:{w}}  => {}({},{}) '.format(txt, c.__name__, dst,
                                              repr(arg), w=maxl))
        else:
            msg(0, 'cmd {:02}'.format(idx),
                '{:{w}}  => ip lookup: {}({},{})'.format(txt, cmd, dst,
                                                        repr(arg), w=maxl))

    msg(0, '\n' + '-'*30, 'available cmds')
    for k, v in sorted(CMDS.items()):
        msg(0, v.__doc__)

#-- commands

@add_cmd
def lower(df, dst, *fields):
    'lower:field1,field2,.. - lower-case 1 or more fields'
    try:
        if dst is None:
            # just lower-case some fields inplace
            for field in fields:
                df[field] = df[field].str.lower()
        elif len(fields) != 1:
            msg(0, cmd_str('lower', dst, fields), '<< failed')
            msg(0, '- dst=lower:field can have only 1 src field')
            msg(0, '- not {}'.format(fields))
            sys.exit(1)
        else:
            df[dst] = df[fields[0]].str.lower()
    except KeyError:
        fatal_field_error(df, 'lower', dst, fields)

    return df


@add_cmd
def upper(df, dst, *fields):
    'upper:field1,field2,.. - upper-case 1 or more fields'
    try:
        if dst is None:
            # just upper-case some fields inplace
            for field in fields:
                df[field] = df[field].str.upper()
        elif len(fields) != 1:
            msg(0, cmd_str('upper', dst, fields), '<< failed')
            msg(0, '- can have only 1 src field, not {}'.format(fields))
            sys.exit(1)
        else:
            df[dst] = df[fields[0]].str.upper()
    except KeyError:
        fatal_field_error(df, 'upper', dst, fields)
        sys.exit(1)

    return df

@add_cmd
def replace(df, dst, *fields):
    '[dst=]replace:field,old,new - old is replaced by new'
    if len(fields) != 3:
        msg(0, cmd_str('replace', dst, fields), '<< failed')
        msg(0, '- need 3 fields, got {}'.format(len(fields)))
        msg(0, '- requires a src-field,old,new - syntax: [dst=]replace:src,old,new')
        sys.exit(1)

    dst = fields[0] if dst is None else dst
    src, old, new = fields
    try:
        df[dst] = df[src].str.replace(old,new)
    except KeyError:
        fatal_field_error(df, 'replace', dst, fields)
        sys.exit(1)

    return df


@add_cmd
def join(df, dst, *fields):
    'dst=join:sep,field1,field2.. - join some fields using sep'
    if dst is None:
        msg(0, cmd_str('join', dst, fields), '<< failed')
        msg(0, '- requires a dst-field, syntax: dst=join:sep,f1,f2..')
        sys.exit(1)
    char, fields = fields[0], list(fields[1:])
    if len(fields) < 2:
        msg(0, 'join', dst, *fields, '<< failed')
        msg(0, '-', '{}="{}".join({})'.format(dst, char, fields), '<< failed')
        msg(0, '- need 2 or more fields to join, got {}'.format(fields))
        sys.exit(1)
    try:
        df[dst] = df[fields].apply(lambda x: char.join(str(f) for f in x), axis=1)
    except KeyError:
        unknowns = [str(x) for x in fields if x not in df.columns]
        msg(0, 'join', dst, *fields, '<< failed:')
        msg(0, ' - available for join: {}'.format(','.join(df.columns.values)))
        msg(0, ' - not available are :  {}'.format(','.join(unknowns)))
        sys.exit(1)
    return df


@add_cmd(name='sum')
def o_sumf(df, *fields):
    'sumf:field - sums a field (int valued) across similar rows'
    print('sumf', *fields)
    return df

@add_cmd
def o_rgx(df, *fields):
    'field1=field2~s/abc/ABC/i or field2~/ABC/ to substitue or filter'
    print('rgx', *fields)
    return df

@add_cmd
def o_fwr(df, *fields):
    'file@ruleset - filter rows using ruleset from file'
    print('fwr', *fields)
    return df

@add_cmd
def nan(df, dst, *fields):
    '[dst=]nan:s1,s2,.. - replace s<x> with null value for dst or all fields'
    try:
        if dst is None:
            for replacer in fields:
                df.replace(replacer, np.nan, inplace=True)
        else:
            for replacer in fields:
                df[dst].replace(replacer, np.nan, inplace=True)

    except KeyError:
        fatal_field_error(df, 'nan', dst, fields)
        sys.exit(1)

    return df

@add_cmd
def o_fillby(df, dst, *fields):
    'fieldx=fillby:fieldy - fills fieldx NaNs via fieldy->fieldx map'
    print('fillby, *fields')
    return df


@add_cmd(name='del')
def delf(df, dst, *fields):
    'del:field1,.. - delete 1 or more fields'
    if dst is not None:
        msg(0, cmd_str('del', dst, fields), '<< failed')
        msg(0, '- no dst field allowed, syntax: del:field1,..')
        sys.exit(1)
    fields = list(fields)
    try:
        df.drop(fields, axis=1, inplace=True)
    except (KeyError, ValueError):
        fatal_field_error(df, 'del', None, fields)
        sys.exit(1)

    return df


@add_cmd
def keep(df, dst, *fields):
    'keep:field,field.. - keep only these fields'
    if dst is not None:
        msg(0, cmd_str('keep', dst, fields), '<< failed')
        msg(0, '- no dst field allowed, syntax: keep:field1,..')
        sys.exit(1)
    fields = list(fields)
    try:
        df = df[fields]
    except (KeyError, ValueError):
        fatal_field_error(df, 'del', None, fields)
        sys.exit(1)

    return df


def main():
    msg(0)
    show_info()
    msg(0)
    df = load_csv(args.i)
    for cmd, dst, arg  in args.cmds:
        msg(0, 'exec:', cmd_str(cmd, dst, arg))
        func = CMDS.get(cmd, None)
        if func:
            df = func(df, dst, *arg)
        else:
            msg(0, '-'*65, 'fail')
            msg(0, 'exec:', cmd_str(cmd, dst, arg))
            msg(0, '- cmd not recognized')
            msg(0, '-'*65, 'bye :(')
            sys.exit(1)

    print('-'*80)
    write_csv(df)

    return 0


if __name__ == '__main__':
    args = parseargs()
    sys.exit(main())
