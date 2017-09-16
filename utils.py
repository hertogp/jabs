'''
Utility functions for other modules.
'''
import os
import sys
import re
import math

import pandas as pd
import pytricia as pt

def normalize(astr):
    'no whitespace or dots in string'
    return re.sub(r'(\s|\.)+', '_', astr)


def load_csv(filename):
    'csv file to dataframe w/ normalized column names'
    try:
        df = pd.read_csv(filename, skipinitialspace=True)
    except (IOError, OSError):
        return pd.DataFrame()  # empty dataframe

    df.columns = [normalize(n) for n in df.columns]

    return df


def write_csv(df, output=sys.stdout):
    'output df to sys.stdout or a file'
    df.to_csv(output, index=False, mode='w')
    return 0


def unknown_fields(df, fields):
    'return list of fields that are not columns in df'
    return [x for x in fields if x not in df.columns]


def load_ipt(filename, ip_field=None):
    'turn a dataframe into ip lookup table -> pd.Series'
    # prn(0, 'loading iptable {}'.format(filename))
    fname = filename if os.path.isfile(filename) else '{}.csv'.format(filename)
    try:
        df = load_csv(fname)
    except (OSError, IOError) as e:
        # prn(0, 'error reading ip lookup file {}'.format(fname))
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
        # prn(0, 'field {!r} not available as lookup column'.format(ip_field))
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
                # prn(0, '>> ignoring duplicate entry for {}'.format(ip_idx))
                # prn(0, ' - already have', ','.join(str(x) for x in ipt[ip_idx]))
                # prn(0, ' - ignoring data', ','.join(str(x) for x in row))
                continue
            ipt[ip_idx] = row  # stores reference to the Series
        except ValueError:
            # prn(0, 'Fatal, cannot create ip lookup table from dataframe')
            # prn(0, 'its index is not an ip address?')
            # prn(0, df.index)
            # prn(0, 'current index element: {}'.format(idx))
            # prn(0, 'current row is', row)
            sys.exit(1)

    return ipt


def cmd_parser(tokens):
    funcsep = ': ~'.split()        # these trigger func resp. regex
    lhs, cmd, rhs = [], None, []   # intended result values
    ptr = lhs                      # used to switch between lhs and rhs
    oldopc = ''                    # previous opcode seen
    for opcode, val in tokens:
        if opcode == '=':
            if val != '=':
                # '=func'
                ptr.append(val)
            ptr = rhs
        elif opcode == ',':
            ptr.append(val)
        elif opcode == ':':
            cmd = val
            ptr = rhs
        elif opcode == '~':
            # support both: f1,f2=~a1 and f1,f2~a1
            if val != '~':
                # f1~a1 case
                ptr.append(val)
            cmd = 'regex'
            ptr = rhs
        # opcode is empty at this point
        elif oldopc == ',':
            # when cmd is just a list of fields like 'f1,f2'
            ptr.append(val)
        elif oldopc == '=':
            if cmd is None:
                # when cmd is '=func'
                cmd = val
            else:
                ptr.append(val)
        else:
            ptr.append(val)

        oldopc = opcode

    cmd = 'keep' if cmd is None else cmd
    return [cmd, lhs, rhs]


def cmd_tokens(command):
    'tokenize a string into a list of (sep, value)'
    tokens = []
    value = []
    seps = ': = , ~'.split()
    escape = '\\'

    for c in command:
        if c in seps:
            if len(value) == 0:
                tokens.append((c,c))
            elif value[-1] == escape:
                value[-1] = c
            else:
                tokens.append((c, ''.join(value)))
                value.clear()
        else:
            value.append(c)

    if len(value):
        tokens.append(('', ''.join(value)))
    return tokens


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
        prn(1, '[{}] doc'.format(func.__name__))
        prn(1, '---')
        prn(1, func.__doc__)
        prn(1, '---')

    sys.exit(1)


def pfx_proper(pfxstr):
    'turn a single pfx-string into a well-formatted pfx'
    try:
        # support shorthands like 10/8, and use a /32 by default
        if '/' not in pfxstr:
            prefix = '{}/32'.format(pfxstr)
        elif pfxstr.endswith('/'):
            prefix = '{}32'.format(pfxstr)
        else:
            prefix = pfxstr

        addr, msk = prefix.split('/', 1)
        addr = '.'.join('{}.0.0.0'.format(addr).split('.')[0:4])
    except Exception as e:
        raise IpfError('cannot turn {!r} into a valid prefix'.format(pfxstr))

    return '{}/{}'.format(addr, msk)

def pfx_fromival(uint, numh):
    'turn a proper (start uint, num_hosts)-tuple into a pfx'
    # proper means uint is a this-network address and
    # num_hosts is a power of two (<= 2**32)
    mask = 2**32 - numh
    plen = 32 - int(math.log(numh) / math.log(2))
    uint = uint & mask
    d1 = (uint // 16777216)  & 0x000000FF
    d2 = (uint // 65536) & 0x000000FF
    d3 = (uint // 256) & 0x000000FF
    d4 = uint & 0x000000FF
    return '{}.{}.{}.{}/{}'.format(d1,d2,d3,d4,plen)

def pfx_toival(pfx):
    'turn properly formatted pfx into (start uint, num_hosts) tuple'
    x = list(map(int, re.split('\.|/', pfx)))
    uint = x[0] * 16777216 + x[1] * 65536 + x[2] * 256 + x[3]
    numh = 2**(32-x[4])
    return (uint & (2**32 - numh), numh)

def ival_combine(x, y):
    'return combined, None if possible, else x, y'
    if y is None:
        return (x, y)
    if x is None:
        return (y, x)

    if x[1] == y[1]:
        if sum(x) == y[0]:    #adjacent, equal length intervals
            return (x[0], x[1] + y[1]), None
        if sum(y) == x[0]:    #adjacent, equal length intervals
            return (y[0], x[1] + y[1]), None

    if x[0] <= y[0] and sum(y) <= sum(x):  # y lies in x
        return (x, None)
    if y[0] <= x[0] and sum(x) <= sum(y):  # x lies in y
        return (y, None)

    return (x, y)

def pfx_summary(pfxlst):
    'remove redundancy from a list of (im)properly formatted pfx-strings'
    # blatant disregard for ipv6
    heap = []
    for pfx in map(pfx_proper, pfxlst):  # properly formatted pfxs
        x = list(map(int, re.split('\.|/', pfx)))
        uint = x[0] * 16777216 + x[1] * 65536 + x[2] * 256 + x[3]
        numh = 2**(32-x[4])
        mask = 2**32 - numh
        heap.append((uint & mask, numh))

    # reverse since this sorts first on uint, then on length in ascending order
    heap = list(reversed(sorted(heap)))

    # reduce heap to minimum amount of ranges/intervals
    rv = []
    while len(heap):
        x = heap.pop()
        y = heap.pop() if len(heap) else None
        if y:
            x, y = ival_combine(x, y)  # y is None when x combines x+y
            if y:
                heap.append(y)  # push back for later combine attempt
            else:
                heap.append(x)  # combined range back on heap
                continue        # and start over

        y = rv.pop() if len(rv) else None
        if y:
            x, y = ival_combine(x, y) # y is None when x combines x+y
            if y:
                rv.append(y)  # could not combine, both goto rv
                rv.append(x)  # make sure to keep rv ordering intact
            else:
                heap.append(x)  # combined range back on heap

        else:
            rv.append(x)

    return [pfx_fromival(*x) for x in rv if x]

def pfx_summary_org(pfxlst):
    'remove redundancy from a list of (im)properly formatted pfx-strings'
    # blatant disregard for ipv6
    rv, heap = [], []
    for pfx in map(pfx_proper, pfxlst):  # properly formatted pfxs
        x = list(map(int, re.split('\.|/', pfx)))
        uint = x[0] * 16777216 + x[1] * 65536 + x[2] * 256 + x[3]
        numh = 2**(32-x[4])
        mask = 2**32 - numh
        heap.append((uint & mask, numh))

    # reverse since this sorts first on uint, then on length in ascending order
    heap = list(reversed(sorted(heap)))

    # absorb/join or keep adjacent (start, length)-intervals
    while len(heap):
        x = heap.pop()
        if len(heap):
            y = heap.pop()
            if x[1] == y[1] and sum(x) == y[0]:
                heap.append((x[0], x[1] + y[1]))  # x joins y
            elif x[0] <= y[0] and sum(y) <= sum(x):
                heap.append(x)                    # x absorbs y
            else:
                heap.append(y)                    # y may absorb/join next one

        if len(rv):
            x, y = rv.pop(), x
            if x[1] == y[1] and sum(x) == y[0]:
                rv.append((x[0], x[1] + y[1]))  # x joins y
            elif x[0] <= y[0] and sum(y) <= sum(x):
                rv.append(x)                    # x absorbs y
            else:
                rv.append(x)
                rv.append(y)                    # y may absorb/join next one

        else:
            rv.append(x)         # no joy, x in final result

    return [pfx_fromival(*x) for x in rv]


def str2list(a_string):
    'split a string into a list of constituents'
    try:
        return [x for x in re.split(' |,', a_string) if len(x)]
    except (TypeError, ValueError):
        raise ValueError('{!r} doesnt look like a string'.format(a_string))
