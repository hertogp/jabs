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
        raise ValueError('cannot turn {!r} into a valid prefix'.format(pfxstr))

    return '{}/{}'.format(addr, msk)

def pfx_network(pfxstr):
    'turn a single pfx-string into a well-formatted network-pfx'
    try:
        netpfx = pfx_fromival(pfx_toivalnetwork(pfxstr))
    except Exception as e:
        raise ValueError('cannot turn {!r} into a valid prefix'.format(pfxstr))

    return netpfx

def pfx_broadcast(pfxstr):
    'turn a single pfx-string into a well-formatted broadcast-pfx'
    try:
        netpfx = pfx_fromival(pfx_toivalbcast(pfxstr))
    except Exception as e:
        raise ValueError('cannot turn {!r} into a valid prefix'.format(pfxstr))

    return netpfx

def pfx_hosts(pfxstr):
    'iterator across valid ip nrs in range of pfxstr, start with host-pfx'
    uint, numh = pfx_toival(pfxstr)
    umax, numh = pfx_toivalbcast(pfxstr)
    print('hosts range', uint, umax, '->', list(range(uint, umax+1)))
    for num in range(uint, umax+1):
        yield pfx_fromival((num, 1))

def pfx_fromival(ival):
    'turn a (host-uint, num_hosts)-tuple into a pfx'
    # donot mask host-uint to this network address
    uint, numh = ival
    plen = 32 - int(math.log(numh) / math.log(2))
    d1 = (uint // 16777216)  & 0x000000FF
    d2 = (uint // 65536) & 0x000000FF
    d3 = (uint // 256) & 0x000000FF
    d4 = uint & 0x000000FF
    return '{}.{}.{}.{}/{}'.format(d1,d2,d3,d4,plen)

def pfxs_fromival(ival):
    'turn a (host-uint, num_hosts)-tuple into a list of net-pfx-s'
    # ival[1] is number of hosts and must always be a power of 2 (!)
    # *-----:-----| -> start == network address -> result = 1 net pfx
    # |-----:-----* -> start == bcast address -> result = 1 host pfx
    # |---*-:-----| -> start inside left half -> result = 1 net pfx + recurse
    # |-----:--*--| -> start inside right half -> result = recurse

    uint, numh = ival
    half = int(numh//2)
    plen = 32 - int(math.log(numh) / math.log(2))
    mask = 2**32 - numh
    imsk = (2**32 - 1) ^ mask
    nint = uint & mask           # this network
    bint = uint | imsk           # broadcast
    mint = nint + half           # start of upper half

    print('pfx', pfx_fromival(ival))
    print('- network', pfx_fromival((nint, numh)))
    print('- bcast  ', pfx_fromival((bint, numh)))
    print('- upperh ', pfx_fromival((mint, numh)))

    rv = []
    if plen == 32:                             # single address
        rv.append(pfx_fromival(ival))
    elif uint == nint:                         # aligned on start of range
        rv.append(pfx_fromival(ival))
    elif uint == bint:                         # aligned on bcast address
        rv.append(pfx_fromival((uint, 1)))
    elif uint == mint:                         # aligned on start of upper half
        rv.append(pfx_fromival((uint, half)))
    elif uint < mint:                          # inside left half
        rv.append(pfx_fromival((mint, half)))  # - add upper half
        rv.extend(pfxs_fromival((uint, half))) # - recurse
    else:                                      # inside right half
        rv.extend(pfxs_fromival((uint, half))) # - recurse

    return rv



def pfx_toival(pfx):
    'turn (im)properly formatted pfx into (host-uint, num_hosts) tuple'
    # donot mask to this network address, use toivalnetwork for that
    x = list(map(int, re.split('\.|/', pfx_proper(pfx))))
    uint = x[0] * 16777216 + x[1] * 65536 + x[2] * 256 + x[3]
    numh = 2**(32-x[4])
    return (uint, numh)

def pfx_toivalnetwork(pfx):
    'turn (im)properly formatted pfx into (network-uint, num_hosts) tuple'
    x = list(map(int, re.split('\.|/', pfx_proper(pfx))))
    uint = x[0] * 16777216 + x[1] * 65536 + x[2] * 256 + x[3]
    numh = 2**(32-x[4])
    return (uint & (2**32 - numh), numh)

def pfx_toivalbcast(pfx):
    'turn (im)properly formatted pfx into (bcast-uint, num_hosts) tuple'
    x = list(map(int, re.split('\.|/', pfx_proper(pfx))))
    uint = x[0] * 16777216 + x[1] * 65536 + x[2] * 256 + x[3]
    numh = 2**(32-x[4])
    invmask = (2**32 -1) ^ (2**32 - numh)
    return (uint | invmask, numh)


def pfx_summary(pfxlst):
    'summarize a list of host-prefixes into minimum set of network-prefixes'
    # blatant disregard for ipv6
    heap = []
    for pfx in pfxlst:
        heap.append(pfx_toival(pfx))

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

    # intervals need to be aligned on power of 2 intervals, so a given
    # single interval might yield multiple network prefixes
    # (s, l) -> 
    #
    return [pfx_fromival(x) for x in rv if x]

def ival_combine(x, y):
    'return (combined, None) if possible, else (x, y)'
    dbg = False
    if y is None:
        return (x, y)
    if x is None:
        return (y, x)
    if dbg: print('combine:', pfx_fromival(x), pfx_fromival(y))
    if x[1] == y[1]:
        # equal length intervals that may be adjacent
        if sum(x) == y[0]:  # x left of y and adjacent
            xy = pfx_toival(pfx_fromival((x[0], 2*x[1])))
            if dbg: print('x|y ->', 'x', x, 'y', y, 'xy', xy, '->', pfx_fromival(xy))
            return (x[0], 2 * x[1]), None
        if sum(y) == x[0]:  # y left of x and adjacent
            yx = (y[0], 2 * y[1])
            if dbg: print('y|x ->', 'y', y, 'x', x, 'yx', yx, '->', pfx_fromival(yx))
            return (y[0], 2 * y[1]), None
        if sum(x) == sum(y): # x == y, they're the same
            if dbg: print('x == y')
            return (x, None)

    # unequal lengths or non-adjacent intervals
    if x[0] <= y[0] and sum(y) <= sum(x):  # y lies in x
        if dbg: print('y in x')
        return (x, None)
    if y[0] <= x[0] and sum(x) <= sum(y):  # x lies in y
        if dbg: print('x in y')
        return (y, None)

    if dbg: print('no joy')
    return (x, y)  # no joy

def pp_fromstr(ppstr):
    'turn port/proto into 0.proto.port1.port2/32 prefix'
    pass

def pp_fromint(uint):
    'turn port, proto into 0.proto.port1.port2 address'
    proto = (uint // 65536) & 0xff
    port = uint & 0xffff
    return (port, proto)

def ports_fromppfx(ppfx):
    '0.d1.d2.d3/len -> port-port/proto, where proto=d1, port=d2*256+d3'
    ppfx = ppfx if '/' in ppfx else ppfx + '/32'  # ensure a mask
    x = list(map(int, re.split('\.|/', ppfx)))
    proto = x[1]
    port = x[2]*256 + x[3]
    nports = 2**(32-x[4])
    if nports > 1:
        rv = '{}-{}/{}'.format(port, port+nports, proto)
    else:
        rv = '{}/{}'.format(port, proto)

def ports_toppfx(portstr):
    'a-b/c -> shortest list of [ppfx-s] possible'
    if '/' not in portstr:
        raise ValueError('{} is missing protocol'.format(portstr))
    x = re.split('-|/', portstr)
    if not len(x) in (2,3):
        raise ValueError('{} is malformed'.format(portstr))
    start, stop, proto = (x[0], x[1], x[2]) if len(x) == 3 else (x[0], x[0], x[1])
    start = int(start)
    stop = int(stop)
    rv = []
    for y in range(start, stop+1):
        p1 = (y // 256) & 0xff
        p2 = y & 0xff
        rv.append('0.{}.{}.{}/32'.format(proto, p1, p2))

    return rv
# 80/tcp -> 80, 6 -> 0.6.0.80/32
#

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

    return [pfx_fromival(x) for x in rv]


def str2list(a_string):
    'split a string into a list of constituents'
    try:
        return [x for x in re.split(' |,', a_string) if len(x)]
    except (TypeError, ValueError):
        raise ValueError('{!r} doesnt look like a string'.format(a_string))

if __name__ == '__main__':
    # seems to be comined to 1.1.1.248/30?
    pfx = '1.1.1.128/24'
    print(pfx, 'ival', pfx_toival(pfx), 'ivalnet', pfx_toivalnetwork(pfx),
          'ivalbcast', pfx_toivalbcast(pfx), 'hosts', list(pfx_hosts(pfx)))
    print(pfx, pfxs_fromival(pfx_toival(pfx)))
