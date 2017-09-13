#!/usr/bin/env python3
'''
ipf - ip filter

  ipf allows for on src,dst,port,proto combinations in e.g. log entries
'''

import os
import sys
import re
import math

import pandas as pd
import numpy as np
import pytricia as pt

#-- helpers
def load_csv(fname):
    'load a csv into a df and sanitize column names'
    # raises OSError or IOError is file is unreadable
    fname = fname if os.path.isfile(fname) else '{}.csv'.format(fname)
    df = pd.read_csv(fname)

    # sanitize columns names
    df.columns = df.columns.str.replace(' ', '_')
    df.columns = df.columns.str.lower()

    return df

def str2list(a_string):
    'split a string into a list of constituents'
    try:
        return [x for x in re.split(' |,', a_string) if len(x)]
    except (TypeError, ValueError):
        raise ValueError('{!r} doesnt look like a string'.format(a_string))

def pfx_fromstr(pfxstr):
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

def ival_topfx(uint, numh):
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

def ival_frompfx(pfx):
    'turn properly formatted pfx into (start uint, num_hosts) tuple'
    x = list(map(int, re.split('\.|/', pfx)))
    uint = x[0] * 16777216 + x[1] * 65536 + x[2] * 256 + x[3]
    numh = 2**(32-x[4])
    return (uint & (2**32 - numh), numh)

def summarize_pfxs(pfxlst):
    'remove redundancy from a list of (im)properly formatted pfx-strings'
    # blatant disregard for ipv6
    rv, heap = [], []
    for pfx in map(pfx_fromstr, pfxlst):  # properly formatted pfxs
        x = list(map(int, re.split('\.|/', pfx)))
        uint = x[0] * 16777216 + x[1] * 65536 + x[2] * 256 + x[3]
        numh = 2**(32-x[4])
        mask = 2**32 - numh
        heap.append((uint & mask, numh))

    heap = list(reversed(sorted(heap)))
    # absorb/join or keep adjacent (start, length)-intervals
    while len(heap):
        x = heap.pop()
        if len(heap) == 0:
            rv.append(ival_topfx(*x))
            break
        y = heap.pop()
        if x[1] == y[1] and sum(x) == y[0]:
            heap.append((x[0], x[1] + y[1]))  # x joins y
        elif x[0] <= y[0] and sum(y) <= sum(x):
            heap.append(x)                    # x absorbs y
        else:
            rv.append(ival_topfx(*x))         # no joy, x in final result
            heap.append(y)                    # y may absorb/join next one
    return rv

class IpfError(Exception):
    pass


class Ip4Proto(object):
    'helper to translate strings to port,protocol nrs'
    # wraps:
    # - dta/service-names-port-numbers.csv and
    # - dta/service-names-port-numbers.csv
    def __init__(self):

        # IPv4 IP Protocol numbers
        self._n2p = {}  # number -> protocol
        self._n2d = {}  # number -> description
        self._p2n = {}  # protocol -> number

        # IPv4 Services
        self._s2pp = {}  # name -> [(portnr, protocolnr), ..]
        self._pp2s = {}  # (port,protocol) -> keyword

        self.lightweight()

    def lightweight(self):
        'fill the dicts with some basic information'
        for n,p,d in [( 1, 'icmp', 'internet control message'),
                      ( 6, 'tcp', 'transmission control '),
                      ( 17,'udp', 'user datagram '),
                      ( 27,'rdp', 'reliable data protocol '),
                      ( 46,'rsvp', 'reservation protocol '),
                      ( 47,'gre', 'generic routing encapsulation '),
                      ( 50,'esp', 'encap security payload'),
                      ( 51,'ah', 'authentication header'),
                      ( 56,'tlsp', 'transport layer security protocol '),
                      ( 58,'ipv6-icmp', 'icmp for ipv6'),
                      ( 88,'eigrp', 'enhanced igrp'),
                      ( 89,'ospfigp', 'ospfigp '),
                      ( 92,'mtp', 'multicast transport protocol '),
                      ( 94,'ipip', 'ip-within-ip encapsulation protocol '),
                      ( 98,'encap', 'encapsulation header '),
                      ( 112,'vrrp', 'virtual router redundancy protocol '),
                      ( 115,'l2tp', 'layer two tunneling protocol '),
                      ( 132,'sctp', 'stream control transmission protocol '),
                      ]:
            self._n2p[n] = p
            self._n2d[n] = d
            self._p2n[p] = n

        for s, p in [('https', [(443, 6), (443, 17)]),
                     ('http', [(80, 6), (80, 17)]),
                     ('snmp', [(161, 17)]),
                     ('smtp', [(25, 6)]),
                     ('dns', [(53, 6), (53, 17)]),
                     ]:
            self._s2pp[s] = p
            for pp in p:
                self._pp2s[pp] = s


    def load_files(self, fproto=None, fservice=None):

        fproto = fproto if fproto else 'dta/ip4-protocols.csv'
        fservice = fservice if fservice else 'dta/ip4-services.csv'
        self.load_protos(fproto)
        self.load_services(fservice)

        return self

    def load_protos(self, fname):
        'load ipv4r-protocol nrs from file created by updta.py'
        # clear all dicts
        self._n2p.clear()    # num -> proto name
        self._n2d.clear()    # num -> description
        self._p2n.clear()    # proto name -> num

        try:
            df = load_csv(fname)
        except (OSError, IOError) as e:
            raise IpfError('err loading info: {}: {}'.format(fname, repr(e)))
            sys.exit(1)
        except Exception as e:
            raise IpfError('runtime error: {}'.format(e))

        # assume properly formatted csv-file
        df = df.set_index('decimal')
        self._n2p = df['keyword'].to_dict()
        self._n2d = df['protocol'].to_dict()
        self._p2n = dict((v, k) for k, v in self._n2p.items())

        return self

    def load_services(self, fname):
        'load ipv4-services from file created by updta.py'
        self._s2pp.clear()
        self._pp2s.clear()

        try:
            df = load_csv(fname)
        except (OSError, IOError) as e:
            raise IpfError('err loading info: {}: {}'.format(fname, repr(e)))
            sys.exit(1)
        except Exception as e:
            raise IpfError('runtime error: {}'.format(e))
            sys.exit(1)

        # assume properly formatted csv-file
        df.columns = ['port', 'proto', 'service']
        df['proto'] = df['proto'].map(self._p2n) # turn proto name into number
        df['pp'] = df[['port', 'proto']].apply(lambda g: tuple(x for x in g), axis=1)
        # _pp2s maps (port, protonr) -> service name
        self._pp2s = dict(zip(df['pp'], df['service']))
        # _s2pp maps service -> [(port, proto), ...]
        for k, v in self._pp2s.items():
            self._s2pp.setdefault(v, []).append(k)

        return self

    def proto_toname(self, num):
        if 0 <= num <= 255:
            return self._n2p.get(num, 'unknown')
        return 'invalid'

    def proto_byname(self, name):
        return self._p2n.get(name.lower(), -1)

    def proto_todescr(self, proto_id):
        try:
            n = int(proto_id)
            if 0 <= n <= 255:
                return self._n2d.get(n, 'no description')
            return 'invalid'
        except ValueError:
            n = self._p2n.get(proto_id, -1)
            return self._n2d.get(n, 'no description')

    def pp_byport(self, portstr):
        'turn string 80/tcp into (port, proto_nr), like (80, 6)'
        try:
            parts = portstr.split('/', 1)
            if len(parts) != 2:
                return (-1, -1)
            proto = self._p2n.get(parts[1].lower(), -1)
            port = int(parts[0])
            if 0 <= port <= 65535:
                return (port, proto)
            return (-1, proto)
        except ValueError:
            return (-1, proto)
        except AttributeError:
            return (-1, -1)  # wrong type of argument

    def pp_toport(self, port, proto):
        'based on port, proto numbers return port/protocol string'
        port = -1 if not (0 <= port <= 65535) else port
        if 0 <= proto <= 255:
            return '{}/{}'.format(port, self._n2p.get(proto, 'unknown'))
        return '{}/invalid'.format(port)

    def pp_byservice(self, service):
        'based on service name like https, return [(443, 6), (443, 17)]'
        return self._s2pp.get(service.lower(), [(-1, -1)])

    def pp_toservice(self, port, proto):
        'based on (port, proto)-numbers, return service name like https'
        if not (0 <= port <= 65535):
            return 'invalid'
        if not (0 <= proto <= 255):
            return 'invalid'
        return self._pp2s.get((port, proto), 'unknown')

class IpFilter(object):

    def __init__(self, pp):
        self._src = pt.PyTricia()  # pfx -> set([rid's])
        self._dst = pt.PyTricia()  # pfx -> set([rid's])
        self._pp = {}              # (port, proto) -> set([rids])
        self._act = {}             # rid -> action (True of False)
        self._tag = {}             # rid -> tag
        self.ip4 = pp              # an Ip4Protocol object

    def _set_pfx(self, rid, tbl, pfx):
        'set a prefix on some rule id in specific tbl'

        try:
            if tbl.has_key(pfx):        # find the exact prefix
                tbl[pfx].add(rid)       # add to existing prefix
            else:
                tbl[pfx] = set([rid])   # it's a new prefix

            # due to the way lookup src,dst works, we need to propagate
            # the rid to more specific matches as well.
            # needs to be sanitized when writing to csv, otherwise it'll look
            # weird when writing out a rulebase after reading it first...
            # TODO: this probably should be in a finalize() or optimize() call
            # after adding all rules, because doing this per prefix added will
            # catch more specific already present in the rulebase, but will miss
            # out on more specifics that are added later on... unless we also
            # traverse the table for less specifics and adopt their rids here as
            # well...
            #

            # donate rid to more specifics currently in the rulebase
            for kid in tbl.children(pfx):  # propagate rid to the more specifics
                tbl[kid].add(rid)

            # TODO: adopt rules matched by less specifics
            parent = tbl.parent(pfx)
            if parent:
                tbl[pfx] = tbl[pfx].union(tbl[parent])

        except ValueError as e:
            print('oopsie', pfx, repr(e))
            sys.exit(1)

    def _set_port(self, rid, port):
        'set ports on a some rule id'
        pp = self.ip4.pp_byport(port)  # gets (port, protocol)
        tbl = self._pp.get(pp, None)
        if tbl is None:
            self._pp[pp] = set([rid])
        else:
            tbl.add(rid)


    def _rids(self, src=None, dst=None, pp=None):
        'get rids (set of rule id-s) hit by some src,dst,pp combi'
        # src, dst, pp  are all optional, if none given return all rids
        # p is (port, proto)-tuple
        try:
            arr = []
            if dst:
                arr.append(self._dst[dst])
            if pp:
                arr.append(self._pp[pp])
            if src:
                arr.append(self._src[src])
            if len(arr):
                return set.intersection(*arr)
            else:
                return set(self._act.keys())

        except KeyError:
            return set([])   # a required table lookup came up empty, so no joy

    def add(self, rid, srcs, dsts, ports, action='', tag=''):
        'add a new rule or just add src and/or dst to an existing rule'
        for pfx in str2list(srcs):
            self._set_pfx(rid, self._src, pfx_fromstr(pfx))

        for pfx in str2list(dsts):
            self._set_pfx(rid, self._dst, pfx_fromstr(pfx))

        for port in str2list(ports):
            self._set_port(rid, port)

        fmt = 'warn: {}, {} swaps {!r} for new {!r}'

        # always set an action for rid: default to False
        new = action.lower() == 'permit' if action else self._act.get(rid, False)
        old = self._act.setdefault(rid, new)
        if old != new:
            self._act[rid] = new
            print(fmt.format(rid, 'permit', old, new))

        # only set tag if given, warn if an older, other value exists
        new = tag if tag else None
        old = self._tag.setdefault(rid, new) if new else new
        if old != new:
            self._tag[rid] = tag
            print(fmt.format(rid, 'tag', old, new))

        return True

    def clear(self):
        'clear all the rules'
        self._src = pt.PyTricia()  # pfx -> set([rid's])
        self._dst = pt.PyTricia()  # pfx -> set([rid's])
        self._pp = {}              # (port, proto) -> set([rids])
        self._act = {}             # rid -> action (True of False)
        self._tag = {}             # rid -> tag

    def match(self, src, dst, pp):
        'return True (allow), False (deny), None (no match)'
        # try to return in the least amount of lookups
        try:
            rids = self._dst[dst]
            rids = rids.intersection(self._pp[pp])
            rids = rids.intersection(self._src[src])
            return self._act.get(min(rids), False)
        except (KeyError, ValueError):
            return None  # empty set or a failed key lookup == no Match -> None



    def matchp(self, src, dst, port):
        'same as match, but port is "port/proto"'
        return self.match(src, dst, self.ip4.pp_byport(port))

    def first(self, src, dst, pp):
        'return first rule hit, None otherwise'
        rids = self._rids(src, dst, pp)
        if len(rids):
            return min(rids)
        return None

    def find(self, src, dst, pp):
        'return set of rules hit by this session'
        return self._rids(src, dst, pp)

    def rules(self):
        'reconstruct the rules in a dict'
        rules = {}  # {rule_id} -> [ [srcs], [dsts], [ports], action, tag ]
        for pfx in self._src.keys():
            for r in self._src[pfx]:
                rules.setdefault(r, [[],[],[],'',''])[0].append(pfx)
        for pfx in self._dst.keys():
            for r in self._dst[pfx]:
                rules.setdefault(r, [[],[],[],'',''])[1].append(pfx)
        for pp, rids in self._pp.items():
            for r in rids:
                rule = rules.setdefault(r, [[],[],[], '', ''])
                rule[2].append(self.ip4.pp_toport(*pp))
        for r, act in self._act.items():
            rule = rules.setdefault(r, [[],[],[],'',''])
            rule[3] = 'permit' if act else 'deny'
        for r, tag in self._tag.items():
            rule = rules.setdefault(r, [[],[],[],'',''])
            rule[4] = tag

        # sanitize more specifics in a src/dst list of a rule
        for r, lst in rules.items():
            lst[0] = summarize_pfxs(lst[0])
            lst[1] = summarize_pfxs(lst[1])

        return rules

    def lines(self, csv=False):
        'return filter as lines for printing'
        fmt = '{},{},{},{},{},{}' if csv else '{:<5} {:21} {:21} {:16} {:7} {}'
        rules = sorted(self.rules().items())
        lines = [fmt.format('rule', 'src', 'dst', 'dport', 'act', 'tag')]
        for nr, (srcs, dsts, ports, act, tag) in rules:
            maxl = max([len(srcs), len(dsts), len(ports)])
            for lnr in range(0, maxl):
                src = srcs[lnr] if lnr < len(srcs) else ''
                dst = dsts[lnr] if lnr < len(dsts) else ''
                prt = ports[lnr] if lnr < len(ports) else ''
                act = act if lnr == 0 else ''
                tag = tag if lnr == 0 else ''
                lines.append(fmt.format(nr, src, dst, prt, act, tag))
                nr = ''  # only list rule nr on first line
        return lines

    def to_csv(self, fname):
        'write ruleset to csv-file'
        try:
            with open(fname, 'w') as outf:
                for line in self.lines(csv=True):
                    print(line, file=outf)
        except (IOError, OSError) as e:
            fmt = 'error saving {!}: {!r}'
            raise IpfError(fmt.format(fname, e))
        return True


    def from_csv(self, fname):
        'read ruleset from csv-file'
        df = load_csv(fname)
        df['rule'].fillna(method='ffill', inplace=True)
        df.fillna(value='', inplace=True)
        df['rule'] = df['rule'].astype(int)
        for idx, row in df.iterrows():
            self.add(*list(row))
        print(df)


if __name__ == '__main__':

    print('-'*30, 'creating rules in code')
    ipf = IpFilter(Ip4Proto().load_files())
    ipf.add(9, '10.11/24/8, 10.10/24', '11/8', '23/udp, 35/tcp, 65535/sctp', 'permit', 'http')
    ipf.add(2, '10/8', '11/8', '80/tcp', 'permit', 'http')
    ipf.add(3, '11/8', '12/8', '80/tcp', 'permit', 'http')
    ipf.add(3, '11/8', '13/8', '88/tcp', 'permit', 'kerberos')
    ipf.add(2, '10/8', '19/8', '80/tcp')
    ipf.add(2, '14/8', '19/8', '80/tcp')
    ipf.add(2, '15/8', '19/8', '80/tcp')
    ipf.add(2, '15/8', '192.192.192.192', '81/tcp')
    ipf.add(4, '15/8', '192/8', '81/tcp')

    print()
    if ipf.to_csv('scr/rules.csv'):
        print('saved to file')

    print('-'*30, 'current rules')
    for line in ipf.lines(csv=False):
        print(line)

    print('15/8 -> 192.192.192.192 hits rules', ipf.find('15.0.0.0/8',
                                                         '192.192.192.192', None))
    print('15/8', ipf._src['15.0.0.0/8'])
    print('192', ipf._dst['192.192.192.192'])
    print('15/8', ipf._src['15.0.0.0/8'])
    print('192', ipf._dst['192.192.192.192'])

    for s,d,p in [('10.10.10.1', '11.11.11.1', (23, 17)),
                  ('15.15.15.1', '19.19.19.1', (80, 6)),
                  ('15.15.15.15', '192.0.0.1', (81, 6))]:
        print(s,d,p,'->', ipf.match(s,d,p))

    print()
    print('-'*30, 'clear rules and reading from file')
    ipf.clear()
    print('reading from file')
    ipf.from_csv('scr/rules.csv')

    print('-'*30)
    print('rules created from csv-file')
    for line in ipf.lines(csv=False):
        print(line)

    print('15/8 -> 192.192.192.192 hits rules', ipf.find('15.0.0.0/8',
                                                         '192.192.192.192', None))
    print('15/8', ipf._src['15.0.0.0/8'])
    print('192', ipf._dst['192.192.192.192'])

    for s,d,p in [('10.10.10.1', '11.11.11.1', (23, 17)),
                  ('15.15.15.1', '19.19.19.1', (80, 6)),
                  ('15.15.15.15', '192.0.0.1', (81, 6))]:
        print(s,d,p,'->', ipf.match(s,d,p))
