#!/usr/bin/env python3
'''
ipf - ip filter

  ipf allows for on src,dst,port,proto combinations in e.g. log entries
'''

import os
import sys
import re
import math
import json

import pandas as pd
import numpy as np
import pytricia as pt

import utils as ut

#-- helpers
# def load_csv(fname):
#     'load a csv into a df and sanitize column names'
#     # raises OSError or IOError is file is unreadable
#     fname = fname if os.path.isfile(fname) else '{}.csv'.format(fname)
#     df = pd.read_csv(fname)

#     # sanitize columns names
#     df.columns = df.columns.str.replace(' ', '_')
#     df.columns = df.columns.str.lower()

#     return df



class IpfError(Exception):
    pass


class Ip4Proto(object):
    'helper to translate strings to port,protocol nrs'
    ip4_proto_json = 'dta/ip4-protocols.json'
    ip4_services_json = 'dta/ip4-services.json'

    def __init__(self, proto_json=None, services_json=None):
        self._num_toname = {}       # e.g. 6 -> 'tcp'
        self._num_todesc = {}       # e.g. 6 -> 'Transmission Control'
        self._name_tonum = {}       # e.e. 'tcp' -> 6
        self._service_toports = {}  # e.g https -> ['443/tcp', '443/udp']
        self._port_toservice = {}   # 'port/proto'     -> ip4-service-name


        if proto_json:
            self.load_protos(proto_json)
        if services_json:
            self.load_services(services_json)

    def load_protos(self, filename):
        'read json encoded ip4-protocol information'
        # {'6': ['tcp', 'Transmission Control'], ..}

        try:
            with open(filename, 'r') as fh:
                dct = json.load(fh)
        except (OSError, IOError) as e:
            raise IOError('Cannot read {!r}: {!r}'.format(filename, e))

        for num, (name, descr) in dct.items():
            num = int(num)

        self._num_toname = dict((int(k), v[0].lower()) for k, v in dct.items())
        self._num_todesc = dict((int(k), v[1]) for k, v in dct.items())
        self._name_tonum = dict((v[0].lower(), int(k)) for k, v in dct.items())

        return self

    def load_services(self, filename):
        'load ipv4-services from file created by updta.py'
        # {"995/udp": "pop3s", ..}

        try:
            with open(filename, 'r') as fh:
                dct = json.load(fh)
        except (OSError, IOError) as e:
            raise IOError('cannot read {!r}: {!r}'.format(filename, e))

        self._port_toservice = dct
        self._service_toports.clear()
        for port, service in dct.items():
            self._service_toports.setdefault(service, []).append(port)

        return self

    def portstr_topp(self, portstr):
        'turn portstr into protocol numbers, e.g. "80/tcp" -> (80, 6)'
        try:
            parts = portstr.lower().split('/')
            assert len(parts) == 2
            portnr = int(parts[0])
            protonr = self._name_tonum[parts[1]]

        except (IndexError, ValueError):
            raise ValueError('{} invalid port/protocol'.format(portstr))

        return (portnr, protonr)

    def portstr_bypp(self, pp_nrs):
        try:
            port, proto = pp_nrs
        except ValueError:
            raise ValueError('{!r} not a (port, proto)-tuple'.format(pp_nrs))
        if 0 < port > 65535:
            raise ValueError("'{}' invalid IP4 port number".format(port))
        if 0 < proto > 255:
            raise ValueError("'{}' invalid IP4 protocol number".format(proto))
        return '{}/{}'.format(port, self._num_toname.get(proto, '?'))

    def portstr_touints(self, portstr):
        'turn port-port/proto into list of uints (proto << 16 + port nr)'
        if '/' not in portstr:
            raise ValueError('{} is missing protocol'.format(portstr))
        x = re.split('-|/', portstr)

        if not len(x) in (2,3):
            raise ValueError('{!r} is malformed'.format(portstr))
        if x[-1].lower() not in self._name_tonum:
            raise ValueError('{!r} has unknown protocol'.format(portstr))

        try:
            proto = self._name_tonum[x[-1].lower()]
            start = int(x[0])
            stop = int(x[1]) if len(x) == 3 else start
            rv = [ proto * 65536 + x for x in range(start, stop+1)]
        except ValueError as e:
            raise ValueError('{!r} not valid portstring'.format(portstr))

        return rv

    def portstr_byuints(self, uints):
        'turn list of uints into portstrings'
        # [x1,x2,..)] -> n-m/proto, ..
        if len(uints) < 1:
            raise ValueError('{!r} not a valid uints list'.format(uints))
        uints = sorted(uints)     # order lowest to highest
        pival = [[uints[0], 1]]   # start with interval of length 1
        for uint in uints[1:]:
            if sum(pival[-1]) == uint:  # add consecutive uints to interval
                pival[-1][1] += 1
            else:
                pival.append([uint, 1]) # else start new interval

        rv = []
        for uint, nump in pival:
            proto = self._num_toname.get((uint // 65536) & 0xFF, '?')
            port = uint & 0xFFFF
            if nump > 1:
                rv.append('{}-{}/{}'.format(port,port+nump-1,proto))
            else:
                rv.append('{}/{}'.format(port, proto))

        return rv




        return summ


    def service_toports(self, service):
        'service name to its known portstrings, eg http->[80/tcp, 80/udp]'
        return self._service_toports.get(service.lower(), [])

    def service_topps(self, service):
        'service name to known port,proto-tuples list'
        # https -> [443,6),(443,17)]'
        return [self.portstr_topp(x) for x in self.service_toports(service)]

    def set_service(self, service, portstrings):
        'set known ports for a service, eg http->[80/tcp]'
        # TODO: check validity, remove spaces etc ...
        self._service_toports[service.lower()] = [x.lower() for x in
                                                  portstrings]

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

            # propagate rid to more specifics
            for kid in tbl.children(pfx):  # propagate rid to the more specifics
                tbl[kid].add(rid)

            # adopt rids matched by less specific parent (if any)
            parent = tbl.parent(pfx)
            if parent:
                tbl[pfx] = tbl[pfx].union(tbl[parent])

        except ValueError as e:
            print('oopsie', pfx, repr(e))
            sys.exit(1)

    def _set_port(self, rid, port):
        'set ports on a some rule id'
        # valid port names include:
        # port/proto      = single port like 80/tcp
        # port-port/proto = port range like 80-88/tcp
        # any/proto       = port range like any/tcp == 0-65535/tcp
        # any             = any port on any protocol == 0-65535/0-255
        # 
        # portpfxs = self.ip4.piv_touints(portstr)
        # for pvx in self.portpfxs:
        #     self._set_pfx(rid, self._piv, pvx)

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
            self._set_pfx(rid, self._src, pfx_proper(pfx))

        for pfx in str2list(dsts):
            self._set_pfx(rid, self._dst, pfx_proper(pfx))

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
            lst[0] = pfx_summary(lst[0])
            lst[1] = pfx_summary(lst[1])

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

    ipp = Ip4Proto(proto_json='dta/ip4-protocols.json',
                   services_json = 'dta/ip4-services.json')
    portstr = '0-14/tcp'
    uints = ipp.portstr_touints(portstr)
    ivals = [(x, 1) for x in uints]
    print('portstr', portstr)
    print('uints  ', uints)
    print('ivals  ', ivals)
    print('summary', ut.ival_summary(ivals))
    print('pfxsumm', [ut.ival2pfx(x) for x in ut.ival_summary(ivals)])
    print('range  ', ipp.portstr_byuints(uints))

