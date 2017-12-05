'''
ilf core utilities
'''

import sys
import re
import math
from itertools import chain

import pytricia as pt

from .numbers import IP4PROTOCOLS, IP4SERVICES


# -- Helpers


def lowest_bit(num):
    bit, low = -1, (num & -num)
    if not low:
        return 0
    while(low):
        low >>= 1
        bit += 1
    return bit


def binarr(n):
    return [n >> i & 1 for i in range(n.bit_length() - 1, -1, -1)]


class Ip4Protocol(object):
    'translate between ipv4 protocol number and associated name'

    def __init__(self):
        self._num_toname = {}       # e.g. 6 -> 'tcp'
        self._num_todesc = {}       # e.g. 6 -> 'Transmission Control'
        self._name_tonum = {}       # e.e. 'tcp' -> 6

        for k, (name, desc) in IP4PROTOCOLS.items():
            self._num_toname[k] = name
            self._num_todesc[k] = desc
            self._name_tonum[name] = k  # TODO: assumes name's are unique

    def getprotobyname(self, name):
        'turn protocol name into its ip protocol number'
        err = 'invalid ipv4 protocol name: {!r}'
        rv = self._name_tonum.get(name.lower(), None)
        if rv is None:
            raise ValueError(err.format(name))
        return rv

    def getnamebyproto(self, num):
        'turn ipv4 protocol number into its name'
        err = 'invalid ipv4 protocol number {}'
        rv = self._num_toname.get(num, None)
        if rv is None:
            raise ValueError(err.format(num))
        return rv


class Ip4Service(object):
    'translate between ipv4 service name and associated portstrings'

    def __init__(self):
        self._service_toports = {}  # e.g https -> ['443/tcp', '443/udp']
        self._port_toservice = {}   # 'port/proto'     -> ip4-service-name

        for portstr, service in IP4SERVICES.items():
            self._port_toservice[portstr] = service
            self._service_toports.setdefault(service, []).append(portstr)

    def getportsbyserv(self, name):
        'translate service name (eg https) to a list of portstrings'
        rv = self._service_toports.get(name.lower(), [])
        return rv

    def getservbyport(self, portstr):
        'translate a portstring to a service name'
        rv = self._port_toservice.get(portstr.lower(), '')
        return rv

    def set_service(self, service, portstrings):
        'set known ports for a service, eg http->[80/tcp]'
        # TODO: check validity, remove spaces etc ...
        service = service.strip().lower()
        portstrings = [portstr.strip().lower() for portstr in portstrings]

        self._service_toports[service] = portstrings
        for portstr in portstrings:
            self._port_toservice[portstr] = service


class Ival(object):
    'helper class that abstracts PORTSTR or IP'
    INVALID, IP, PORTSTR = (0, 1, 2)  # types of Ival's
    TYPE = {0: 'INVALID', 1: 'IP', 2: 'PORTSTR'}
    TYPES = (INVALID, IP, PORTSTR)

    ipp = Ip4Protocol()  # ipv4 only

    def __init__(self, value=None):
        if value is None:  # init an INVALID Ival
            self.type = self.start = self.length = 0
            return

        if isinstance(value, (tuple, list)):
            if len(value) == 2:
                self.type = Ival.PORTSTR  # value = (port, protocolnr)
                port, proto = value
                err = '{!r} invalid ipv4 port and/or protocol numbers'
                try:  # ensure port, proto are ints
                    port = int(port)
                    proto = int(proto)
                except ValueError:
                    raise ValueError(err.format(value))
                if proto < 0 or proto > 255 or port < 0 or port > 2**16 - 1:
                    raise ValueError(err.format(value))
                self.start, self.length = (port + proto * 2**16, 1)
                return
            elif len(value) != 3:
                raise ValueError(err.format(value))
            # blindly accept any 3-tuple & trust caller knows what she's doing
            self.type, self.start, self.length = value
            return

        # Sooo, value must be a string
        try:
            value = value.lower().strip()
        except:
            raise ValueError('invalid Ival value {!r}'.format(value))

        if value == 'any':
            self.type, self.start, self.length = self.IP, 0, 2**32
            return

        if value == 'any/any':
            self.type, self.start, self.length = self.PORTSTR, 0, 2**32
            return

        # an IP pfx string has no letters, and a PORTSTR always does.
        is_pfx = len([x for x in value if x not in '0123456789./']) == 0

        if is_pfx:
            # must be an ip prefix string
            # since 10.10/16 means 10.10.0.0/16, socket.inet_aton is a nogo
            self.type = self.IP
            err = 'Invalid ipv4 prefix string: {!r}'
            try:
                # pfx-len defaults to /32 if absent
                x = value.split('/', 1)
                plen = 32 if len(x) == 1 else int(x[1])
                if plen < 0 or plen > 32:
                    raise ValueError(err.format(value))

                # donot allow double dots or trailing dots
                x = list(map(int, x[0].split('.')))
                if len(x) < 1 or len(x) > 4:
                    raise ValueError(err.format(value))
                elif len(x) < 4:
                    x = (x + [0, 0, 0, 0])[0:4]
                for digit in x:
                    if digit < 0 or digit > 255:
                        raise ValueError(err.format(value))

                # only after checking any digits, return 0/0 if plen is 0
                # if plen == 0:
                #     self.start = 0
                #     self.length = 2**32
                # else:
                self.length = 2**(32-plen)
                self.start = x[0]*2**24 + x[1]*2**16 + x[2]*2**8 + x[3]
                    # import socket, struct
                    # long = struct.unpack(">L", socket.inet_aton(ipstr))
                    # print(self.start, long)
                return
            except (AttributeError, ValueError):
                raise ValueError(err.format(value))

        else:
            # must be a PORTSTR
            self.type = self.PORTSTR
            err = 'invalid portstring {!r}'
            try:
                x = value.split('/')      # port(range)/proto-name
                if len(x) != 2:
                    raise ValueError(err.format(value))
                x[0:1] = x[0].split('-')  # only split port(range) on '-'
                x = [y.strip() for y in x]

                if len(x) == 1:
                    if x[0] != 'any':
                        raise ValueError(err.format(value))
                    self.start = 0
                    self.length = 2**32
                    return

                elif len(x) == 2:
                    # port/proto or any/proto
                    proto_num = self.ipp.getprotobyname(x[1])
                    if x[0] == 'any':
                        length = 2**16
                        base = 0
                    else:
                        length = 1
                        base = int(x[0])
                        if base < 0 or base > 2**16 - 1:
                            raise ValueError(err.format(value))
                    self.start = proto_num * 2**16 + base
                    self.length = length
                    return  # 0.proto.p2.p1

                elif len(x) == 3:
                    # start-stop/proto-name
                    try:
                        proto_num = self.ipp.getprotobyname(x[2])
                    except ValueError:
                        raise ValueError(err.format(value))
                    start, stop = int(x[0]), int(x[1])
                    if start > stop:
                        start, stop = stop, start
                    length = stop - start + 1
                    if start < 0 or start > 2**16 - 1:
                        raise ValueError(err.format(value))
                    if stop < 0 or stop > 2**16 - 1:
                        raise ValueError(err.format(value))
                    self.start = proto_num * 2**16 + start
                    self.length = length
                    return

            except (AttributeError, ValueError):
                # eg if portstr is not a string or int(port-part) fails
                raise ValueError(err.format(value))

    def __repr__(self):
        return '({!r}, {!r})'.format(self.TYPE[self.type], str(self))

    def __str__(self):
        if self.type == self.IP:
            if self.length == 2**32:
                return '0.0.0.0/0'  # 'any'
            elif self.length == 1:
                plen = ''
            else:
                plen = '/{}'.format(32 - int(math.log(
                    1 + self.length)//math.log(2)))

            d1 = (self.start // 2**24) & 0xFF
            d2 = (self.start // 2**16) & 0xFF
            d3 = (self.start // 2**8) & 0xFF
            d4 = (self.start) & 0xFF

            return '{}.{}.{}.{}{}'.format(d1, d2, d3, d4, plen)

        elif self.type == self.PORTSTR:
            if self.length == 2**32:
                return 'any/any'
            elif self.length == 2**16:
                ports = 'any'
            elif self.length == 1:
                ports = str(self.start & 0xFFFF)
            else:
                start = self.start & 0xFFFF
                ports = '{}-{}'.format(start, start + self.length - 1)

            proto = int((self.start // 2**16) & 0xFF)
            name = self.ipp.getnamebyproto(proto)
            return '{}/{}'.format(ports, name)

        else:
            return 'invalid'

    def __len__(self):
        return self.length

    def __contains__(self, other):
        return self.type == other.type and\
            self.start <= other.start and\
            self.start + self.length >= other.start + other.length

    def __hash__(self):
        'needed because of __eq__, donot modify obj when hashed'
        return hash(self.values())

    def __ne__(self, other):
        return self.values() != other.values()

    def __eq__(self, other):
        # max intervals (len is 2**32) are equal regardless of start value
        if self.type == other.type and self.length == 2**32:
            return other.length == self.length
        return self.values() == other.values()

    def __lt__(self, other):
        return self.values() < other.values()

    def __le__(self, other):
        'self starts to the left of other or is smaller'
        return self.values() <= other.values()

    def __gt__(self, other):
        'self starts to the right of other'
        return self.values() > other.values()

    def __ge__(self, other):
        'self starts to the right of other'
        return self.values() >= other.values()

    def __iter__(self):
        'iterate through the interval with new ivals of len=1'
        self.idx = -1
        return self

    def __next__(self):
        self.idx += 1
        if self.idx < self.length:
            return Ival((self.type, self.start + self.idx, 1))
        raise StopIteration

    def values(self, values=None):
        'get the values of the ival object'
        return (self.type, self.start, self.length)

    def is_valid(self):
        'raise ValueError if invalid, return True otherwise'
        if self.type not in self.TYPES:
            raise ValueError('Invalid Ival type {!r}'.format(self.type))
        if self.start < 0 or self.start > 2**32 - 1:
            raise ValueError('Invalid Ival start {!r}'.format(self.start))
        if self.length < 0 or self.length > 2**32 - 1:
            raise ValueError('Invalid Ival length {!r}'.format(self.length))
        return True

    def prefix(self):
        'return an new IP-typed Ival for this ival'
        ival = self.network()
        ival.type = Ival.IP
        return ival

    def network(self):
        'return new ival for the first value'
        # keeps the prefix (ival) length, only mask start if its IP
        mask = 2**32 - self.length
        start = self.start & mask if self.type == Ival.IP else self.start
        return Ival((self.type, start, self.length))

    def broadcast(self):
        'return new ival for the last value'
        # TODO: Ival('0/0').broadcast() == Ival('255.255.255.255') ??
        # should broadcast yield an address/32 or address/pfxlen ??
        imask = self.length - 1
        start = self.start | imask if self.type == Ival.IP else self.start
        return Ival((self.type, start, self.length))

    def address(self):
        'return new ival with length 1 for start value'
        return Ival((self.type, self.start, 1))

    def mask(self):
        'return the mask as quad dotted string'
        if self.type == self.IP:
            mask = 2**32 - self.length
            d1 = (mask // 2**24) & 0xFF
            d2 = (mask // 2**16) & 0xFF
            d3 = (mask // 2**8) & 0xFF
            d4 = (mask) & 0xFF
            return '{}.{}.{}.{}'.format(d1, d2, d3, d4)
        raise ValueError('type {!r} not a prefix'.format(self.TYPE[self.type]))

    def imask(self):
        'return the inverse mask as quad dotted string'
        if self.type == self.IP:
            imask = self.length - 1
            d1 = (imask // 2**24) & 0xFF
            d2 = (imask // 2**16) & 0xFF
            d3 = (imask // 2**8) & 0xFF
            d4 = (imask) & 0xFF
            return '{}.{}.{}.{}'.format(d1, d2, d3, d4)
        raise ValueError('type {!r} not a prefix'.format(self.TYPE[self.type]))

    def is_any(self):
        return self.length == 2**32  # any-interval has max length

    @classmethod
    def splice(cls, ival):
        'break up a ival into a list of prefix-like ranges'
        rv = []
        start, length = ival.start, ival.length
        maxx = start + length
        while start < maxx:
            lbit = lowest_bit(start)
            hbit = length.bit_length()
            maxlen = 2**lbit
            newlen = maxlen if length > maxlen else 2**(hbit-1)
            rv.append((start, newlen))
            start, length = start + newlen, length - newlen

        return [Ival((ival.type, x, y)) for x, y in rv]

    def as_networks(self):
        'turn this ival into a list of valid IP prefixes'
        pfxs = Ival.splice(self)
        for pfx in pfxs:
            pfx.type = Ival.IP
        return pfxs

    @classmethod
    def combine(cls, x, y):
        'if possible, return a combined ival, None otherwise'
        # PORTSTR intervals can be combined if adjacent or overlapping
        # ditto for IP intervals, plus adjacent ivals must have same length
        if y is None:
            return cls(x.values())
        if x is None:
            return cls(y.values())
        if x.type != y.type:
            return None
        if x == y:
            return cls(x.values())
        # x starts to the left of y
        x, y = (x, y) if x < y else (y, x)
        if x in y:
            return cls(y.values())
        if x.type == cls.IP and x.length != y.length:
            return None
        if x.start + x.length == y.start:
            if x.type == cls.PORTSTR or x.start % 2 == 0:
                return cls((x.type, x.start, x.length + y.length))
        if x.type == cls.PORTSTR and x.start + x.length > y.start:
            ivlen = max(x.start + x.length, y.start + y.length) - x.start
            return cls((x.type, x.start, ivlen))

        return None  # no joy

    @classmethod
    def summary(cls, ivals):
        'summarize a (heterogeneous) list of port/prefix-intervals'
        # reverse since this sorts on type, start & length in ascending order
        # originals go back on the heap, new ivals go onto rv
        heap = list(reversed(sorted(ivals)))
        rv = []
        while len(heap):
            x = heap.pop()
            y = heap.pop() if len(heap) else None
            if y:
                z = cls.combine(x, y)  # z is None if not combined
                if z:
                    heap.append(z)  # combined range back on heap
                    continue        # start again
                else:
                    heap.append(y)  # push back for later combine attempt

            y = rv.pop() if len(rv) else None
            if y:
                z = cls.combine(x, y)  # y is None when x combines x+y
                if z:
                    heap.append(z)  # combined range back on heap
                else:
                    rv.append(y)  # could not combine, both goto rv and
                    rv.append(x)  # make sure to keep rv ordering intact

            else:
                rv.append(x)

        return [Ival(i.values()) for i in rv]  # ensure new objs are returned

    @classmethod
    def pfx_summary(cls, ivals):
        'summarize the IP-prefixes in ivals'
        subset = [i.network() for i in ivals if i.type == cls.IP]
        return cls.summary(subset)

    @classmethod
    def port_summary(cls, ivals):
        'summarize the PORTSTR-ings in ivals'
        subset = [i for i in ivals if i.type == cls.PORTSTR]
        return cls.summary(subset)

    @classmethod
    def portpfx_summary(cls, ivals):
        'summarize PORTSTR-ivals and as if they were prefixes'
        ports = []
        for p in ivals:
            if p.type == cls.PORTSTR:
                ports.extend(cls.splice(p))
        for p in ports:
            p.type = cls.IP  # switch types to get pfx treatment
        summ = cls.summary(ports)
        for p in summ:
            p.type = cls.PORTSTR  # switch back to portstr type
        return summ


class Ip4Filter(object):
    '''
    A class for ip session lookup's via src, dst [,portstring]
    - match() -> True, False or no_match value (None by default)
    - get()   -> Ip4Match object {
                    'match': True or False or no_match value,
                    'data' : dta dict or empty dict (if any)
                    'ruleid': lowest matching rulenr or -1,
                    'ruleids': all matching rulenrs
                    }
    '''
    def __init__(self, filename=None):
        self._src = pt.PyTricia()  # pfx -> set(rids) - Ival(src ip pfx)
        self._dst = pt.PyTricia()  # pfx -> set(rids) - Ival(dst ip pfx)
        self._dpp = pt.PyTricia()  # pfx'-> set(rids) - Ival(dport/protocol)
        self._act = {}             # rid -> action (True of False)
        self._dta = {}             # rid -> dict data fields (if any)
        self._pp = Ip4Protocol()   # an Ip4Protocol object
        self._nomatch = None       # is returned when filter has no match
        self.filename = filename
        if filename:
            self.from_csv(filename)

    def __len__(self):
        return len(self._act)

    def _set_rid(self, rid, tbl, ival):
        'set rule-id on single prefix in specific table'
        pfx = str(ival)
        try:
            if tbl.has_key(pfx):        # find the exact prefix
                tbl[pfx].add(rid)       # add to existing prefix
            else:
                tbl[pfx] = set([rid])   # it's a new prefix

            # propagate rid to more specifics
            for kid in tbl.children(pfx):  # propagate rid to more specifics
                tbl[kid].add(rid)

            # adopt rid's matched by less specific parent (if any)
            parent = tbl.parent(pfx)
            if parent:
                tbl[pfx] = tbl[pfx].union(tbl[parent])

        except ValueError as e:
            print('invalid prefix? {}: {}'.format(pfx, repr(e)),
                  file=sys.stderr)
            sys.exit(1)

    def set_nomatch(self, nomatch):
        'Sets the value for a no-match, returns the old value'
        self._nomatch, oldval = nomatch, self._nomatch
        return oldval

    def add(self, rid, srcs, dsts, ports, action='', dta={}):
        'add a new rule or just add src and/or dst to an existing rule'
        summary = Ival.pfx_summary
        for ival in summary(Ival(x).network() for x in srcs):
            self._set_rid(rid, self._src, ival)

        for ival in summary(Ival(x).network() for x in dsts):
            self._set_rid(rid, self._dst, ival)

        ports_as_pfxs = chain(*(Ival(x).as_networks() for x in ports))
        for ival in ports_as_pfxs:
            self._set_rid(rid, self._dpp, ival)

        fmt = 'warn: {}, {} swaps {!r} for new {!r}'

        # always set an action for rid: default to False
        new = action.lower() == 'permit' if action else self._act.get(rid, False)
        old = self._act.setdefault(rid, new)
        if old != new:
            self._act[rid] = new
            print(fmt.format(rid, 'action', old, new))

        # always set additional data dict (when it doesn't exist already)
        old = self._dta.get(rid, None)  # get the old value
        if old is None:
            self._dta[rid] = dta            # set the new value
            if old is not None and old != dta:  # if existing old != new, warn
                print(fmt.format(rid, 'dta', old, dta))

        return True

    def clear(self):
        'clear all the rules'
        self._src = pt.PyTricia()  # pfx -> set([rid's])
        self._dst = pt.PyTricia()  # pfx -> set([rid's])
        self._dpp = pt.PyTricai()  # pfx' -> set([rids])
        self._act = {}             # rid -> action (True of False)

    def get_rids(self, src, dst, port=None, proto=None):
        'return the set of rule ids matched by session-tuple'

        try:
            if port is None:
                dpp = None
            elif proto is None:
                dpp = Ival.from_portstr(port).to_pfx()
            else:
                dpp = Ival.from_portproto(int(port), int(proto)).to_pfx()
            rids = self._dst[dst]
            if dpp is not None:
                rids = rids.intersection(self._dpp[dpp])
            return rids.intersection(self._src[src])
        except (KeyError, ValueError):
            return set()
        except TypeError:  # invalid port, proto
            print('get rids error on port, proto', port, proto)
            return set()

    def match(self, src, dst, port=None, proto=None):
        'return True (permit), False (no permit) or the nomatch value'
        rids = self.get_rids(src, dst, port, proto)
        if len(rids) == 0:
            return self._nomatch
        # TODO: make it an error is a rule-id is missing from _act
        return self._act.get(min(rids), self._nomatch)

    def get(self, src, dst, port=None, proto=None):
        'return match object of the matching rule or the nomatch value'
        rids = self.get_rids(src, dst, port, proto)
        if len(rids) == 0:
            return self._nomatch

        # TODO: make it an error is a rule-id is missing from _act
        return self._dta.get(min(rids), self._nomatch)

    def rules(self):
        'reconstruct the rules in a dict of dicts'
        # {rule_id} -> {src:[srcs],
        #               dst:[dsts],
        #               dport: [ports],
        #               action: action,
        #               dta: {dta-dict}
        #              }
        rules = {}
        # note: a PyTricia dict has no items() method
        for pfx in self._src.keys():
            ruleset = self._src[pfx]
            for rulenr in ruleset:
                dct = rules.setdefault(rulenr, {})
                dct.setdefault('src', []).append(pfx)

        # by now, rules should have all available rule nrs
        errfmt = 'Malformed Filter for rule {}'
        for pfx in self._dst.keys():
            ruleset = self._dst[pfx]
            for rulenr in ruleset:
                dct = rules.setdefault(rulenr, {})
                if len(dct) == 0:
                    raise Exception(errfmt.format(rulenr))
                dct.setdefault('dst', []).append(pfx)

        for dpp in self._dpp.keys():
            ruleset = self._dpp[dpp]
            port = Ival.from_pfx(dpp).to_portstr()
            for rulenr in ruleset:
                dct = rules.setdefault(rulenr, {})
                if len(dct) == 0:
                    raise Exception(errfmt.format(rulenr))
                dct.setdefault('dport', []).append(port)

        for rulenr, action in self._act.items():
            dct = rules.get(rulenr, None)
            if dct is None:
                raise Exception(errfmt.format(rulenr))
            dct['action'] = action

        for rulenr, data in self._dta.items():
            dct = rules.get(rulenr, None)
            if dct is None:
                raise Exception(errfmt.format(rulenr))
            dct['dta'] = data

        # sanitize more specifics in a src/dst list of a rule
        for r, rule in rules.items():
            summ = Ival.pfx_summary(map(Ival.from_pfx, rule['src']))
            rule['src'] = [x.to_pfx() for x in summ]

            summ = Ival.pfx_summary(map(Ival.from_pfx, rule['dst']))
            rule['dst'] = [x.to_pfx() for x in summ]

            # TODO: minimize port ranges
            summ = Ival.port_summary(map(Ival.from_portstr, rule['dport']))
            rule['dport'] = [x.to_portstr() for x in summ]

        return rules

    def lines(self, csv=False):
        'return filter as lines for printing'
        # {rule_id} -> {src:[srcs],
        #               dst:[dsts],
        #               dport: [ports],
        #               action: action,
        #               dta: {dta-dict}
        #              }
        rules = sorted(self.rules().items())  # rules dict -> ordered [(k,v)]
        rdct=rules[-1][-1]  # a sample dta dict

        required_fields = 'rule src dst dport action'.split()
        dta_fields = sorted(rdct.get('dta', {}).keys())  # sorted dta keys
        dta_fields = [x for x in rdct['dta'].keys() if x not in required_fields]

        fmt = '{},{},{},{},{}' if csv else '{:<5} {:21} {:21} {:16} {:7}'
        dta_header = ',{}' if csv else ' {:15}'
        fmt += dta_header * len(dta_fields)

        all_fields = required_fields + dta_fields
        lines = [fmt.format(*all_fields)]   # csv-header of field names
        for nr, rule in rules:
            maxl = max(len(rule['src']), len(rule['dst']), len(rule['dport']))
            for lnr in range(0, maxl):
                src = rule['src'][lnr] if lnr < len(rule['src']) else ''
                dst = rule['dst'][lnr] if lnr < len(rule['dst']) else ''
                prt = rule['dport'][lnr] if lnr < len(rule['dport']) else ''
                if lnr == 0:
                    act = 'permit' if rule['action'] else 'deny'
                else:
                    act = ''
                if lnr == 0:
                    data = [rule['dta'][k] for k in dta_fields]
                else:
                    data = [''] * len(dta_fields)

                lines.append(fmt.format(nr, src, dst, prt, act, *data))
                nr = ''  # only list rule nr on first line
        return lines

    def to_csv(self, fname):
        'write ruleset to csv-file'
        try:
            outf = fname if fname is sys.stdout else open(fname, 'w')
            for line in self.lines(csv=True):
                print(line, file=outf)
            if outf is not sys.stdout:
                outf.close()
        except (IOError, OSError) as e:
            fmt = 'error saving {!}: {!r}'
            raise OSError(fmt.format(fname, e))
        return True

    def from_csv(self, fname):
        'read ruleset from csv-file'
        # TODO: check for empty df and presence of required fields
        inpfile = fname if os.path.isfile(fname) else '{}.csv'.format(fname)
        try:
            df = pd.read_csv(inpfile, skipinitialspace=True)
        except (IOError, OSError):
            df = pd.DataFrame()  # empty dataframe

        df.columns = [re.sub(r'(\s|\.)+', '_', n) for n in df.columns]
        # df = ut.load_csv(inpfile)
        if len(df.index) == 0:
            raise IOError('Ip4Filter cannot read {!r}'.format(fname))

        # check columns and get superfluous cols into list for later dta dict
        required_columns = 'rule src dst dport action'.split()
        missing = [x for x in required_columns if x not in df.columns.values]
        dta_cols = [x for x in df.columns.values if x not in required_columns]
        dta_cols.extend(['rule', 'action'])  # add these -> match object

        if len(missing):
            raise ValueError('Ip4Filter is missing columns {}'.format(missing))

        try:
            df['rule'].fillna(method='ffill', inplace=True)
            df.fillna(value='', inplace=True)
            df['rule'] = df['rule'].astype(int)
            for idx, row in df.iterrows():
                rid = int(row['rule'])  # TODO: we did atype(int) already?
                srcs = [x.strip() for x in row['src'].split()]
                dsts = [x.strip() for x in row['dst'].split()]
                ports = [x.strip() for x in row['dport'].split()]
                act = row['action']
                dta = row[dta_cols].to_dict()
                self.add(rid, srcs, dsts, ports, act, dta)
        except Exception as e:
            print('oops', repr(e))
            sys.exit(1)
