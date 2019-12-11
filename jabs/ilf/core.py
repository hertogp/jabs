'''
ilf core utilities
'''

import sys
import re
import math
import json
import io
import pandas as pd
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


def is_power2(n):
    'check if n is power of 2, note: 2**0 is 1 is valid'
    return (n>0 and (n & (n-1) == 0))


def pp2portstr(port, proto):
    'convert port, protocol numbers to port string'
    return str(Ival.port_proto(int(port), int(proto)))


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


IPP = Ip4Protocol()  # for use w/ Ival (ipv4 only)


class Ival(object):
    'helper class that abstracts PORTSTR or IP'
    INVALID, IP, PORTSTR = (0, 1, 2)  # types of Ival's
    TYPE = {0: 'INVALID', 1: 'IP', 2: 'PORTSTR'}
    TYPES = (INVALID, IP, PORTSTR)

    def __init__(self, type_, start, length):
        'create Ival from specified type & start, length'
        self.type = type_
        self.start = start
        self.length = length

    # -- alternate constructors

    @classmethod
    def ip_pfx(cls, value):
        'Create Ival IP from a.b.c.d/e'
        if value == 'any':
            return cls(cls.IP, 0, 2**32)

        x = value.split('/', 1)
        err = 'Invalid ip prefix {!r}'
        plen = 32 if len(x) == 1 else int(x[1])
        if plen < 0 or plen > 32:
            raise ValueError(err.format(value))

        x = list(map(int, x[0].split('.')))
        if len(x) < 1 or len(x) > 4:
            raise ValueError(err.format(value))
        elif len(x) < 4:
            x = (x + [0, 0, 0, 0])[0:4]
        for digit in x:
            if digit < 0 or digit > 255:
                raise ValueError(err.format(value))

        return cls(cls.IP, x[0]*2**24 + x[1]*2**16 + x[2]*2**8 + x[3],
                   2**(32-plen))

    @classmethod
    def port_pfx(cls, value):
        'create Ival PORTSTR from port expressed as prefix a.b.c.d/e'
        return Ival.ip_pfx(value).switch(cls.PORTSTR)

    @classmethod
    def port_str(cls, value):
        'Create Ival from <port>/<proto>'
        value = value.lower().strip()
        err = 'Invalid port string {!r}'
        if value == 'any/any' or value == 'any':
            return cls(cls.PORTSTR, 0, 2**32)

        x = value.split('/')      # port(range)/proto-name
        if len(x) != 2:
            raise ValueError(err.format(value))
        x[0:1] = x[0].split('-')  # only split port(range) on '-'
        x = [y.strip() for y in x]

        if len(x) == 2:
            # port/proto or any/proto
            proto_num = IPP.getprotobyname(x[1])
            if x[0] == 'any':
                length = 2**16
                base = 0
            else:
                length = 1
                base = int(x[0])
                if base < 0 or base > 2**16 - 1:
                    raise ValueError(err.format(value))
            return cls(cls.PORTSTR, proto_num * 2**16 + base, length)

        elif len(x) == 3:
            # start-stop/proto-name
            proto_num = IPP.getprotobyname(x[2])
            start, stop = int(x[0]), int(x[1])
            if start > stop:
                start, stop = stop, start
            length = stop - start + 1
            if start < 0 or start > 2**16 - 1:
                raise ValueError(err.format(value))
            if stop < 0 or stop > 2**16 - 1:
                raise ValueError(err.format(value))
            return cls(cls.PORTSTR, proto_num * 2**16 + start, length)

    @classmethod
    def port_proto(cls, port, proto):
        'Create Ival from <port>, <proto>'
        port = int(port)
        proto = int(proto)
        err = 'Invalid port protocol numbers {!r}, {!r}'
        if proto < 0 or proto > 255 or port < 0 or port > 2**16 - 1:
            raise ValueError(err.format(port, proto))
        return cls(cls.PORTSTR, port + proto * 2**16, 1)

    # -- comparisons

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
            name = IPP.getnamebyproto(proto)
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
            return Ival(self.type, self.start + self.idx, 1)
        raise StopIteration

    # -- methods

    def values(self, values=None):
        'get the values of the ival object'
        return (self.type, self.start, self.length)

    def is_valid(self):
        'return True if valid, False otherwise'
        if self.type not in self.TYPES:
            return False
        if self.start < 0 or self.start > 2**32 - 1:
            return False
        if self.length < 0 or self.length > 2**32 - 1:
            return False
        return True

    def prefix(self):
        'return an new IP-typed Ival for this ival'
        ival = self.network()
        ival.type = Ival.IP
        return ival

    def network(self):
        'return new ival for the first value'
        # keeps the prefix (ival) length, only mask start if its IP
        # is a no-op for types != 'IP' (!)
        mask = 2**32 - self.length
        start = self.start & mask if self.type == Ival.IP else self.start
        return Ival(self.type, start, self.length)

    def broadcast(self):
        'return new ival for the last value'
        # TODO: Ival('0/0').broadcast() == Ival('255.255.255.255') ??
        # should broadcast yield an address/32 or address/pfxlen ??
        imask = self.length - 1
        start = self.start | imask if self.type == Ival.IP else self.start
        return Ival(self.type, start, self.length)

    def address(self):
        'return new ival with length 1 for start value'
        return Ival(self.type, self.start, 1)

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

    def port(self):
        'return new Ival with type set as PORTSTR'
        return Ival(Ival.PORTSTR, self.start, self.length)

    def switch(self, ival_type):
        'switch Ival.type to ival_type'
        if ival_type not in self.TYPES:
            raise ValueError('Unknown Ival type {!r}'.format(ival_type))
        self.type = ival_type
        return self

    # -- summarization

    def splice(self, ival_type=None):
        'return a list of new prefix-like intervals, override type if given'
        if ival_type and ival_type not in self.TYPES:
            raise ValueError('Unknown Ival type {!r}'.format(ival_type))

        rv = []
        start, length = self.start, self.length
        ival_type = ival_type if ival_type else self.type
        maxx = start + length
        while start < maxx:
            lbit = lowest_bit(start)
            hbit = length.bit_length()
            maxlen = 2**lbit
            newlen = maxlen if length > maxlen else 2**(hbit-1)
            rv.append((start, newlen))
            start, length = start + newlen, length - newlen

        return [Ival(ival_type, x, y) for x, y in rv]

    @classmethod
    def combine(cls, x, y):
        'if possible, return a combined ival, None otherwise'
        # border cases
        if x is None and y is None:
            return None
        elif y is None:
            return cls(*x.values())
        elif x is None:
            return cls(*y.values())
        elif x.type != y.type:
            return None

        # x,y two valid Ivals of same type

        # - intervals are the same
        if x == y:
            return cls(*x.values())

        # - interval inside the other interval
        if x in y:
            return cls(*y.values())
        if y in x:
            return cls(*x.values())

        # ensure x starts to the left of y
        x, y = (x, y) if x.start <= y.start else (y, x)

        # type dependent situations
        if x.type == cls.PORTSTR:
            # combine adjacent intervals
            if x.start + x.length == y.start:
                return cls(x.type, x.start, x.length + y.length)
            # combine partially overlapping intervals
            if x.start + x.length > y.start:
                ivlen = max(x.start + x.length, y.start + y.length) - x.start
                return cls(x.type, x.start, ivlen)

        if x.type == cls.IP:
            # pfxs can only be combined if:
            # - intervals are adjacent
            # - lengths are equal
            # - lowest start address does not change with doubling of mask
            if x.length == y.length and x.start + x.length == y.start:
                # x.start MUST be the network() address of the ival!
                if x.start == x.start & (2**32 - 2*x.length):
                    return cls(x.type, x.start, 2*x.length)

        return None  # no joy

    @classmethod
    def summary(cls, ivals):
        'summarize a (heterogeneous) list of port/prefix-intervals'
        # reverse since this sorts on type, start & length in ascending order
        # originals go back on the heap, new ivals go onto rv
        heap = list(reversed(sorted(i.network() for i in ivals)))
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

        return [Ival(*i.values()) for i in rv]  # ensure new objs are returned

    @classmethod
    def pfx_summary(cls, ivals):
        'summarize the IP-s in ivals, returns only IP-pfxs'
        return cls.summary(i for i in ivals if i.type == cls.IP)

    @classmethod
    def port_summary(cls, ivals):
        'summarize the PORTSTR-s in ivals, returns only PORTSTRs'
        return cls.summary(i for i in ivals if i.type == cls.PORTSTR)

    @classmethod
    def portpfx_summary(cls, ivals):
        'summarize PORTSTR-s and return them as ip prefixes'
        PORTSTR, IP = cls.PORTSTR, cls.IP
        portpfxs = [y for x in ivals if x.type==PORTSTR for y in x.splice(IP)]
        return cls.summary(portpfxs)


class Ip4FilterError(Exception):
    pass

class Ip4Match(object):
    __slots__ = 'rule action name object'.split()

    def __init__(self, rule, action, name, obj):
        self.rule = rule
        self.action = action
        self.name = name
        self.object = obj

class Ip4Filter(object):
    '''
    A class for ip session lookup's via src, dst  & portstring
    - action() -> yields associated action or nomatch value
    - match() -> yields match dict or nomatch value
    - get()   -> match dict {
                    'rule': Matched rule number
                    'name' : the name of rule (or '')
                    'action': the rule's action
                    'object': the rule's python object (or None)
                    }
    '''
    def __init__(self, nomatch=None):
        self._src = pt.PyTricia()  # pfx -> set(rids) - Ival(src ip pfx)
        self._dst = pt.PyTricia()  # pfx -> set(rids) - Ival(dst ip pfx)
        self._srv = pt.PyTricia()  # pfx'-> set(rids) - Ival(dport/protocol)
        self._act = {}             # rid -> action (lower cased)
        self._obj = {}             # rid -> any python object
        self._tag = {}             # rid -> name tag of rule if any, else ''
        self._nomatch = nomatch    # return value when there is no match at all

    def __len__(self):
        'the number of rules in the filter'
        return len(self._act)

    def _lines(self, csv=False):
        'return filter as lines for printing'
        # {rule_id: {src:[..], dst:[..], srv: [..], name: str, action: str, obj: obj}}
        rules = sorted(self.as_dict.items())  # rules dict -> ordered [(k,v)]
        fields = 'rule name src dst srv action obj'.split()
        fmt = '{!s:<5} {!s:<15} {!s:21} {!s:21} {!s:16} {!s:7} {!s}'
        fmt = '{},{},{},{},{},{},{}' if csv else fmt
        lines = [fmt.format(*fields)]   # csv-header of field names
        for rid, rule in rules:
            maxl = max(len(rule['src']), len(rule['dst']), len(rule['srv']))
            for lnr in range(0, maxl):
                rid = rid if lnr == 0 else ''
                tag = rule['name'] if lnr == 0 else ''
                src = rule['src'][lnr] if lnr < len(rule['src']) else ''
                dst = rule['dst'][lnr] if lnr < len(rule['dst']) else ''
                prt = rule['srv'][lnr] if lnr < len(rule['srv']) else ''
                act = rule['action'] if lnr == 0 else ''
                obj = json.dumps(rule['obj']) if lnr == 0 else ''
                obj = '' if obj in ['null', '""'] else obj
                lines.append(fmt.format(rid, tag, src, dst, prt, act, obj))

        return lines

    def _set_rid(self, rid, tbl, ival):
        'set/add to rule-id on single prefix in specific table'
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
            fmt = 'invalid prefix? {}: {}'
            print(fmt.format(pfx, repr(e)), file=sys.stderr)
            sys.exit(1)
        return self


    def _add(self, rid, srcs, dsts, srvs, name='', action='', obj=None):
        'add Ivals to a new rule or just add to an existing rule'
        for ival in Ival.pfx_summary(srcs):
            self._set_rid(rid, self._src, ival)
        for ival in Ival.pfx_summary(dsts):
            self._set_rid(rid, self._dst, ival)
        for ival in Ival.portpfx_summary(srvs):
            self._set_rid(rid, self._srv, ival)

        # name,action are strings; action always lowercase
        name = '' if name is None else str(name).strip()
        action = '' if action is None else str(action).strip().lower()

        # set attributes if not already present
        self._act.setdefault(rid, action)
        self._obj.setdefault(rid, obj)
        self._tag.setdefault(rid, name)

        return self

    # -- build methods
    @classmethod
    def compile(cls, fname):
        from . import comp
        return comp.compile(fname)

    def add(self, rid, srcs, dsts, srvs, action='', name='', obj=None):
        'add src-list, dst-list and or list of srvs to a new/old rule'
        # sanity check arguments
        if not isinstance(rid, int):
            raise TypeError('expected an int, not {!r}'.format(rid))
        for x in [srcs, dsts, srvs]:
            if not isinstance(x, (list, tuple)):
                raise TypeError('expected a list, not {!r}'.format(x))
        srcs = [Ival.ip_pfx(x) for x in srcs]
        dsts = [Ival.ip_pfx(x) for x in dsts]
        srvs = [Ival.port_str(x) for x in srvs]

        return self._add(rid, srcs, dsts, srvs, name, action, obj)

    def ruleset(self, src=None, dst=None, srv=None):
        'return the set of rule ids matched by src and/or dst and/or service'
        # - finds matching rule sets by prefix lookups per item
        #   returns the minimum rule nr of intersection
        try:
            rv = []  # collect required matches

            if src is not None:
                rv.append(self._src[src])
            if dst is not None:
                rv.append(self._dst[dst])
            if srv is not None:
                # encode as pfx to index a PyTricia table
                pfx = str(Ival.port_str(srv).switch(Ival.IP))
                rv.append(self._srv[pfx])

            if len(rv):
                return set.intersection(*rv)
            return set()

        except (KeyError, ValueError):
            return set()
        except TypeError:  # invalid value supplied
            print('ruleset type error on', src, dst, srv)
            return set()

    # -- usage methods

    def match(self, src, dst, srv):
        'return a match object or the nomatch value'
        rids = self.ruleset(src, dst, srv)
        if len(rids) == 0:
            return self._nomatch
        rid = min(rids)
        return Ip4Match(rid,
                        self._act.get(rid, None),
                        self._tag.get(rid, ''),
                        self._obj.get(rid, None))

    # -- to/from CSV

    @property
    def as_dict(self):
        'reconstruct the rules in a dict of dicts'
        # {rule nr: {src:[..], dst:[..], srv: [..], action: str, name: str, obj: {..}}}

        rules = {}
        for pfx in self._src.keys():
            for rulenr in self._src[pfx]:
                rules.setdefault(rulenr, {}).setdefault('src', []).append(pfx)

        try:
            for pfx in self._dst.keys():
                for rulenr in self._dst[pfx]:
                    rules[rulenr].setdefault('dst', []).append(pfx)

            for pfx in self._srv.keys():  # portstr encoded as a pfx
                for rulenr in self._srv[pfx]:
                    rules[rulenr].setdefault('srv', []).append(pfx)

            for rulenr, action in self._act.items():
                rules[rulenr]['action'] = action

            for rulenr, obj in self._obj.items():
                rules[rulenr]['obj'] = obj

            for rulenr, name in self._tag.items():
                rules[rulenr]['name'] = name

        except KeyError as e:
            errfmt = 'Error in rule {}:{}'
            raise Exception(errfmt.format(rulenr, repr(e)))

        for r, rule in rules.items():
            # first summarize auto-added more specifics (for set calculations)
            rule['src'] = Ival.summary(map(Ival.ip_pfx, rule['src']))
            rule['dst'] = Ival.summary(map(Ival.ip_pfx, rule['dst']))
            rule['srv'] = Ival.summary(map(Ival.port_pfx, rule['srv']))
            # next stringify the ivals
            rule['src'] = list(map(str, rule['src']))
            rule['dst'] = list(map(str, rule['dst']))
            rule['srv'] = list(map(str, rule['srv']))

        return rules

    def to_csv(self):
        'write ruleset to csv-file'
        rv = []
        for line in self._lines(csv=True):
            rv.append(line)
        return '\n'.join(rv)

    def from_csv(self, text):
        'read ruleset from csv-text'
        inp = io.StringIO(text + '\n')
        try:
            df = pd.read_csv(inp, skipinitialspace=True)
        except pd.errors.EmptyDataError:
            df = pd.DataFrame()  # empty dataframe

        df.columns = [re.sub(r'(\s|\.)+', '_', n) for n in df.columns]
        if len(df.index) == 0:
            raise IOError('Ip4Filter cannot read {!r}'.format(fname))

        required_columns = 'rule name src dst srv action obj'.split()
        missing = [x for x in required_columns if x not in df.columns.values]

        if len(missing):
            raise ValueError('Ip4Filter is missing columns {}'.format(missing))

        try:
            df['rule'].fillna(method='ffill', inplace=True)
            df.fillna(value='', inplace=True)
            df['rule'] = df['rule'].astype(int)
            for idx, row in df.iterrows():
                rid = row['rule']
                srcs = [Ival.ip_pfx(x) for x in row['src'].split()]
                dsts = [Ival.ip_pfx(x) for x in row['dst'].split()]
                ports = [Ival.port_str(x) for x in row['srv'].split()]
                act = row['action']
                name = row['name']
                obj = json.loads(row['obj']) if len(row['obj']) else ''
                self._add(rid, srcs, dsts, ports, name=name, action=act, obj=obj)
        except Exception as e:
            sys.exit(repr(e))
        return self
