'''
ilf core utilities
'''

import re
import math

from .numbers import IP4PROTOCOLS, IP4SERVICES


class Ip4Protocol(object):
    'translate between ipv4 protocol number and associated name'

    def __init__(self):
        self._num_toname = {}       # e.g. 6 -> 'tcp'
        self._num_todesc = {}       # e.g. 6 -> 'Transmission Control'
        self._name_tonum = {}       # e.e. 'tcp' -> 6

        # self._num_toname = dict((int(k), v[0].lower()) for k, v in DCT.items())
        # self._num_todesc = dict((int(k), v[1]) for k, v in DCT.items())
        # self._name_tonum = dict((v[0].lower(), int(k)) for k, v in DCT.items())

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
        err = 'unknown ipv4 service name {!r}'
        rv = self._service_toports(name.lower(), None)
        if rv is None:
            raise ValueError(err.format(name))
        return rv

    def getservbyport(self, portstr):
        'translate a portstring to a service namet'
        err = 'invalid ipv4 protocol port string'
        rv = self._port_toservice.get(portstr.lower(), '')
        return rv

    def set_service(self, service, portstrings):
        'set known ports for a service, eg http->[80/tcp]'
        # TODO: check validity, remove spaces etc ...
        service = service.lower()
        portstrings = [portstr.lower() for portstr in portstrings]

        self._service_toports[service] = portstrings.copy()
        for portstr in portstrings:
            self._port_toservice[portstr.lower()] = service


class Ival(object):
    'helper class in (uint, num) conversions to/from port-ranges & pfxs'
    # ipv4 only
    ipp = Ip4Protocol()

    def __init__(self, start = 0, length = 0):
        self.start = start    # unsigned int for a.b.c.d or 0.proto.p1.p2
        self.length = length  # ival length

    def __repr__(self):
        return 'Ival({}, {})'.format(self.start, self.length)

    def __str__(self):
        return '({}, {})'.format(self.start, self.length)

    def __len__(self):
        return self.length

    def __contains__(self, other):
        return self.start <= other.start and\
            self.start + self.length >= other.start + other.length

    def __eq__(self, other):
        return self.start == other.start and self.length == other.length

    def __hash__(self):
        'needed because of __eq__, donot modify obj when hashed'
        return hash((self.start, self.length))

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        return self.start < other.start

    def __lte__(self, other):
        return self.start <= other.start

    def __gt__(self, other):
        return self.start > other.start + other.length

    def __gte__(self, other):
        return self.start >= other.start + other.length

    def values(self):
        return (self.start, self.length)

    def to_portstr(self):
        'return any, any/proto, port/proto or port-port/proto from interval'
        if self.length == 2**32:
            return 'any'
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

    def to_pfx(self):
        'turn ival (start, length) into pfx string any or a.b.c.d/e'
        # a /32 will be omitted
        err = 'invalid ival for ipv4 pfx {}'.format(self)
        if self.length == 2**32:
            return '0.0.0.0/0' #'any'  XXX length 2**32 means any, not length 0
        elif self.length == 1:
            plen = ''
        else:
            plen = '/{}'.format(32 - int(math.log(1+self.length)//math.log(2)))

        d1 = (self.start // 2**24) & 0xFF
        d2 = (self.start // 2**16) & 0xFF
        d3 = (self.start // 2**8) & 0xFF
        d4 = (self.start) & 0xFF

        return '{}.{}.{}.{}{}'.format(d1, d2, d3, d4, plen)

    def is_any(self):
        return self.length == 2**32  # any-interval has max length

    def network(self):
        'return new ival for this-network prefix'
        mask = 2**32 - self.length
        return Ival(self.start & mask, self.length)

    def broadcast(self):
        'return new ival for broadcast prefix'
        imask = 2**32 ^ (self.length - 1)
        return Ival(self.start | imask, self.length)

    def address(self):
        'return address part of an interval (usually a pfx ival)'
        return Ival(self.start, 1).to_pfx()

    @classmethod
    def from_pfx(cls, pfxstr):
        'turn any or a.b.c.d/e into ival (start, length)'
        # allow for shorthands and /e defaults to /32 if absent
        err = 'invalid ipv4 prefix string {!r}'
        pfx = pfxstr.lower()  # keep pfxstr as-is for exceptions (if any)
        if pfx == 'any':
            return cls(0, 2**32)   # i.e. 0/0

        if pfx.count('.') > 3:
            raise ValueError(err.format(pfxstr))
        try:
            # options /pfx-len, defaults to /32 if absent
            x = pfx.split('/', 1)
            plen = 32 if len(x) == 1 else int(x[1])
            if plen < 0 or plen > 32:
                raise ValueError(err.format(pfxstr))

            # x = list(map(int, filter(None, x[0].split('.'))))
            # donot allow double dots or trailing dots
            x = list(map(int, x[0].split('.')))
            if len(x) < 1 or len(x) > 4:
                raise ValueError(err.format(pfxstr))
            elif len(x) < 4:
                x = (x + [0, 0, 0, 0])[0:4]
            for digit in x:
                if digit < 0 or digit > 255:
                    raise ValueError(err.format(pfxstr))

            # only after checking any digits, return 0/0 if plen is 0
            if plen == 0:
                return cls(0, 2**32)
            length = 2**(32-plen)

            start = x[0] * 2**24 + x[1] * 2**16 + x[2] * 2**8 + x[3]

        except (AttributeError, ValueError):
            raise ValueError(err.format(pfxstr))

        return cls(start, length)

    @classmethod
    def from_portproto(cls, port, proto):
        'return port-interval by numbers'
        err = '({}, {}) invalid ipv4 port and/or protocol number'
        try:  # accept stringified port,proto nrs and turn 'm into ints
            port = int(port)
            proto = int(proto)
        except ValueError:
            raise ValueError(err.format(port, proto))

        if proto < 0 or proto > 255:
            raise ValueError(err.format(port, proto))
        if port < 0 or port > 2**16 -1:
            raise ValueError(err.format(port, proto))
        return cls(port + proto * 2**16, 1)

    @classmethod
    def from_portstr(cls, portstr):
        'turn start-stop/proto into start-uint, length'
        # valid portstr include: any, [port-]port/proto, any/proto
        err = 'invalid portstring {!r}'
        try:
            x = [y.strip() for y in re.split('-|/', portstr.lower())]
            if len(x) == 1:
                if x[0] != 'any':
                    raise ValueError(err.format(portstr))
                return cls(0, 2**32)  # any port, any protocol

            elif len(x) == 2:
                # port/proto or any/proto
                if '/' not in portstr:
                    raise ValueError(err.format(portstr))

                proto_num = cls.ipp.getprotobyname(x[1])
                if x[0].lower() == 'any':
                    length = 2**16
                    base = 0
                else:
                    length = 1
                    base = int(x[0])
                    if base < 0 or base > 2**16 - 1:
                        raise ValueError(err.format(portstr))
                return cls(proto_num * 2**16 + base, length)  # 0.proto.p2.p1

            elif len(x) == 3:
                # start-stop/proto
                if '/' not in portstr or '-' not in portstr:
                    raise ValueError(err.format(portstr))
                proto_num = cls.ipp.getprotobyname(x[2])
                start, stop = int(x[0]), int(x[1])
                length = stop - start + 1
                if start > stop:
                    raise ValueError(err.format(portstr))
                if start > stop or start < 0 or start > 2**16 - 1 or\
                        stop < 0 or stop > 2**16-1:
                    raise ValueError(err.format(portstr))
                return cls(proto_num * 2**16 + start, length)

        except (AttributeError, ValueError):
            # eg if portstr is not a string or int(port-part) fails
            raise ValueError(err.format(portstr))

    @classmethod
    def any(cls):
        return cls(0, 2**32)

    @classmethod
    def _combine(cls, x, y, pfx=False):
        'return new combined ival if possible, None otherwise'
        # intervals can be combined iff:
        # - one lies inside the other, or
        # - overlap each other exactly, or
        # - are adjacent to each other (pfx=True enforces equal lengths)
        if y is None:
            return cls(*x.values())
        if x is None:
            return cls(*y.values())
        if x == y:
            return cls(*x.values())
        if x in y:
            return cls(*y.values())
        if y in x:
            return cls(*x.values())
        if x.start + x.length == y.start:
            if pfx and x.length != y.length:
                return None
            return cls(x.start, x.length + y.length)
        if y.start + y.length == x.start:
            if pfx and x.length != y.length:
                return None
            return cls(y.start, y.length + x.length)

        return None  # no joy

    @classmethod
    def _summary(cls, ivals, pfx=False):
        'summarize a list of port- or prefix-intervals into minimum set of intervals'
        # reverse since this sorts first on uint, then on length in ascending order
        if pfx:
            heap = list(reversed(sorted(ival.network() for ival in ivals)))
        else:
            heap = list(reversed(sorted(ivals)))

        # reduce heap to minimum amount of intervals
        rv = []
        while len(heap):
            x = heap.pop()
            y = heap.pop() if len(heap) else None
            if y:
                z = cls._combine(x, y, pfx)  # z is None if not combined
                if z:
                    heap.append(z)  # combined range back on heap
                    continue        # start again
                else:
                    heap.append(y)  # push back for later combine attempt

            y = rv.pop() if len(rv) else None
            if y:
                z = cls._combine(x, y, pfx) # y is None when x combines x+y
                if z:
                    heap.append(z)  # combined range back on heap
                else:
                    rv.append(y)  # could not combine, both goto rv and
                    rv.append(x)  # make sure to keep rv ordering intact

            else:
                rv.append(x)

        return rv

    @classmethod
    def pfx_summary(cls, ivals):
        'convenience method wrapping Ival.summary(.., pfx=True) class method'
        return cls._summary(ivals, pfx=True)

    @classmethod
    def port_summary(cls, ivals):
        'convenience method wrapping Ival.summary(.., pfx=False) class method'
        return cls._summary(ivals, pfx=False)


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

    def _set_rid(self, rid, tbl, pfx):
        'set rule-id on single prefix in specific table'
        try:
            if tbl.has_key(pfx):        # find the exact prefix
                tbl[pfx].add(rid)       # add to existing prefix
            else:
                tbl[pfx] = set([rid])   # it's a new prefix

            # propagate rid to more specifics
            for kid in tbl.children(pfx):  # propagate rid to the more specifics
                tbl[kid].add(rid)

            # adopt rid's matched by less specific parent (if any)
            parent = tbl.parent(pfx)
            if parent:
                tbl[pfx] = tbl[pfx].union(tbl[parent])

        except ValueError as e:
            log.error('invalid prefix? {} :{}'.format(pfx, repr(e)))
            sys.exit(1)

    def set_nomatch(self, nomatch):
        'Sets the value for a no-match, returns the old value'
        self._nomatch, oldval = nomatch, self._nomatch
        return oldval

    def add(self, rid, srcs, dsts, ports, action='', dta={}):
        'add a new rule or just add src and/or dst to an existing rule'
        summary = Ival.pfx_summary
        for ival in summary(x.network() for x in map(Ival.from_pfx, srcs)):
            self._set_rid(rid, self._src, ival.to_pfx())

        for ival in summary(x.network() for x in map(Ival.from_pfx, dsts)):
            self._set_rid(rid, self._dst, ival.to_pfx())

        for ival in summary(x.network() for x in map(Ival.from_portstr, ports)):
            self._set_rid(rid, self._dpp, ival.to_pfx())

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
            summ  = Ival.pfx_summary(map(Ival.from_pfx, rule['src']))
            rule['src'] = [x.to_pfx() for x in summ]

            summ  = Ival.pfx_summary(map(Ival.from_pfx, rule['dst']))
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

        # checking columns and get superfluous cols into list for later dta dict
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
