'''
Helpers for filter.IP4Filter.
'''
import re
import math

from assigned_numbers import IP4PROTOCOLS
from assigned_numbers import IP4SERVICES

class Ip4Protocol(object):
    'wrapper around data.IP4PROTOCOLS'

    def __init__(self):
        self._num_toname = {}       # e.g. 6 -> 'tcp'
        self._num_todesc = {}       # e.g. 6 -> 'Transmission Control'
        self._name_tonum = {}       # e.e. 'tcp' -> 6

        # self._num_toname = dict((int(k), v[0].lower()) for k, v in DCT.items())
        # self._num_todesc = dict((int(k), v[1]) for k, v in DCT.items())
        # self._name_tonum = dict((v[0].lower(), int(k)) for k, v in DCT.items())

        for k, (name, desc) in IP4PROTOCOLS.items():
            print('k, name, desc', k, name, desc)
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
    'wrapper around data.IP4SERVICES'

    def __init__(self):
        self._service_toports = {}  # e.g https -> ['443/tcp', '443/udp']
        self._port_toservice = {}   # 'port/proto'     -> ip4-service-name

        for portstr, service in IP4SERVICES:
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
        self._service_toports[service.lower()] = [x.lower() for x in
                                                  portstrings]


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
            start = self.start & 0xFF
            ports = '{}-{}'.format(start, start + self.length - 1)

        proto = int((self.start // 2**16) & 0xFF)
        name = self.ipp.getnamebyproto(proto)
        return '{}/{}'.format(ports, name)

    def to_pfx(self):
        'turn ival (start, length) into pfx string any or a.b.c.d/e'
        # a /32 will be omitted
        err = 'invalid ival for ipv4 pfx {}'.format(self)
        if self.length == 0:
            return '0.0.0.0/0' #'any'
        elif self.length == 1:
            plen = ''
        else:
            plen = '/{}'.format(32 - int(math.log(1+self.length)//math.log(2)))

        d1 = (self.start // 2**24) & 0xFF
        d2 = (self.start // 2**16) & 0xFF
        d3 = (self.start // 2**8) & 0xFF
        d4 = (self.start) & 0xFF

        return '{}.{}.{}.{}{}'.format(d1, d2, d3, d4, plen)

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
