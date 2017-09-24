#!/usr/bin/env python3
'''
ipf - ip filter

  ipf filters or tags (src_ip, dest_ip, dest_port)-combinations on its stdin'

'''

import os
import sys
import logging
import re
import math
import json

import pandas as pd
import numpy as np
import pytricia as pt

import utils as ut

#-- logging
log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

#-- glob
__version__ = '0.1'

IP4PROTOS = {
    0: ['hopopt', 'IPv6 Hop-by-Hop Option'],
    1: ['icmp', 'Internet Control Message'],
    2: ['igmp', 'Internet Group Management'], 3: ['ggp', 'Gateway-to-Gateway'],
    4: ['ipv4', 'IPv4 encapsulation'], 5: ['st', 'Stream'],
    6: ['tcp', 'Transmission Control'], 7: ['cbt', 'CBT'],
    8: ['egp', 'Exterior Gateway Protocol'],
    9: ['igp', 'any private interior gateway (used by Cisco for their IGRP)'],
    10: ['bbn-rcc-mon', 'BBN RCC Monitoring'],
    11: ['nvp-ii', 'Network Voice Protocol'], 12: ['pup', 'PUP'],
    13: ['argus', 'ARGUS'], 14: ['emcon', 'EMCON'],
    15: ['xnet', 'Cross Net Debugger'], 16: ['chaos', 'Chaos'],
    17: ['udp', 'User Datagram'], 18: ['mux', 'Multiplexing'],
    19: ['dcn-meas', 'DCN Measurement Subsystems'],
    20: ['hmp', 'Host Monitoring'], 21: ['prm', 'Packet Radio Measurement'],
    22: ['xns-idp', 'XEROX NS IDP'], 23: ['trunk-1', 'Trunk-1'],
    24: ['trunk-2', 'Trunk-2'], 25: ['leaf-1', 'Leaf-1'],
    26: ['leaf-2', 'Leaf-2'], 27: ['rdp', 'Reliable Data Protocol'],
    28: ['irtp', 'Internet Reliable Transaction'],
    29: ['iso-tp4', 'ISO Transport Protocol Class 4'],
    30: ['netblt', 'Bulk Data Transfer Protocol'],
    31: ['mfe-nsp', 'MFE Network Services Protocol'],
    32: ['merit-inp', 'MERIT Internodal Protocol'],
    33: ['dccp', 'Datagram Congestion Control Protocol'],
    34: ['3pc', 'Third Party Connect Protocol'],
    35: ['idpr', 'Inter-Domain Policy Routing Protocol'], 36: ['xtp', 'XTP'],
    37: ['ddp', 'Datagram Delivery Protocol'],
    38: ['idpr-cmtp', 'IDPR Control Message Transport Proto'],
    39: ['tp++', 'TP++ Transport Protocol'],
    40: ['il', 'IL Transport Protocol'], 41: ['ipv6', 'IPv6 encapsulation'],
    42: ['sdrp', 'Source Demand Routing Protocol'],
    43: ['ipv6-route', 'Routing Header for IPv6'],
    44: ['ipv6-frag', 'Fragment Header for IPv6'],
    45: ['idrp', 'Inter-Domain Routing Protocol'],
    46: ['rsvp', 'Reservation Protocol'],
    47: ['gre', 'Generic Routing Encapsulation'],
    48: ['dsr', 'Dynamic Source Routing Protocol'], 49: ['bna', 'BNA'],
    50: ['esp', 'Encap Security Payload'], 51: ['ah', 'Authentication Header'],
    52: ['i-nlsp', 'Integrated Net Layer Security TUBA'],
    53: ['swipe', 'IP with Encryption'],
    54: ['narp', 'NBMA Address Resolution Protocol'],
    55: ['mobile', 'IP Mobility'],
    56: ['tlsp', 'Transport Layer Security Protocol using Kryptonet key management'],
    57: ['skip', 'SKIP'], 58: ['ipv6-icmp', 'ICMP for IPv6'],
    59: ['ipv6-nonxt', 'No Next Header for IPv6'],
    60: ['ipv6-opts', 'Destination Options for IPv6'],
    61: ['ip61', 'any host internal protocol'], 62: ['cftp', 'CFTP'],
    63: ['ip63', 'any local network'],
    64: ['sat-expak', 'SATNET and Backroom EXPAK'],
    65: ['kryptolan', 'Kryptolan'],
    66: ['rvd', 'MIT Remote Virtual Disk Protocol'],
    67: ['ippc', 'Internet Pluribus Packet Core'],
    68: ['ip68', 'any distributed file system'],
    69: ['sat-mon', 'SATNET Monitoring'], 70: ['visa', 'VISA Protocol'],
    71: ['ipcv', 'Internet Packet Core Utility'],
    72: ['cpnx', 'Computer Protocol Network Executive'],
    73: ['cphb', 'Computer Protocol Heart Beat'],
    74: ['wsn', 'Wang Span Network'], 75: ['pvp', 'Packet Video Protocol'],
    76: ['br-sat-mon', 'Backroom SATNET Monitoring'],
    77: ['sun-nd', 'SUN ND PROTOCOL-Temporary'],
    78: ['wb-mon', 'WIDEBAND Monitoring'], 79: ['wb-expak', 'WIDEBAND EXPAK'],
    80: ['iso-ip', 'ISO Internet Protocol'], 81: ['vmtp', 'VMTP'],
    82: ['secure-vmtp', 'SECURE-VMTP'], 83: ['vines', 'VINES'],
    84: ['ttp', 'Transaction Transport Protocol'],
    85: ['nsfnet-igp', 'NSFNET-IGP'],
    86: ['dgp', 'Dissimilar Gateway Protocol'], 87: ['tcf', 'TCF'],
    88: ['eigrp', 'EIGRP'], 89: ['ospfigp', 'OSPFIGP'],
    90: ['sprite-rpc', 'Sprite RPC Protocol'],
    91: ['larp', 'Locus Address Resolution Protocol'],
    92: ['mtp', 'Multicast Transport Protocol'], 93: ['ax.25', 'AX.25 Frames'],
    94: ['ipip', 'IP-within-IP Encapsulation Protocol'],
    95: ['micp', 'Mobile Internetworking Control Pro.'],
    96: ['scc-sp', 'Semaphore Communications Sec. Pro.'],
    97: ['etherip', 'Ethernet-within-IP Encapsulation'],
    98: ['encap', 'Encapsulation Header'],
    99: ['ip99', 'any private encryption scheme'], 100: ['gmtp', 'GMTP'],
    101: ['ifmp', 'Ipsilon Flow Management Protocol'],
    102: ['pnni', 'PNNI over IP'],
    103: ['pim', 'Protocol Independent Multicast'], 104: ['aris', 'ARIS'],
    105: ['scps', 'SCPS'], 106: ['qnx', 'QNX'], 107: ['a/n', 'Active Networks'],
    108: ['ipcomp', 'IP Payload Compression Protocol'],
    109: ['snp', 'Sitara Networks Protocol'],
    110: ['compaq-peer', 'Compaq Peer Protocol'],
    111: ['ipx-in-ip', 'IPX in IP'],
    112: ['vrrp', 'Virtual Router Redundancy Protocol'],
    113: ['pgm', 'PGM Reliable Transport Protocol'],
    114: ['ip114', 'any 0-hop protocol'],
    115: ['l2tp', 'Layer Two Tunneling Protocol'],
    116: ['ddx', 'D-II Data Exchange (DDX)'],
    117: ['iatp', 'Interactive Agent Transfer Protocol'],
    118: ['stp', 'Schedule Transfer Protocol'],
    119: ['srp', 'SpectraLink Radio Protocol'], 120: ['uti', 'UTI'],
    121: ['smp', 'Simple Message Protocol'],
    122: ['sm', 'Simple Multicast Protocol'],
    123: ['ptp', 'Performance Transparency Protocol'], 124: ['isis', 'isis'],
    125: ['fire', 'fire'], 126: ['crtp', 'Combat Radio Transport Protocol'],
    127: ['crudp', 'Combat Radio User Datagram'], 128: ['sscopmce', 'sscopmce'],
    129: ['iplt', 'iplt'], 130: ['sps', 'Secure Packet Shield'],
    131: ['pipe', 'Private IP Encapsulation within IP'],
    132: ['sctp', 'Stream Control Transmission Protocol'],
    133: ['fc', 'Fibre Channel'], 134: ['rsvp-e2e-ignore', 'rsvp-e2e-ignore'],
    135: ['mobility', 'mobility'], 136: ['udplite', 'udplite'],
    137: ['mpls-in-ip', 'mpls-in-ip'], 138: ['manet', 'MANET Protocols'],
    139: ['hip', 'Host Identity Protocol'], 140: ['shim6', 'Shim6 Protocol'],
    141: ['wesp', 'Wrapped Encapsulating Security Payload'],
    142: ['rohc', 'Robust Header Compression'], 143: ['ip143', 'Unassigned'],
    144: ['ip144', 'Unassigned'], 145: ['ip145', 'Unassigned'],
    146: ['ip146', 'Unassigned'], 147: ['ip147', 'Unassigned'],
    148: ['ip148', 'Unassigned'], 149: ['ip149', 'Unassigned'],
    150: ['ip150', 'Unassigned'], 151: ['ip151', 'Unassigned'],
    152: ['ip152', 'Unassigned'], 153: ['ip153', 'Unassigned'],
    154: ['ip154', 'Unassigned'], 155: ['ip155', 'Unassigned'],
    156: ['ip156', 'Unassigned'], 157: ['ip157', 'Unassigned'],
    158: ['ip158', 'Unassigned'], 159: ['ip159', 'Unassigned'],
    160: ['ip160', 'Unassigned'], 161: ['ip161', 'Unassigned'],
    162: ['ip162', 'Unassigned'], 163: ['ip163', 'Unassigned'],
    164: ['ip164', 'Unassigned'], 165: ['ip165', 'Unassigned'],
    166: ['ip166', 'Unassigned'], 167: ['ip167', 'Unassigned'],
    168: ['ip168', 'Unassigned'], 169: ['ip169', 'Unassigned'],
    170: ['ip170', 'Unassigned'], 171: ['ip171', 'Unassigned'],
    172: ['ip172', 'Unassigned'], 173: ['ip173', 'Unassigned'],
    174: ['ip174', 'Unassigned'], 175: ['ip175', 'Unassigned'],
    176: ['ip176', 'Unassigned'], 177: ['ip177', 'Unassigned'],
    178: ['ip178', 'Unassigned'], 179: ['ip179', 'Unassigned'],
    180: ['ip180', 'Unassigned'], 181: ['ip181', 'Unassigned'],
    182: ['ip182', 'Unassigned'], 183: ['ip183', 'Unassigned'],
    184: ['ip184', 'Unassigned'], 185: ['ip185', 'Unassigned'],
    186: ['ip186', 'Unassigned'], 187: ['ip187', 'Unassigned'],
    188: ['ip188', 'Unassigned'], 189: ['ip189', 'Unassigned'],
    190: ['ip190', 'Unassigned'], 191: ['ip191', 'Unassigned'],
    192: ['ip192', 'Unassigned'], 193: ['ip193', 'Unassigned'],
    194: ['ip194', 'Unassigned'], 195: ['ip195', 'Unassigned'],
    196: ['ip196', 'Unassigned'], 197: ['ip197', 'Unassigned'],
    198: ['ip198', 'Unassigned'], 199: ['ip199', 'Unassigned'],
    200: ['ip200', 'Unassigned'], 201: ['ip201', 'Unassigned'],
    202: ['ip202', 'Unassigned'], 203: ['ip203', 'Unassigned'],
    204: ['ip204', 'Unassigned'], 205: ['ip205', 'Unassigned'],
    206: ['ip206', 'Unassigned'], 207: ['ip207', 'Unassigned'],
    208: ['ip208', 'Unassigned'], 209: ['ip209', 'Unassigned'],
    210: ['ip210', 'Unassigned'], 211: ['ip211', 'Unassigned'],
    212: ['ip212', 'Unassigned'], 213: ['ip213', 'Unassigned'],
    214: ['ip214', 'Unassigned'], 215: ['ip215', 'Unassigned'],
    216: ['ip216', 'Unassigned'], 217: ['ip217', 'Unassigned'],
    218: ['ip218', 'Unassigned'], 219: ['ip219', 'Unassigned'],
    220: ['ip220', 'Unassigned'], 221: ['ip221', 'Unassigned'],
    222: ['ip222', 'Unassigned'], 223: ['ip223', 'Unassigned'],
    224: ['ip224', 'Unassigned'], 225: ['ip225', 'Unassigned'],
    226: ['ip226', 'Unassigned'], 227: ['ip227', 'Unassigned'],
    228: ['ip228', 'Unassigned'], 229: ['ip229', 'Unassigned'],
    230: ['ip230', 'Unassigned'], 231: ['ip231', 'Unassigned'],
    232: ['ip232', 'Unassigned'], 233: ['ip233', 'Unassigned'],
    234: ['ip234', 'Unassigned'], 235: ['ip235', 'Unassigned'],
    236: ['ip236', 'Unassigned'], 237: ['ip237', 'Unassigned'],
    238: ['ip238', 'Unassigned'], 239: ['ip239', 'Unassigned'],
    240: ['ip240', 'Unassigned'], 241: ['ip241', 'Unassigned'],
    242: ['ip242', 'Unassigned'], 243: ['ip243', 'Unassigned'],
    244: ['ip244', 'Unassigned'], 245: ['ip245', 'Unassigned'],
    246: ['ip246', 'Unassigned'], 247: ['ip247', 'Unassigned'],
    248: ['ip248', 'Unassigned'], 249: ['ip249', 'Unassigned'],
    250: ['ip250', 'Unassigned'], 251: ['ip251', 'Unassigned'],
    252: ['ip252', 'Unassigned'],
    253: ['ip253', 'Use for experimentation and testing'],
    254: ['ip254', 'Use for experimentation and testing'],
}

class Ip4Protocol(object):
    'helper to translate strings to port,protocol nrs'
    ip4_proto_json = 'ip4-protocols.json'
    ip4_services_json = 'ip4-services.json'

    def __init__(self, load_services=False):
        self._num_toname = {}       # e.g. 6 -> 'tcp'
        self._num_todesc = {}       # e.g. 6 -> 'Transmission Control'
        self._name_tonum = {}       # e.e. 'tcp' -> 6
        self._service_toports = {}  # e.g https -> ['443/tcp', '443/udp']
        self._port_toservice = {}   # 'port/proto'     -> ip4-service-name


        # the json files are data files produced for ipf.py by updta.py
        self.load_protos('ip4-protocols.json')
        if load_services:
            self.load_services('ip4-services.json')

    def load_protos(self, filename):
        'read json encoded ip4-protocol information'
        # {'6': ['tcp', 'Transmission Control'], ..}

        try:
            with open(filename, 'r') as fh:
                dct = json.load(fh)
        except (OSError, IOError) as e:
            raise IOError('Cannot read {!r}: {!r}'.format(filename, e))

        self._num_toname = dict((int(k), v[0].lower()) for k, v in dct.items())
        self._num_todesc = dict((int(k), v[1]) for k, v in dct.items())
        self._name_tonum = dict((v[0].lower(), int(k)) for k, v in dct.items())

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

    def proto_byname(self, name):
        'turn protocol name into its ip protocol number'
        err = 'invalid ipv4 protocol name: {!r}'
        rv = self._name_tonum.get(name.lower(), None)
        if rv is None:
            raise ValueError(err.format(name))
        return rv

    def proto_toname(self, num):
        'turn ipv4 protocol number into its name'
        err = 'invalid ipv4 protocol number {}'
        rv = self._num_toname.get(num, None)
        if rv is None:
            raise ValueError(err.format(num))
        return rv

    def service_toports(self, name):
        'turn service name into a list of port strings'
        err = 'unknown service name {!r}'
        rv = self._service_toports(name.lower(), None)
        if rv is None:
            raise ValueError(err.format(name))
        return rv

    def service_byport(self, portstr):
        'turn port string into its associated service name'
        err = 'invalid ipv4 protocol port string'
        rv = self._port_toservice(portstr.lower(), None)
        if rv is None:
            raise ValueError(err.format(name))


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
            ports = str(self.start & 0xFF)
        else:
            start = self.start & 0xFF
            ports = '{}-{}'.format(start, start + self.length - 1)

        proto = int((self.start & 0xFF0000) // 2**16)
        name = self.ipp.proto_toname(proto)
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
        return Ival(self.start ^ imask, self.length)

    def address(self):
        'return address part of prefix-interval'
        return Ival(self.start, 1).to_pfx()

    @classmethod
    def from_pfx(cls, pfxstr):
        'turn any or a.b.c.d/e into ival (start, length)'
        # allow for shorthands and /e defaults to /32 if absent
        err = 'invalid ipv4 prefix string {!r}'
        pfx = pfxstr.lower()  # keep pfxstr as-is for exceptions (if any)
        if pfx == 'any':
            return cls(0, 2**32)

        try:
            # options /pfx-len, defaults to /32 if absent
            x = pfx.split('/', 1)
            plen = 32 if len(x) == 1 else int(x[1])
            if plen < 0 or plen > 32:
                raise ValueError(err.format(pfxstr))

            if plen == 0:
                return cls(0, 2**32)

            length = 2**(32-plen)

            # a.b.c.d may be shortened to a, a.b or a.b.c
            # - filter handles weird dots like a. or a...
            x = list(map(int, filter(None, x[0].split('.'))))
            if len(x) > 4:
                raise ValueError(err.format(pfxstr))
            elif len(x) < 4:
                x = (x + [0, 0, 0, 0])[0:4]
            for digit in x:
                if digit < 0 or digit > 255:
                    raise ValueError(err.format(pfxstr))

            start = x[0] * 2**24 + x[1] * 2**16 + x[2] * 2**8 + x[3]

        except (AttributeError, ValueError):
            raise ValueError(err.format(pfxstr))

        return cls(start, length)

    @classmethod
    def from_portproto(cls, port, proto):
        'return port-interval by numbers'
        err = '({}, {}) invalid ipv4 port and/or protocol number'
        length = 1
        if proto < 0 or proto > 255:
            raise ValueError(err.format(port, proto))
        if port < 0 or port > 2**16 -1:
            raise ValueError(err.format(port, proto))
        return cls(proto * 2**16 + port, 1)

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

                proto_num = cls.ipp.proto_byname(x[1])
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
                proto_num = cls.ipp.proto_byname(x[2])
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
                    heap.append(x)  # combined range back on heap
                else:
                    rv.append(y)  # could not combine, both goto rv
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

    def __init__(self):
        self._src = pt.PyTricia()  # pfx  -> set([rid's]) - source ip addr
        self._dst = pt.PyTricia()  # pfx  -> set([rid's]) - destination ip addr
        self._dpp = pt.PyTricia()  # pfx' -> set([rid's]) - dest. port/protocol
        self._act = {}             # rid -> action (True of False)
        self._tag = {}             # rid -> tag
        self._pp = Ip4Protocol()   # an Ip4Protocol object
        self._nomatch = None       # is returned when filter has no match

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
            print('oopsie', pfx, repr(e))
            sys.exit(1)

    def set_nomatch(self, nomatch):
        'Sets the value for a no-match, returns the old value'
        self._nomatch, oldval = nomatch, self._nomatch
        return oldval

    def add(self, rid, srcs, dsts, ports, action='', tag=''):
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
        self._dpp = pt.PyTricai()  # pfx' -> set([rids])
        self._act = {}             # rid -> action (True of False)
        self._tag = {}             # rid -> tag

    def get_rids(self, src, dst, dpp):
        'return the set of rule ids matched by session-tuple'
        try:
            # KeyError means no match in a src, dst or dpp table
            rids = self._dst[dst]
            rids = rids.intersection(self._dpp[dpp])
            return rids.intersection(self._src[src])
        except (KeyError, ValueError):
            return set()

    def match(self, src, dst, port, proto=None):
        'return True (permit), False (no permit) or the nomatch value'
        # if proto is given as the protocol number, port should be the port number
        dpp = Ival.from_portproto(port, proto) if proto else Ival.from_portstr(port)
        rids = self.get_rids(src, dst, dpp.to_pfx())
        if len(rids) == 0:
            return self._nomatch
        # TODO: make it an error is a rule-id is missing from _act
        return self._act.get(min(rids), self._nomatch)

    def tag(self, src, dst, port, proto=None):
        'return tag value of matched rule or the nomatch value'
        dpp = Ival.from_portproto(port, proto) if proto else Ival.from_portstr(port)
        rids = self.get_rids(src, dst, dpp.to_pfx())
        if len(rids) == 0:
            return self._nomatch
        # TODO: make it an error is a rule-id is missing from _act
        return self._tag.get(min(rids), self._nomatch)

    def rules(self):
        'reconstruct the rules in a dict'
        rules = {}  # {rule_id} -> [ [srcs], [dsts], [ports], action, tag ]
        for src in self._src.keys():
            for rsrc in self._src[src]:
                rules.setdefault(rsrc, [[],[],[],'',''])[0].append(src)

        for dst in self._dst.keys():
            for rdst in self._dst[dst]:
                rules.setdefault(rdst, [[],[],[],'',''])[1].append(dst)

        for dpp in self._dpp.keys():
            port = Ival.from_pfx(dpp).to_portstr()
            for rdpp in self._dpp[dpp]:
                rules.setdefault(rdpp, [[],[],[],'',''])[2].append(port)

        for r, act in self._act.items():
            rule = rules.setdefault(r, [[],[],[],'',''])
            rule[3] = 'permit' if act else 'deny'

        for r, tag in self._tag.items():
            rule = rules.setdefault(r, [[],[],[],'',''])
            rule[4] = tag

        # sanitize more specifics in a src/dst list of a rule
        for r, rule in rules.items():
            summ  = Ival.pfx_summary(map(Ival.from_pfx, rule[0]))
            rule[0] = [x.to_pfx() for x in summ]

            summ  = Ival.pfx_summary(map(Ival.from_pfx, rule[1]))
            rule[1] = [x.to_pfx() for x in summ]

            # TODO: minimize port ranges
            summ = Ival.port_summary(map(Ival.from_portstr, rule[2]))
            rule[2] = [x.to_portstr() for x in summ]

        return rules

    def lines(self, csv=False):
        'return filter as lines for printing'
        fmt = '{},{},{},{},{},{}' if csv else '{:<5} {:21} {:21} {:16} {:7} {}'
        rules = sorted(self.rules().items())
        lines = [fmt.format('rule', 'src_ip', 'dest_ip', 'dest_port', 'action', 'tag')]
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
        df = ut.load_csv(fname)
        df['rule'].fillna(method='ffill', inplace=True)
        df.fillna(value='', inplace=True)
        df['rule'] = df['rule'].astype(int)
        print(df)
        for idx, row in df.iterrows():
            rid = int(row['rule'])
            srcs = [x.strip() for x in row['src_ip'].split()]
            dsts = [x.strip() for x in row['dest_ip'].split()]
            ports = [x.strip() for x in row['dest_port'].split()]
            act = row['action']
            tag = row['tag']
            self.add(rid, srcs, dsts, ports, act, tag)

def parse_args(argv):
    'parse commandline arguments, return arguments Namespace'
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    padd = p.add_argument
    padd('-v', '--verbose', action='store_const', dest='log_level',
         const=logging.INFO, default=logging.WARNING,
         help='show informational messages')
    padd('-d', '--debug', action='store_const', dest='log_level',
         const=logging.DEBUG, help='show debug messages')
    padd('-V', '--Version', action='version',
         version='{} {}'.format(argv[0], __version__))
    padd('command', nargs='*')

    # parse & sanitize the arguments
    arg = p.parse_args(argv[1:])
    arg.prog = argv[0]
    arg.cmds = []
    for cmd in arg.command:
        arg.cmds.append([cmd, *cmd_parser(cmd_tokens(cmd))])

    return arg

if __name__ == '__main__':

    ipf = Ip4Filter()
    ipf.from_csv('dta/rules2.csv')
    print()
    print('\n'.join(ipf.lines()))
    print()
    ipf.to_csv('dta/rules2.csv')
    print(ipf.match('11.1.1.1', '12.2.2.2', '80/tcp'))
    print(ipf.tag('11.1.1.1', '12.2.2.2', 80, 6))


