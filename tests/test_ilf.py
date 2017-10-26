#!/usr/bin/env python3


import sys
sys.path.insert(0, '..')
import random
import pytest

import ilf

class TestIpProto(object):
    'test port, protocol, service conversions'

    known_protos = [('icmp', 1),
                    ('tcp', 6),
                    ('udp', 17),
                    ('rdp', 27),
                    ('rsvp', 46),
                    ('gre', 47),
                    ('esp', 50),
                    ('ah', 51),
                    ('encap', 98),
                    ('eigrp', 88),
                    ('ospfigp', 89),
                    ('vrrp', 112),
                    ]

    def test_init(self):
        ipp = ilf.Ip4Protocol()
        assert len(ipp._num_toname) == 256
        assert len(ipp._num_todesc) == 256
        assert len(ipp._name_tonum) == 256
        assert len(ipp._service_toports) == 0
        assert len(ipp._port_toservice) == 0

    def test_init_loading(self):
        ipp = ilf.Ip4Protocol()
        assert len(ipp._num_toname) == 256
        assert len(ipp._num_todesc) == 256
        assert len(ipp._name_tonum) > 0

        ipp = ilf.Ip4Protocol(load_services='ip4-services.json')
        assert len(ipp._service_toports) > 0
        assert len(ipp._port_toservice) > 0


class TestIval_as_port(object):
    'test Ival.from_portstr'
    # portstr is:
    # any, any/protocol, port/protocol, port-port/protocol

    def test_any(self):
        'any is a valid portstring meaning any port for any protocol'
        # any port, any protocol -> length is 2**32 with base 0
        assert ilf.Ival.from_portstr('any') == ilf.Ival(0, 2**32)
        assert ilf.Ival.from_portstr('any').to_portstr() == 'any'

        with pytest.raises(ValueError):
            ilf.Ival.from_portstr('any/any')

    def test_any_proto(self):
        'any/<protoname> is valid portstring meaning any <protoname>-port'
        # any sctp port (port = 16 uint so 2**16 ports
        assert ilf.Ival.from_portstr('any/hopopt') == ilf.Ival(0, 2**16)
        assert ilf.Ival(0, 2**16).to_portstr() == 'any/hopopt'

        assert ilf.Ival.from_portstr('any/tcp') == ilf.Ival(6 * 2**16, 2**16)
        assert ilf.Ival.from_portstr('any/tcp').to_portstr() == 'any/tcp'

        assert ilf.Ival.from_portstr('any/udp') == ilf.Ival(17 * 2**16, 2**16)
        assert ilf.Ival.from_portstr('any/udp').to_portstr() == 'any/udp'

        assert ilf.Ival.from_portstr('any/sctp') == ilf.Ival(132 * 2**16, 2**16)
        assert ilf.Ival.from_portstr('any/sctp').to_portstr() == 'any/sctp'

        # only 255 has protocol name reserverd ... hmmm..
        assert ilf.Ival.from_portstr('any/reserved') == ilf.Ival(255 * 2**16, 2**16)
        assert ilf.Ival.from_portstr('any/reserved').to_portstr() == 'any/reserved'


    def test_good_portstrings(self):
        'nr/<protoname> is valid if <protoname> is known and nr in 0-65535'
        # ival start = 0.proto.port2.port1 = protonr * 2*16 + port nr
        for nr in [0, 1, 128, 365, 2*10-1, 65535]:
            port = '{}/sctp'.format(nr)  # all 1 port only, so length == 1
            assert ilf.Ival.from_portstr(port) == ilf.Ival(132 * 2**16 + nr, 1)

    def test_bad_portstrings(self):
        invalids = ['-1/tcp',     # no negative port nrs
                    '65536/tcp',  # port nr too large
                    '1/',         # missing protocol
                    '/tcp',       # missing port nr
                    '1/xxx',      # unknown protocol name
                    ]
        for invalid in invalids:
            with pytest.raises(ValueError):
                ilf.Ival.from_portstr(invalid)

    def test_portstrings_with_range(self):
        cases = [
            # ('0-0/tcp', 6 * 2**16, 1),  # border case, to_portstr() -> 0/tcp
            ('0-1/tcp', 6 * 2**16, 2),
            ('0-127/tcp', 6 * 2**16, 128),
            ('1-130/tcp', 6 * 2**16 + 1, 130),
            # ('0-65535/tcp', 6 * 2**16, 2**16), # border case, to_portstr -> any/tcp
            ('any/tcp', 6 * 2**16, 2**16)
        ]

        for portstr, start, length in cases:
            assert ilf.Ival.from_portstr(portstr) == ilf.Ival(start, length)
            assert ilf.Ival.from_portstr(portstr).to_portstr() == portstr

        # border cases, where to_portstr() returns saner portstring
        assert ilf.Ival.from_portstr('0-0/tcp') == ilf.Ival(6 * 2**16, 1)
        assert ilf.Ival.from_portstr('0-0/tcp').to_portstr() == '0/tcp'

        assert ilf.Ival.from_portstr('0-65535/tcp') == ilf.Ival(6 * 2**16, 2**16)
        assert ilf.Ival.from_portstr('0-65535/tcp').to_portstr() == 'any/tcp'


    def test_single_range(self):
        'multiple ports combine into 1 range'
        cases = [('80/tcp 81/tcp 82/tcp'.split(), '80-82/tcp'),
                 ('89/udp 90/udp'.split(), '89-90/udp'),
                 ('90/udp 89/udp'.split(), '89-90/udp')
                 ]

        for ports, summary in cases:
            ivals = [ilf.Ival.from_portstr(x) for x in ports]
            summ = ilf.Ival.port_summary(ivals)
            assert len(summ) == 1
            assert summ[0].to_portstr() == summary


    def test_two_ranges(self):
        'multiple ports that combine into two ranges'
        cases = [('80/tcp 81/tcp 83/tcp 84/tcp'.split(),
                  '80-81/tcp 83-84/tcp'.split()),
                  ('84/tcp 80/tcp 83/tcp 81/tcp'.split(),
                  '80-81/tcp 83-84/tcp'.split()),
                 ]

        for ports, ranges in cases:
            ivals = [ilf.Ival.from_portstr(x) for x in ports]
            summ = ilf.Ival.port_summary(ivals)
            assert len(summ) == len(ranges)
            assert all(x.to_portstr() in ranges for x in summ)



class TestIval_as_portproto(object):
    'test Ival created from port, protocol nrs'

    def test_good_portprotos(self):
        valids = [(0, 0),  # port 0 for proto 0
                  (0, 1),  # port 0 for proto 1
                  (65535, 255),  # max port for protocol reserved
                  ]

        for port, proto in valids:
            ilf.Ival.from_portproto(port, proto)

    def test_known_port_protos(self):
        assert '80/tcp' == ilf.Ival.from_portproto(80, 6).to_portstr()
        print(ilf.Ival.from_portproto(3216,6))
        print(ilf.Ival.from_portstr('3216/tcp').values())
        assert ilf.Ival.from_portproto(3216, 6) == ilf.Ival.from_portstr('3216/tcp')
        assert '3216/tcp' == ilf.Ival.from_portproto(3216, 6).to_portstr()

    def test_bad_portprotos(self):
        invalids = [(-1,0),      # port nr too small
                    (65536, 0),  # port nr too large
                    (0, -1),     # proto nr too small
                    (0, 256),    # proto nr too large
                    ]

        with pytest.raises(ValueError):
            for port, proto in invalids:
                ilf.Ival.from_portproto(port, proto)

class TestIval_as_pfx(object):
    'test Ival as prefix'

    def test_any(self):
        assert ilf.Ival.from_pfx('0/0').to_pfx() == '0.0.0.0/0'
        assert ilf.Ival.from_pfx('any').to_pfx() == '0.0.0.0/0'
        assert ilf.Ival.from_pfx('0.0.0.0/0').to_pfx() == '0.0.0.0/0'

    def test_from_pfx_good(self):
        cases = [('1/8', '1.0.0.0/8'),
                 ('1.0/8', '1.0.0.0/8'),
                 ('1.0.0/8', '1.0.0.0/8'),
                 ('1.0.0.0/8', '1.0.0.0/8'),
                 ('0/0', '0.0.0.0/0'),
                 ('0.0.0.0/0', '0.0.0.0/0'),
                 ('255.255.255.255/0', '0.0.0.0/0'),
                 ('255.255.255.255/32', '255.255.255.255'),
                 ]

        for pfx, proper in cases:
            assert ilf.Ival.from_pfx(pfx).to_pfx() == proper


    def test_from_pfx_bad(self):
        invalids = ['1.0.0.0.0/8',  # too many digits
                    '1.0.0.0./8',   # too many dots
                    '1/',           # missing prefixlength (implied by /)
                    '/8',           # missing digits
                    '256.0.0.0/0'   # digit too large
                    '0.256.0.0/16', # ,,
                    '0.0.256.0/24', # ,,
                    '0.0.0.256/0',  # ,,
                    '1.0.0.0/-1',   # pfxlen too small
                    '1.0.0.0/33',   # pfxlen too large
                    '1./8',         # trailing dot
                    '1.0./8',       # ,,
                    '1.0.0./8',     # ,,
                    '.0.0/8',       # missing digit
                    ]

        for invalid in invalids:
            with pytest.raises(ValueError):
                ilf.Ival.from_pfx(invalid)

    def test_network(self):
        valids = [
            # prefix        network-pfx   network-addr
            ('1.1.1.43/24', '1.1.1.0/24', '1.1.1.0', '1.1.1.255'),
            ('1.1.1.250/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
            ('1.1.1.251/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
            ('1.1.1.251/32', '1.1.1.251', '1.1.1.251', '1.1.1.251'),
        ]

        for pfx, netpfx, netaddr, bcastaddr in valids:
            ival = ilf.Ival.from_pfx(pfx)
            assert ival.network().to_pfx() == netpfx
            assert ival.network().address() == netaddr
            assert ival.broadcast().address() == bcastaddr

    def test_pfx_summary(self):
        #          pfx-list,  single-summary-prefix
        valids = [(['1.1.1.0/24', '1.1.2.0/24'], '1.1.1.0/23'),
                  (['1.1.1.0/25', '1.1.1.128/25'], '1.1.1.0/24'),
                  (['1.1.2.128/25', '1.1.2.0/25'], '1.1.2.0/24'),
                  (['1.1.1.0/25', '1.1.2.128/25',
                    '1.1.1.128/25', '1.1.2.0/25'], '1.1.1.0/23'),

                  # all hosts 1.0.0.0 - 1.0.0.255 => 1.0.0.0/24
                  (['1.0.0.{}'.format(x) for x in range(0, 256)],
                   '1.0.0.0/24'),
                  # hosts 1.0.0.0 - 1.0.1.255 => 1.0.0.0/23
                  (list('1.0.0.{}'.format(x) for x in range(0, 256)) +
                    list('1.0.1.{}'.format(x) for x in range(0, 256)),
                   '1.0.0.0/23')
                  ]

        for pfxs, summ in valids:
            ivals = list(map(ilf.Ival.from_pfx, pfxs))
            isumm = ilf.Ival.pfx_summary(ivals)
            assert len(isumm) == 1
            assert isumm[0] == ilf.Ival.from_pfx(summ)

