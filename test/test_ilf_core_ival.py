'''
Test jabs.ifl.Ival
'''

import sys
sys.path.insert(0, '..')
sys.path.insert(0, '.')
import pytest
from jabs.ilf.core import Ival, Ival2


# -- Test Ival2 - set operations

def test_set_equal_ivals():
    'equal Ivals turn up as 1 entry in a set'
    # invalid Ivals
    values = (0, 0, 0)
    i0 = Ival2(values)
    i1 = Ival2(values)
    assert len(set([i0, i1])) == 1

    # valid Pfx Ivals
    i0 = Ival2('any')
    i1 = Ival2('any')
    assert len(set([i0, i1])) == 1

    # valid Portstr Ivals
    i0 = Ival2('any/any')
    i1 = Ival2('any/any')
    assert len(set([i0, i1])) == 1


def test_set_diff_ivals():
    'unequal Ivals turn up as entries in a set'
    i0, i1 = Ival2((1, 0, 2**16)), Ival2((1, 1, 2**16))
    assert len(set([i0, i1])) == 2

    i0, i1 = Ival2((1, 0, 0)), Ival2((1, 1, 0))
    assert len(set([i0, i1])) == 2

    i0, i1 = Ival2('128.192.224.240/28'), Ival2('128.192.224.0/28')
    assert len(set([i0, i1])) == 2

    i0, i1 = Ival2('80/tcp'), Ival2('80/udp')
    assert len(set([i0, i1])) == 2


def test_ival_hashing():
    'ivals can be hashed'
    i0 = Ival2('0.0.0.0/0')
    i1 = Ival2('0.0.0.0/0')  # a new different Ival with same values
    d = {i0: 99}
    assert d[i1] == 99  # i0 == i1 -> same hash result


def test_ival_equality():
    'ivals can be equal or not'
    i0 = Ival2('10.10.10.10/24')

    i1 = Ival2('10.10.10.10/24')
    assert i0 == i1

    i1 = Ival2('10.10.10.0/32')
    assert i0 != i1


class TestIval_hashing(object):
    'test Ival can be hashed safely'

    def test_set_1(self):
        i0 = Ival(0,0)
        i1 = Ival(0,0)

        assert len(set([i0, i1])) == 1

    def test_set_2(self):
        i0, i1 = Ival(0,2**16), Ival(1,2**16)
        assert len(set([i0, i1])) == 2

        i0, i1 = Ival(0,0), Ival(1,0)
        assert len(set([i0, i1])) == 2

class TestIval_as_port(object):
    'test Ival.from_portstr'
    # portstr is:
    # any, any/protocol, port/protocol, port-port/protocol

    def test_any(self):
        'any is a valid portstring meaning any port for any protocol'
        # any port, any protocol -> length is 2**32 with base 0
        assert Ival.from_portstr('any') == Ival(0, 2**32)
        assert Ival.from_portstr('any').to_portstr() == 'any'

        with pytest.raises(ValueError):
            Ival.from_portstr('any/any')

    def test_any_proto(self):
        'any/<protoname> is valid portstring meaning any <protoname>-port'
        # any sctp port (port = 16 uint so 2**16 ports
        assert Ival.from_portstr('any/hopopt') == Ival(0, 2**16)
        assert Ival(0, 2**16).to_portstr() == 'any/hopopt'

        assert Ival.from_portstr('any/tcp') == Ival(6 * 2**16, 2**16)
        assert Ival.from_portstr('any/tcp').to_portstr() == 'any/tcp'

        assert Ival.from_portstr('any/udp') == Ival(17 * 2**16, 2**16)
        assert Ival.from_portstr('any/udp').to_portstr() == 'any/udp'

        assert Ival.from_portstr('any/sctp') == Ival(132 * 2**16, 2**16)
        assert Ival.from_portstr('any/sctp').to_portstr() == 'any/sctp'

        # only 255 has protocol name reserverd ... hmmm..
        assert Ival.from_portstr('any/reserved') == Ival(255 * 2**16, 2**16)
        assert Ival.from_portstr('any/reserved').to_portstr() == 'any/reserved'


    def test_good_portstrings(self):
        'nr/<protoname> is valid if <protoname> is known and nr in 0-65535'
        # ival start = 0.proto.port2.port1 = protonr * 2*16 + port nr
        for nr in [0, 1, 128, 365, 2*10-1, 65535]:
            port = '{}/sctp'.format(nr)  # all 1 port only, so length == 1
            assert Ival.from_portstr(port) == Ival(132 * 2**16 + nr, 1)

    def test_bad_portstrings(self):
        invalids = ['-1/tcp',     # no negative port nrs
                    '65536/tcp',  # port nr too large
                    '1/',         # missing protocol
                    '/tcp',       # missing port nr
                    '1/xxx',      # unknown protocol name
                    ]
        for invalid in invalids:
            with pytest.raises(ValueError):
                Ival.from_portstr(invalid)

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
            assert Ival.from_portstr(portstr) == Ival(start, length)
            assert Ival.from_portstr(portstr).to_portstr() == portstr

        # border cases, where to_portstr() returns saner portstring
        assert Ival.from_portstr('0-0/tcp') == Ival(6 * 2**16, 1)
        assert Ival.from_portstr('0-0/tcp').to_portstr() == '0/tcp'

        assert Ival.from_portstr('0-65535/tcp') == Ival(6 * 2**16, 2**16)
        assert Ival.from_portstr('0-65535/tcp').to_portstr() == 'any/tcp'

    def test_portstr_ranges(self):
        assert Ival.from_portstr('5200-5300/tcp').to_portstr() == '5200-5300/tcp'

    def test_single_range(self):
        'multiple ports combine into 1 range'
        cases = [('80/tcp 81/tcp 82/tcp'.split(), '80-82/tcp'),
                 ('89/udp 90/udp'.split(), '89-90/udp'),
                 ('90/udp 89/udp'.split(), '89-90/udp')
                 ]

        for ports, summary in cases:
            ivals = [Ival.from_portstr(x) for x in ports]
            summ = Ival.port_summary(ivals)
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
            ivals = [Ival.from_portstr(x) for x in ports]
            summ = Ival.port_summary(ivals)
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
            Ival.from_portproto(port, proto)

    def test_known_port_protos(self):
        assert '80/tcp' == Ival.from_portproto(80, 6).to_portstr()
        print(Ival.from_portproto(3216,6))
        print(Ival.from_portstr('3216/tcp').values())
        assert Ival.from_portproto(3216, 6) == Ival.from_portstr('3216/tcp')
        assert '3216/tcp' == Ival.from_portproto(3216, 6).to_portstr()

    def test_bad_portprotos(self):
        invalids = [(-1,0),      # port nr too small
                    (65536, 0),  # port nr too large
                    (0, -1),     # proto nr too small
                    (0, 256),    # proto nr too large
                    ]

        with pytest.raises(ValueError):
            for port, proto in invalids:
                Ival.from_portproto(port, proto)

class TestIval_as_pfx(object):
    'test Ival as prefix'

    def test_any(self):
        assert Ival.from_pfx('0/0').to_pfx() == '0.0.0.0/0'
        assert Ival.from_pfx('any').to_pfx() == '0.0.0.0/0'
        assert Ival.from_pfx('0.0.0.0/0').to_pfx() == '0.0.0.0/0'

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
            assert Ival.from_pfx(pfx).to_pfx() == proper


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
                Ival.from_pfx(invalid)

    def test_network(self):
        valids = [
            # prefix        network-pfx   network-addr
            ('1.1.1.43/24', '1.1.1.0/24', '1.1.1.0', '1.1.1.255'),
            ('1.1.1.250/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
            ('1.1.1.251/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
            ('1.1.1.251/32', '1.1.1.251', '1.1.1.251', '1.1.1.251'),
        ]

        for pfx, netpfx, netaddr, bcastaddr in valids:
            ival = Ival.from_pfx(pfx)
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
            ivals = list(map(Ival.from_pfx, pfxs))
            isumm = Ival.pfx_summary(ivals)
            assert len(isumm) == 1
            assert isumm[0] == Ival.from_pfx(summ)

