'''
Test jabs.ifl.Ival
'''

import sys
sys.path.insert(0, '..')
sys.path.insert(0, '.')
import pytest
from jabs.ilf.core import Ival, Ival2


# -- Test Ival2 - set operations

def test_ival_in_set1():
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


def test_ival_in_set2():
    'unequal Ivals turn up as entries in a set'
    i0, i1 = Ival2((1, 0, 2**16)), Ival2((1, 1, 2**16))
    assert len(set([i0, i1])) == 2

    i0, i1 = Ival2((1, 0, 0)), Ival2((1, 1, 0))
    assert len(set([i0, i1])) == 2

    i0, i1 = Ival2('128.192.224.240/28'), Ival2('128.192.224.0/28')
    assert len(set([i0, i1])) == 2

    i0, i1 = Ival2('80/tcp'), Ival2('80/udp')
    assert len(set([i0, i1])) == 2


def test_ival_hash1():
    'ivals can be hashed'
    for i0, i1 in [(Ival2('0.0.0.0/0'), Ival2('0.0.0.0/0')),
                   (Ival2('255.255.255.255/32'), Ival2('255.255.255.255/32'))]:
        d = {i0: 99}
        assert d[i1] == d[i0]  # i1 should index the same as i0

    i0, i1 = Ival2('any'), Ival2('0/0')
    d = {i0: 99}
    assert d[i1] == d[i0]


def test_ival_hash2():
    'ivals can be hashed'
    for i0, i1 in [(Ival2('80/tcp'), Ival2('80/tcp')),
                   (Ival2('65535/udp'), Ival2('65535/udp'))]:
        d = {i0: 99}
        assert d[i1] == d[i0]  # i1 should index the same as i0


def test_ival_equality():
    'ivals can be equal or not'
    assert Ival2('0.0.0.0/0') == Ival2('any')
    assert Ival2('10.10.10.10/32') == Ival2('10.10.10.10')
    assert Ival2('10.10.10.10/0') == Ival2('any')


def test_ival_equality2():
    'ivals can be equal or not'
    assert Ival2('any/tcp') == Ival2('0-65535/tcp')
    assert Ival2('any/udp') == Ival2('0-65535/udp')
    with pytest.raises(ValueError):
        Ival2('0-65535/any')


def test_ival_inequality():
    'a prefix Ival2 is never equal to portstr Ival2'
    assert Ival2('any') != Ival2('any/any')


def test_ival_pfx_shorthand():
    'prefix shorthands are supported'
    assert Ival2('224.224.224.224') == Ival2('224.224.224.224/32')
    assert Ival2('192.192.0.0/16') == Ival2('192.192/16')
    assert Ival2('0/0') == Ival2('0.0.0.0/0')
    assert Ival2('0.0/0') == Ival2('0.0.0.0/0')
    assert Ival2('0.0.0/0') == Ival2('0.0.0.0/0')
    assert Ival2('255/8') == Ival2('255.0.0.0/8')
    assert Ival2('255.255/16') == Ival2('255.255.0.0/16')
    assert Ival2('255.255.255/24') == Ival2('255.255.255.0/24')


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


def test_ival_pfx_good():
    'some good prefixes'

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
        assert str(Ival2(pfx)) == proper

def test_ival_pfx_bad():
    invalids = ['1.0.0.0.0/8',   # too many digits
                '1.0.0.0./8',    # too many dots
                '1/',            # missing prefixlength (implied by /)
                '/8',            # missing digits
                '256.0.0.0/0'    # digit too large
                '0.256.0.0/16',  # ,,
                '0.0.256.0/24',  # ,,
                '0.0.0.256/0',   # ,,
                '1.0.0.0/-1',    # pfxlen too small
                '1.0.0.0/33',    # pfxlen too large
                '1./8',          # trailing dot
                '1.0./8',        # ,,
                '1.0.0./8',      # ,,
                '.0.0/8',        # missing digit
                ]

    for invalid in invalids:
        with pytest.raises(ValueError):
            Ival2(invalid)


def test_ival_pfx_attrs():
    valids = [
        # prefix         network-pfx     network-addr bcast-addr
        ('1.1.1.43/24',  '1.1.1.0/24',   '1.1.1.0',   '1.1.1.255'),
        ('1.1.1.250/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
        ('1.1.1.251/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
        ('1.1.1.251/32', '1.1.1.251',    '1.1.1.251', '1.1.1.251'),
    ]

    for pfx, netpfx, netaddr, bcastaddr in valids:
        ival = Ival2(pfx)
        assert str(ival.network()) == netpfx
        assert str(ival.network().address()) == netaddr
        assert str(ival.broadcast().address()) == bcastaddr


def test_ival_pfx_summary():
    'test summarization of prefixes'
    #            pfx-list,                     single-summary-prefix
    valids = [(['1.1.1.0/24', '1.1.2.0/24'],   '1.1.1.0/23'),
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
        ivals = [Ival2(pfx) for pfx in pfxs]
        isumm = Ival2.pfx_summary(ivals)
        assert len(isumm) == 1
        assert isumm[0] == Ival2(summ)


def test_ival_port_summary():
    'test summarization of port strings'
    valids = [(['80/tcp', '81/tcp', '82/tcp'], '80-82/tcp'),
              (['80-82/tcp', '84/tcp', '83/tcp'], '80-84/tcp'),

              # combine ranges
              (['8-10/udp', '11-21/udp', '22-25/udp'], '8-25/udp'),

              # combine ranges with individual ports
              (['0-127/udp', '128/udp', '129-255/udp'], '0-255/udp'),

              # large range of ports
              (['{}/rdp'.format(x) for x in range(65000, 65535+1)],
               '65000-65535/rdp'),
              ]

    for ports, summ in valids:
        ivals = [Ival2(port) for port in ports]
        isumm = Ival2.port_summary(ivals)
        assert len(isumm) == 1
        assert isumm[0] == Ival2(summ)
