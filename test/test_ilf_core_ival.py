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
    assert Ival2('any/tcp') == Ival2('0-65535/tcp')
    assert Ival2('any/udp') == Ival2('0-65535/udp')
    with pytest.raises(ValueError):
        Ival2('0-65535/any')


def test_ival_inequality():
    'a prefix Ival2 is never equal to portstr Ival2'
    assert Ival2('any') != Ival2('any/any')


def test_ival_pfx_any():
    'any is a prefix shorthand for ALL ip addresses'
    assert Ival2('any').type == Ival2.IP
    assert Ival2('any') == Ival2((Ival2.IP, 0, 2**32))
    assert str(Ival2('any')) == '0.0.0.0/0'


def test_ival_portstr_any():
    'any/any is a portstr shorthand for any port, any protocol'
    # 0.proto.portx.porty/length -> start at 0, length 2**24 but we do
    # 2**32 to mask all bits in the portstr_as_pfx
    assert Ival2('any/any').type == Ival2.PORTSTR
    assert Ival2('any/any').values() == (Ival2.PORTSTR, 0, 2**32)
    assert str(Ival2('any/any')) == 'any/any'

    assert Ival2('any/tcp').type == Ival2.PORTSTR
    assert Ival2('any/tcp').values() == (Ival2.PORTSTR, 6 * 2**16, 2**16)
    assert str(Ival2('any/tcp')) == 'any/tcp'
    assert str(Ival2((Ival2.PORTSTR, 6 * 2**16, 2**16))) == 'any/tcp'

    # only 255 has protocol name reserverd ... hmmm..
    assert Ival2('any/reserved') == Ival2((Ival2.PORTSTR, 255 * 2**16, 2**16))
    assert str(Ival2('any/reserveD')) == 'any/reserved'


def test_ival_pfx_shorthand():
    'prefix shorthands'
    assert Ival2('224.224.224.224') == Ival2('224.224.224.224/32')
    assert Ival2('192.192/16') == Ival2('192.192.0.0/16')
    assert Ival2('0/0') == Ival2('0.0.0.0/0')
    assert Ival2('0.0/0') == Ival2('0.0.0.0/0')
    assert Ival2('0.0.0/0') == Ival2('0.0.0.0/0')
    assert Ival2('255/8') == Ival2('255.0.0.0/8')
    assert Ival2('255.255/16') == Ival2('255.255.0.0/16')
    assert Ival2('255.255.255/24') == Ival2('255.255.255.0/24')


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


def test_ival_portstr_good():
    'nr/<protoname> is valid if <protoname> is known and nr in 0-65535'
    # ival start = 0.proto.port2.port1 = protonr * 2*16 + port nr
    for nr in [0, 1, 128, 365, 2*10-1, 65535]:
        port = '{}/sctp'.format(nr)  # all 1 port only, so length == 1
        assert Ival2(port) == Ival2((Ival2.PORTSTR, 132 * 2**16 + nr, 1))


def test_bad_portstrings():
    invalids = ['-1/tcp',     # no negative port nrs
                '65536/tcp',  # port nr too large
                '1/',         # missing protocol
                '/tcp',       # missing port nr
                '1/xxx',      # unknown protocol name
                ]
    for invalid in invalids:
        with pytest.raises(ValueError):
            Ival2(invalid)


def test_portstrings_with_range():
    cases = [
        ('0-1/tcp', 6 * 2**16, 2),
        ('0-127/tcp', 6 * 2**16, 128),
        ('1-130/tcp', 6 * 2**16 + 1, 130),
        ('any/tcp', 6 * 2**16, 2**16)
    ]

    for portstr, start, length in cases:
        assert Ival2(portstr) == Ival2((Ival2.PORTSTR, start, length))
        assert str(Ival2(portstr)) == portstr

    # border cases, where to_portstr() returns saner portstring
    assert Ival2('0-0/tcp') == Ival2((Ival2.PORTSTR, 6 * 2**16, 1))
    assert str(Ival2('0-0/tcp')) == '0/tcp'

    assert Ival2('0-65535/tcp') == Ival2((Ival2.PORTSTR, 6 * 2**16, 2**16))
    assert str(Ival2('0-65535/tcp')) == 'any/tcp'


def test_portstr_ranges():
    'some roundtrip tests'
    cases = ['5200-5300/tcp',
             '1-81/udp',
             '3610-56031/hopopt',
             '60-65/icmp',
             '1-65535/nvp-ii',
             ]

    for portstr in cases:
        print(portstr, Ival2(portstr), Ival2(portstr).values())
        assert str(Ival2(portstr)) == portstr


def test_two_ranges():
    'multiple ports that combine into two ranges'
    cases = [('80/tcp 81/tcp 83/tcp 84/tcp'.split(),
              '80-81/tcp 83-84/tcp'.split()),
             ('84/tcp 80/tcp 83/tcp 81/tcp'.split(),
              '80-81/tcp 83-84/tcp'.split()),
             ]

    for ports, ranges in cases:
        ivals = [Ival2(x) for x in ports]
        summ = Ival2.port_summary(ivals)
        assert len(summ) == len(ranges)
        # ranges contains the correct list of summary ranges
        assert all(str(x) in ranges for x in summ)


def test_portstr_swapped_start_stop():
    'higher-lower/protocol comes out as lower-higher/protocol'
    assert str(Ival2('50-25/udp')) == '25-50/udp'
    assert str(Ival2('65535-0/tcp')) == 'any/tcp'


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


def test_ival_port_pfx_summ():
    ivals = ['0-64/tcp', '65-127/tcp', '128-255/tcp']
    summ = Ival2._summary([Ival2(i) for i in ivals])
    assert len(summ) == 1


def tst_ival_portproto_good():
    valids = [(0, 0),  # port 0 for proto 0
              (0, 1),  # port 0 for proto 1
              (65535, 255),  # max port for protocol reserved
              ]

    for port, proto in valids:
        Ival2.from_portproto(port, proto)


def test_ival_portproto_known():
    assert '80/tcp' == str(Ival2.from_portproto(80, 6))
    assert Ival2.from_portproto(3216, 6) == Ival2('3216/tcp')
    assert '3216/tcp' == str(Ival2.from_portproto(3216, 6))


def test_bad_portprotos():
    invalids = [(-1, 0),      # port nr too small
                (65536, 0),  # port nr too large
                (0, -1),     # proto nr too small
                (0, 256),    # proto nr too large
                ]

    with pytest.raises(ValueError):
        for port, proto in invalids:
            Ival2.from_portproto(port, proto)
