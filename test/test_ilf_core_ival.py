'''
Test jabs.ifl.Ival
'''

import sys
sys.path.insert(0, '..')
sys.path.insert(0, '.')
import pytest
from jabs.ilf.core import Ival


# -- Test Ival - set operations

def test_ival_in_set1():
    'equal Ivals turn up as 1 entry in a set'
    # invalid Ivals
    values = (0, 0, 0)
    i0 = Ival(values)
    i1 = Ival(values)
    assert len(set([i0, i1])) == 1

    # valid Pfx Ivals
    i0 = Ival('any')
    i1 = Ival('any')
    assert len(set([i0, i1])) == 1

    # valid Portstr Ivals
    i0 = Ival('any/any')
    i1 = Ival('any/any')
    assert len(set([i0, i1])) == 1


def test_ival_in_set2():
    'unequal Ivals turn up as entries in a set'
    i0, i1 = Ival((1, 0, 2**16)), Ival((1, 1, 2**16))
    assert len(set([i0, i1])) == 2

    i0, i1 = Ival((1, 0, 0)), Ival((1, 1, 0))
    assert len(set([i0, i1])) == 2

    i0, i1 = Ival('128.192.224.240/28'), Ival('128.192.224.0/28')
    assert len(set([i0, i1])) == 2

    i0, i1 = Ival('80/tcp'), Ival('80/udp')
    assert len(set([i0, i1])) == 2


def test_ival_hash1():
    'ivals can be hashed'
    for i0, i1 in [(Ival('0.0.0.0/0'), Ival('0.0.0.0/0')),
                   (Ival('255.255.255.255/32'), Ival('255.255.255.255/32'))]:
        d = {i0: 99}
        assert d[i1] == d[i0]  # i1 should index the same as i0

    i0, i1 = Ival('any'), Ival('0/0')
    d = {i0: 99}
    assert d[i1] == d[i0]


def test_ival_hash2():
    'ivals can be hashed'
    for i0, i1 in [(Ival('80/tcp'), Ival('80/tcp')),
                   (Ival('65535/udp'), Ival('65535/udp'))]:
        d = {i0: 99}
        assert d[i1] == d[i0]  # i1 should index the same as i0


def test_ival_equality():
    'ivals can be equal or not'
    assert Ival('0.0.0.0/0') == Ival('any')
    assert Ival('10.10.10.10/32') == Ival('10.10.10.10')
    assert Ival('10.10.10.10/0') == Ival('any')
    assert Ival('any/tcp') == Ival('0-65535/tcp')
    assert Ival('any/udp') == Ival('0-65535/udp')
    with pytest.raises(ValueError):
        Ival('0-65535/any')


def test_ival_inequality():
    'a prefix Ival is never equal to portstr Ival'
    assert Ival('any') != Ival('any/any')


def test_ival_pfx_any():
    'any is a prefix shorthand for ALL ip addresses'
    assert Ival('any').type == Ival.IP
    assert Ival('any') == Ival((Ival.IP, 0, 2**32))
    assert str(Ival('any')) == '0.0.0.0/0'
    assert Ival('any').is_any()


def test_ival_portstr_any():
    'any/any is a portstr shorthand for any port, any protocol'
    # 0.proto.portx.porty/length -> start at 0, length 2**24 but we do
    # 2**32 to mask all bits in the portstr_as_pfx
    assert Ival('any/any').type == Ival.PORTSTR
    assert Ival('any/any').values() == (Ival.PORTSTR, 0, 2**32)
    assert str(Ival('any/any')) == 'any/any'
    assert Ival('any/any').is_any()

    assert Ival('any/tcp').type == Ival.PORTSTR
    assert Ival('any/tcp').values() == (Ival.PORTSTR, 6 * 2**16, 2**16)
    assert str(Ival('any/tcp')) == 'any/tcp'
    assert str(Ival((Ival.PORTSTR, 6 * 2**16, 2**16))) == 'any/tcp'

    # only 255 has protocol name reserverd ... hmmm..
    assert Ival('any/reserved') == Ival((Ival.PORTSTR, 255 * 2**16, 2**16))
    assert str(Ival('any/reserveD')) == 'any/reserved'


def test_any_anyany():
    'any is IP, any/any is PORTSTR'
    assert Ival('any') != Ival('any/any')
    assert Ival('any').is_any()
    assert Ival('any/any').is_any()


def test_ival_pfx_shorthand():
    'prefix shorthands'
    assert Ival('224.224.224.224') == Ival('224.224.224.224/32')
    assert Ival('192.192/16') == Ival('192.192.0.0/16')
    assert Ival('0/0') == Ival('0.0.0.0/0')
    assert Ival('0.0/0') == Ival('0.0.0.0/0')
    assert Ival('0.0.0/0') == Ival('0.0.0.0/0')
    assert Ival('255/8') == Ival('255.0.0.0/8')
    assert Ival('255.255/16') == Ival('255.255.0.0/16')
    assert Ival('255.255.255/24') == Ival('255.255.255.0/24')


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
        assert str(Ival(pfx)) == proper


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
            Ival(invalid)


def test_ival_pfx_attrs():
    valids = [
        # prefix         network-pfx     network-addr bcast-addr
        ('1.1.1.43/24',  '1.1.1.0/24',   '1.1.1.0',   '1.1.1.255'),
        ('1.1.1.250/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
        ('1.1.1.251/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
        ('1.1.1.251/32', '1.1.1.251',    '1.1.1.251', '1.1.1.251'),
    ]

    for pfx, netpfx, netaddr, bcastaddr in valids:
        ival = Ival(pfx)
        assert str(ival.network()) == netpfx
        assert str(ival.network().address()) == netaddr
        assert str(ival.broadcast().address()) == bcastaddr


def test_ival_portstr_good():
    'nr/<protoname> is valid if <protoname> is known and nr in 0-65535'
    # ival start = 0.proto.port2.port1 = protonr * 2*16 + port nr
    for nr in [0, 1, 128, 365, 2*10-1, 65535]:
        port = '{}/sctp'.format(nr)  # all 1 port only, so length == 1
        assert Ival(port) == Ival((Ival.PORTSTR, 132 * 2**16 + nr, 1))


def test_bad_portstrings():
    invalids = ['-1/tcp',     # no negative port nrs
                '65536/tcp',  # port nr too large
                '1/',         # missing protocol
                '/tcp',       # missing port nr
                '1/xxx',      # unknown protocol name
                ]
    for invalid in invalids:
        with pytest.raises(ValueError):
            Ival(invalid)


def test_portstrings_with_range():
    cases = [
        ('0-1/tcp', 6 * 2**16, 2),
        ('0-127/tcp', 6 * 2**16, 128),
        ('1-130/tcp', 6 * 2**16 + 1, 130),
        ('any/tcp', 6 * 2**16, 2**16)
    ]

    for portstr, start, length in cases:
        assert Ival(portstr) == Ival((Ival.PORTSTR, start, length))
        assert str(Ival(portstr)) == portstr

    # border cases, where to_portstr() returns saner portstring
    assert Ival('0-0/tcp') == Ival((Ival.PORTSTR, 6 * 2**16, 1))
    assert str(Ival('0-0/tcp')) == '0/tcp'

    assert Ival('0-65535/tcp') == Ival((Ival.PORTSTR, 6 * 2**16, 2**16))
    assert str(Ival('0-65535/tcp')) == 'any/tcp'


def test_portstr_ranges():
    'some roundtrip tests'
    cases = ['5200-5300/tcp',
             '1-81/udp',
             '3610-56031/hopopt',
             '60-65/icmp',
             '1-65535/nvp-ii',
             ]

    for portstr in cases:
        print(portstr, Ival(portstr), Ival(portstr).values())
        assert str(Ival(portstr)) == portstr


def test_two_ranges():
    'multiple ports that combine into two ranges'
    cases = [('80/tcp 81/tcp 83/tcp 84/tcp'.split(),
              '80-81/tcp 83-84/tcp'.split()),
             ('84/tcp 80/tcp 83/tcp 81/tcp'.split(),
              '80-81/tcp 83-84/tcp'.split()),
             ]

    for ports, ranges in cases:
        ivals = [Ival(x) for x in ports]
        summ = Ival.port_summary(ivals)
        assert len(summ) == len(ranges)
        # ranges contains the correct list of summary ranges
        assert all(str(x) in ranges for x in summ)


def test_portstr_swapped_start_stop():
    'higher-lower/protocol comes out as lower-higher/protocol'
    assert str(Ival('50-25/udp')) == '25-50/udp'
    assert str(Ival('65535-0/tcp')) == 'any/tcp'


def test_ival_compare_lt():
    'ival is smaller if it starts to the left or is smaller'
    # ival starting to the left is always smaller
    assert Ival('1.1.0.0/24') < Ival('1.1.1.0/32')
    assert Ival('0-100/tcp') < Ival('1/tcp')

    # with same start, compare based on lentg
    assert Ival('1.1.0.0/24') < Ival('1.1.0.0/23')

    # invalid < cls.IP < cls.PORTSTR
    assert Ival() < Ival('0.0.0.0')
    assert Ival('255.255.255.255') < Ival('0/hopopt')
    assert Ival('0/0') < Ival('0/tcp')


def test_ival_compare_le():
    'ival is smaller if it starts to the left or is smaller'
    # smaller start
    assert Ival('1.1.0.0/24') <= Ival('1.1.1.0/32')

    # same start, smaller lenth
    assert Ival('1.1.0.0/24') <= Ival('1.1.0.0/23')
    assert Ival('1-10/tcp') <= Ival('1-11/tcp')

    # due to type
    assert Ival() <= Ival('0.0.0.0')
    assert Ival('255.255.255.255') <= Ival('0/hopopt')
    assert Ival('0/0') <= Ival('0/tcp')


def test_ival_compare_gt():
    # due to type
    assert Ival('0.0.0.0') > Ival()
    assert Ival('0/udp') > Ival('255.255.255.255')

    # due to start
    assert Ival('0.0.0.1/32') > Ival('0.0.0.0/24')
    assert Ival('10/tcp') > Ival('0-65535/tcp')

    # due to protocol number
    assert Ival('1/udp') > Ival('1/tcp')


def test_ival_compare_ge():
    # due to type
    assert Ival('0.0.0.0') >= Ival()
    assert Ival('0/udp') >= Ival('255.255.255.255')

    # due to start
    assert Ival('0.0.0.1/32') >= Ival('0.0.0.0/24')
    assert Ival('10/tcp') >= Ival('0-65535/tcp')

    # due to protocol number
    assert Ival('1/udp') >= Ival('1/tcp')


def test_ival_sorting():
    'ivals sort on type, then on start then on length'
    ivals = [Ival(i) for i in '9/tcp 1.1.1.0/23 10/tcp 1.1.1.0/24'.split()]
    svals = [Ival(i) for i in '1.1.1.0/24 1.1.1.0/23 9/tcp 10/tcp'.split()]
    assert list(sorted(ivals)) == svals


def test_ival_pfx_summary1():
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
        ivals = [Ival(pfx) for pfx in pfxs]
        isumm = Ival.pfx_summary(ivals)
        assert len(isumm) == 1
        assert isumm[0] == Ival(summ)


def test_ival_pfx_summary2():
    'test summarization of prefixes'
    ips = map(Ival, ['0.0.0.0', '0.0.0.1', '0.0.0.2', '0.0.0.3'])
    assert Ival.pfx_summary(ips) == [Ival('0.0.0.0/30')]

    ips = map(Ival, ['0.0.0.0', '0.0.0.1', '0.0.0.2'])
    assert Ival.pfx_summary(ips) == [Ival('0.0.0.0/31'), Ival('0.0.0.2')]


def test_ival_pfx_summary3():
    ips = map(Ival, ['0.0.0.9', '0.0.0.10', '0.0.0.11'])
    assert Ival.pfx_summary(ips) == [Ival('0.0.0.9'), Ival('0.0.0.10/31')]

    ips = map(Ival, ['0.0.0.10', '0.0.0.11', '0.0.0.12'])
    assert Ival.pfx_summary(ips) == [Ival('0.0.0.10/31'), Ival('0.0.0.12')]


def test_ival_port_summary():
    'port summary of adjacent intervals'
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
        ivals = [Ival(port) for port in ports]
        isumm = Ival.port_summary(ivals)
        assert len(isumm) == 1
        assert isumm[0] == Ival(summ)


def test_ival_port_summary1():
    'port summary of adjacent intervals'
    ivals = ['0-64/tcp', '65-127/tcp', '128-255/tcp']
    summ = Ival.summary([Ival(i) for i in ivals])
    assert len(summ) == 1
    assert str(summ[0]) == '0-255/tcp'


def test_ival_port_summary2():
    'port summary of overlapping intervals'
    ivals = ['0-7/tcp', '3-8/tcp', '5-10/tcp']
    summ = Ival.port_summary([Ival(i) for i in ivals])
    assert len(summ) == 1
    assert str(summ[0]) == '0-10/tcp'

    ivals = ['0-7/tcp', '1-2/tcp', '2-5/tcp']
    summ = Ival.port_summary([Ival(i) for i in ivals])
    assert len(summ) == 1
    assert str(summ[0]) == '0-7/tcp'


def test_ival_summary():
    'mixed ivals can be summarized as well'
    ivals = ['1.1.1.0/24', '0-12/tcp', '1.1.0.0/24', '13-15/tcp']
    mixed = [Ival(i) for i in ivals]
    assert Ival.summary(mixed) == [Ival('1.1.0.0/23'), Ival('0-15/tcp')]


def tst_ival_portproto_good():
    valids = [(0, 0),  # port 0 for proto 0
              (0, 1),  # port 0 for proto 1
              (65535, 255),  # max port for protocol reserved
              ]

    for port_proto in valids:
        Ival(port_proto)


def test_ival_portproto_known():
    assert '80/tcp' == str(Ival((80, 6)))
    assert Ival((3216, 6)) == Ival('3216/tcp')
    assert '3216/tcp' == str(Ival((3216, 6)))


def test_bad_portprotos():
    invalids = [(-1, 0),      # port nr too small
                (65536, 0),  # port nr too large
                (0, -1),     # proto nr too small
                (0, 256),    # proto nr too large
                ]

    with pytest.raises(ValueError):
        for port_proto in invalids:
            Ival(port_proto)


def test_ival_splicing():
    'PORTSTRings need to be spliced into prefix-like ranges'
    ival = Ival('0-9/tcp')
    assert Ival.splice(ival) == [Ival('0-7/tcp'), Ival('8-9/tcp')]

    ival = Ival('0-15/tcp')
    assert Ival.splice(ival) == [Ival('0-15/tcp')]

    ival = Ival('0-12/tcp')
    assert Ival.splice(ival) == [Ival('0-7/tcp'), Ival('8-11/tcp'),
                                 Ival('12/tcp')]

    assert Ival.splice(Ival('0-13/tcp')) == [Ival('0-7/tcp'),
                                             Ival('8-11/tcp'),
                                             Ival('12-13/tcp')]


def test_ival_splice2():
    'splicing a port-range, '
    pass


def test_ival_network():
    'network is new ival for 1st value in ival'
    # network() preserves mask/length
    x = Ival('10.10.10.10/24')
    y = x.network()
    assert y is not x
    assert y == Ival('10.10.10.0/24')

    # for a portrange, you get the range back
    x = Ival('123-125/tcp')
    y = x.network()
    assert y is not x
    assert y == Ival('123-125/tcp')

    assert Ival('1.1.1.1/31').network() == Ival('1.1.1.0/31')
    assert Ival('1.1.1.1/32').network() == Ival('1.1.1.1/32')

    x = Ival('0.0.0.0/0')
    y = x.network()
    assert y is not x
    assert y == Ival('0.0.0.0/0')


def test_ival_broadcast1():
    'broadcast yields new ival for last value in ival'
    # also preserves mask
    x = Ival('12-15/tcp')
    y = x.broadcast()
    assert y is not x
    assert y == Ival('12-15/tcp')


def test_ival_broadcast2():
    x = Ival('255.255.255.0/24')
    y = x.broadcast()
    print(x, y)
    assert y is not x
    z = Ival('255.255.255.255/24')
    print(x, y, z)
    print(x.values())
    print(y.values())
    print(z.values())
    print(x.imask())
    assert y == Ival('255.255.255.255/24')


def test_ival_broadcast3():
    x = Ival('0.0.0.0/0')
    y = x.broadcast()
    assert y is not x
    assert y == Ival('255.255.255.255/0')
    assert y.address() == Ival('255.255.255.255/32')

