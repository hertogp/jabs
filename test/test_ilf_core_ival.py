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
    ival0 = Ival(0, 0, 0)
    ival1 = Ival(0, 0, 0)
    assert len(set([ival0, ival1])) == 1

    # valid Pfx Ivals
    ival0 = Ival.ip_pfx('any')
    ival1 = Ival.ip_pfx('any')
    assert len(set([ival0, ival1])) == 1

    # valid Portstr Ivals
    ival0 = Ival.port_str('any/any')
    ival1 = Ival.port_str('any/any')
    assert len(set([ival0, ival1])) == 1


def test_ival_in_set2():
    'unequal Ivals turn up as entries in a set'
    ival0, ival1 = Ival(1, 0, 2**16), Ival(1, 1, 2**16)
    assert len(set([ival0, ival1])) == 2

    ival0, ival1 = Ival(1, 0, 0), Ival(1, 1, 0)
    assert len(set([ival0, ival1])) == 2

    ival0 = Ival.ip_pfx('128.192.224.240/28')
    ival1 = Ival.ip_pfx('128.192.224.0/28')
    assert len(set([ival0, ival1])) == 2

    ival0 = Ival.port_str('80/tcp')
    ival1 = Ival.port_str('80/udp')
    assert len(set([ival0, ival1])) == 2


def test_ival_hash1():
    'ivals can be hashed'
    for ival0, ival1 in [(Ival.ip_pfx('0.0.0.0/0'),
                          Ival.ip_pfx('0.0.0.0/0')),

                         (Ival.ip_pfx('255.255.255.255/32'),
                          Ival.ip_pfx('255.255.255.255/32'))]:
        dct = {ival0: 99}
        assert dct[ival1] == dct[ival0]  # ival1 should index the same as ival0

    ival0 = Ival.ip_pfx('any')
    ival1 = Ival.ip_pfx('0/0')
    dct = {ival0: 99}
    assert dct[ival1] == dct[ival0]


def test_ival_hash2():
    'ivals can be hashed'
    for ival0, ival1 in [(Ival.port_str('80/tcp'),
                          Ival.port_str('80/tcp')),

                         (Ival.port_str('65535/udp'),
                          Ival.port_str('65535/udp'))]:
        dct = {ival0: 99}
        assert dct[ival1] == dct[ival0]  # ival1 should index the same as ival0


def test_ival_equality():
    'ivals can be equal or not'
    assert Ival.ip_pfx('0.0.0.0/0') == Ival.ip_pfx('any')
    assert Ival.ip_pfx('10.10.10.10/32') == Ival.ip_pfx('10.10.10.10')
    assert Ival.ip_pfx('10.10.10.10/0') == Ival.ip_pfx('any')
    assert Ival.port_str('any/tcp') == Ival.port_str('0-65535/tcp')
    assert Ival.port_str('any/udp') == Ival.port_str('0-65535/udp')
    with pytest.raises(ValueError):
        Ival.port_str('0-65535/any')  # TODO: should equal any/any ...


def test_ival_inequality():
    'a prefix Ival is never equal to portstr Ival'
    assert Ival.ip_pfx('any') != Ival.port_str('any/any')


def test_ival_pfx_any():
    'any is a prefix shorthand for ALL ip addresses'
    assert Ival.ip_pfx('any').type == Ival.IP
    assert Ival.ip_pfx('any') == Ival(Ival.IP, 0, 2**32)
    assert str(Ival.ip_pfx('any')) == '0.0.0.0/0'
    assert Ival.ip_pfx('any').is_any()


def test_ival_portstr_any():
    'any/any is a portstr shorthand for any port, any protocol'
    # 0.proto.portx.porty/length -> start at 0, length 2**24 but we do
    # 2**32 to mask all bits in the portstr_as_pfx
    assert Ival.port_str('any/any').type == Ival.PORTSTR
    assert Ival.port_str('any/any').values() == (Ival.PORTSTR, 0, 2**32)
    assert str(Ival.port_str('any/any')) == 'any/any'
    assert Ival.port_str('any/any').is_any()

    assert Ival.port_str('any/tcp').type == Ival.PORTSTR
    assert Ival.port_str('any/tcp').values() == (Ival.PORTSTR, 6 * 2**16,
                                                 2**16)
    assert str(Ival.port_str('any/tcp')) == 'any/tcp'
    assert str(Ival(Ival.PORTSTR, 6 * 2**16, 2**16)) == 'any/tcp'

    # only 255 has protocol name reserverd ... hmmm..
    assert Ival.port_str('any/reserved') == Ival(Ival.PORTSTR, 255 * 2**16,
                                                 2**16)
    assert str(Ival.port_str('any/ReSeRvEd')) == 'any/reserved'


def test_any_anyany():
    'any is IP, any/any is PORTSTR'
    assert Ival.ip_pfx('any').is_any()
    assert Ival.port_str('any/any').is_any()
    # and yet:
    assert Ival.ip_pfx('any') != Ival.port_str('any/any')


def test_ival_pfx_shorthand():
    'prefix shorthands'
    assert Ival.ip_pfx('224.224.224.224') == Ival.ip_pfx('224.224.224.224/32')
    assert Ival.ip_pfx('192.192/16') == Ival.ip_pfx('192.192.0.0/16')
    assert Ival.ip_pfx('0/0') == Ival.ip_pfx('0.0.0.0/0')
    assert Ival.ip_pfx('0.0/0') == Ival.ip_pfx('0.0.0.0/0')
    assert Ival.ip_pfx('0.0.0/0') == Ival.ip_pfx('0.0.0.0/0')
    assert Ival.ip_pfx('255/8') == Ival.ip_pfx('255.0.0.0/8')
    assert Ival.ip_pfx('255.255/16') == Ival.ip_pfx('255.255.0.0/16')
    assert Ival.ip_pfx('255.255.255/24') == Ival.ip_pfx('255.255.255.0/24')


def test_ival_pfx_good():
    'some good prefixes'

    cases = [('1/8', '1.0.0.0/8'),
             ('1.0/8', '1.0.0.0/8'),
             ('1.0.0/8', '1.0.0.0/8'),
             ('1.0.0.0/8', '1.0.0.0/8'),
             ('0/0', '0.0.0.0/0'),
             ('0.0.0.0/0', '0.0.0.0/0'),
             ('255.255.255.255/0', '0.0.0.0/0'),
             ('255.255.255.255/32', '255.255.255.255')
             ]

    for pfx, proper in cases:
        assert str(Ival.ip_pfx(pfx)) == proper


def test_ival_pfx_bad():
    'test bad ipv4 address strings'
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
            Ival.ip_pfx(invalid)


def test_ival_pfx_attrs():
    'test some valid ipv4 prefix strings'
    valids = [
        # prefix         network-pfx     network-addr bcast-addr
        ('1.1.1.43/24', '1.1.1.0/24', '1.1.1.0', '1.1.1.255'),
        ('1.1.1.250/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
        ('1.1.1.251/31', '1.1.1.250/31', '1.1.1.250', '1.1.1.251'),
        ('1.1.1.251/32', '1.1.1.251', '1.1.1.251', '1.1.1.251'),
    ]

    for pfx, netpfx, netaddr, bcastaddr in valids:
        ival = Ival.ip_pfx(pfx)
        assert str(ival.network()) == netpfx
        assert str(ival.network().address()) == netaddr
        assert str(ival.broadcast().address()) == bcastaddr


def test_ival_portstr_good():
    'nr/<protoname> is valid if <protoname> is known and nr in 0-65535'
    # ival start = 0.proto.port2.port1 = protonr * 2*16 + port nr
    # sctp is protonr 132
    for portnum in [0, 1, 128, 365, 2*10-1, 65535]:
        port = '{}/sctp'.format(portnum)  # all 1 port only, so length == 1
        assert Ival.port_str(port) == Ival(Ival.PORTSTR,
                                           132 * 2**16 + portnum, 1)


def test_bad_portstrings():
    'portstrings that should fail with a ValueError'
    invalids = ['-1/tcp',     # no negative port nrs
                '65536/tcp',  # port nr too large
                '1/',         # missing protocol
                '/tcp',       # missing port nr
                '1/xxx',      # unknown protocol name
                ]
    for invalid in invalids:
        with pytest.raises(ValueError):
            Ival.port_str(invalid)


def test_portstrings_with_range():
    'portstring that should succeed'
    cases = [
        ('0-1/tcp', 6 * 2**16, 2),
        ('0-127/tcp', 6 * 2**16, 128),
        ('1-130/tcp', 6 * 2**16 + 1, 130),
        ('any/tcp', 6 * 2**16, 2**16)
    ]

    for portstr, start, length in cases:
        assert Ival.port_str(portstr) == Ival(Ival.PORTSTR, start, length)
        assert str(Ival.port_str(portstr)) == portstr

    # border cases, where str() returns saner portstring
    assert Ival.port_str('0-0/tcp') == Ival(Ival.PORTSTR, 6 * 2**16, 1)
    assert str(Ival.port_str('0-0/tcp')) == '0/tcp'

    assert Ival.port_str('0-65535/tcp') == Ival(Ival.PORTSTR, 6 * 2**16, 2**16)
    assert str(Ival.port_str('0-65535/tcp')) == 'any/tcp'


def test_portstr_ranges():
    'some roundtrip tests'
    cases = ['5200-5300/tcp',
             '1-81/udp',
             '3610-56031/hopopt',
             '60-65/icmp',
             '1-65535/nvp-ii'  # yup, proto-name may contain '-'s
             ]

    for portstr in cases:
        assert str(Ival.port_str(portstr)) == portstr


def test_two_ranges():
    'multiple ports that combine into two ranges'
    cases = [('80/tcp 81/tcp 83/tcp 84/tcp'.split(),
              '80-81/tcp 83-84/tcp'.split()),
             ('84/tcp 80/tcp 83/tcp 81/tcp'.split(),
              '80-81/tcp 83-84/tcp'.split()),
             ]

    for ports, ranges in cases:
        ivals = [Ival.port_str(x) for x in ports]
        summ = Ival.port_summary(ivals)
        assert len(summ) == len(ranges)
        # ranges contains the correct list of summary ranges
        assert all(str(x) in ranges for x in summ)


def test_portstr_swapped_start_stop():
    'higher-lower/protocol comes out as lower-higher/protocol'
    assert str(Ival.port_str('50-25/udp')) == '25-50/udp'
    assert str(Ival.port_str('65535-0/tcp')) == 'any/tcp'


def test_ival_compare_lt():
    'ival is smaller if it starts to the left or is smaller'
    # ival starting to the left is always smaller
    assert Ival.ip_pfx('1.1.0.0/24') < Ival.ip_pfx('1.1.1.0/32')
    assert Ival.port_str('0-100/tcp') < Ival.port_str('1/tcp')

    # with same start, compare based on lentg
    assert Ival.ip_pfx('1.1.0.0/24') < Ival.ip_pfx('1.1.0.0/23')

    # invalid < cls.IP < cls.PORTSTR
    assert Ival(0, 0, 0) < Ival.ip_pfx('0.0.0.0')
    assert Ival.ip_pfx('255.255.255.255') < Ival.port_str('0/hopopt')
    assert Ival.ip_pfx('0/0') < Ival.port_str('0/tcp')


def test_ival_compare_le():
    'ival is smaller if it starts to the left or is smaller'
    # smaller start
    assert Ival.ip_pfx('1.1.0.0/24') <= Ival.ip_pfx('1.1.1.0/32')

    # same start, smaller lenth
    assert Ival.ip_pfx('1.1.0.0/24') <= Ival.ip_pfx('1.1.0.0/23')
    assert Ival.port_str('1-10/tcp') <= Ival.port_str('1-11/tcp')

    # due to type
    assert Ival(0, 0, 0) <= Ival.ip_pfx('0.0.0.0')
    assert Ival.ip_pfx('255.255.255.255') <= Ival.port_str('0/hopopt')
    assert Ival.ip_pfx('0/0') <= Ival.port_str('0/tcp')


def test_ival_compare_gt():
    'comparing ivals uses ival.types as well'
    # due to type
    assert Ival.ip_pfx('0.0.0.0') > Ival(0, 0, 0)
    assert Ival.port_str('0/udp') > Ival.ip_pfx('255.255.255.255')

    # due to start
    assert Ival.ip_pfx('0.0.0.1/32') > Ival.ip_pfx('0.0.0.0/24')
    assert Ival.port_str('10/tcp') > Ival.port_str('0-65535/tcp')

    # due to protocol number
    assert Ival.port_str('1/udp') > Ival.port_str('1/tcp')


def test_ival_compare_ge():
    # due to type
    assert Ival.ip_pfx('0.0.0.0') >= Ival(0, 0, 0)
    assert Ival.port_str('0/udp') >= Ival.ip_pfx('255.255.255.255')

    # due to start
    assert Ival.ip_pfx('0.0.0.1/32') >= Ival.ip_pfx('0.0.0.0/24')
    assert Ival.port_str('10/tcp') >= Ival.port_str('0-65535/tcp')

    # due to protocol number
    assert Ival.port_str('1/udp') >= Ival.port_str('1/tcp')


def test_ival_sorting():
    'ivals sort on type, then on start then on length'
    ivals = [Ival.port_str('9/tcp'), Ival.ip_pfx('1.1.1.0/23'),
             Ival.port_str('10/tcp'), Ival.ip_pfx(' 1.1.1.0/24')]
    svals = [
        Ival.ip_pfx(' 1.1.1.0/24'),
        Ival.ip_pfx('1.1.1.0/23'),
        Ival.port_str('9/tcp'),
        Ival.port_str('10/tcp'),
        ]
    assert list(sorted(ivals)) == svals


def test_ival_pfx_summary1():
    'test summarization of prefixes'
    #            pfx-list,                     single-summary-prefix
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
        ivals = [Ival.ip_pfx(pfx) for pfx in pfxs]
        isumm = Ival.pfx_summary(ivals)
        assert len(isumm) == 1
        assert isumm[0] == Ival.ip_pfx(summ)


def test_ival_pfx_summary2():
    'test summarization of prefixes'
    ips = map(Ival.ip_pfx, ['0.0.0.0', '0.0.0.1', '0.0.0.2', '0.0.0.3'])
    assert Ival.pfx_summary(ips) == [Ival.ip_pfx('0.0.0.0/30')]

    ips = map(Ival.ip_pfx, ['0.0.0.0', '0.0.0.1', '0.0.0.2'])
    assert Ival.pfx_summary(ips) == [Ival.ip_pfx('0.0.0.0/31'),
                                     Ival.ip_pfx('0.0.0.2')]


def test_ival_pfx_summary3():
    ips = map(Ival.ip_pfx, ['0.0.0.9', '0.0.0.10', '0.0.0.11'])
    assert Ival.pfx_summary(ips) == [Ival.ip_pfx('0.0.0.9'),
                                     Ival.ip_pfx('0.0.0.10/31')]

    ips = map(Ival.ip_pfx, ['0.0.0.10', '0.0.0.11', '0.0.0.12'])
    assert Ival.pfx_summary(ips) == [Ival.ip_pfx('0.0.0.10/31'),
                                     Ival.ip_pfx('0.0.0.12')]


def test_ival_pfx_summary4():
    'test pfx summary for only two nets'
    ivals = [Ival.ip_pfx('4.4.4.0/24'), Ival.ip_pfx('4.4.4.128/25')]
    assert Ival.pfx_summary(ivals) == [Ival.ip_pfx('4.4.4.0/24')]


def test_ival_pfx_summary5():
    'test pfx summary for only two nets'
    ivals = [Ival.ip_pfx('4.4.4.11/24'), Ival.ip_pfx('4.4.4.128/25')]
    assert Ival.pfx_summary(ivals) == [Ival.ip_pfx('4.4.4.0/24')]


def test_ival_pfx_summary6():
    'no input means an empty summary'
    ivals = []
    assert Ival.pfx_summary(ivals) == []


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
        ivals = [Ival.port_str(port) for port in ports]
        isumm = Ival.port_summary(ivals)
        assert len(isumm) == 1
        assert isumm[0] == Ival.port_str(summ)


def test_ival_port_summary1():
    'port summary of adjacent intervals'
    ivals = ['0-64/tcp', '65-127/tcp', '128-255/tcp']
    summ = Ival.summary([Ival.port_str(i) for i in ivals])
    assert len(summ) == 1
    assert str(summ[0]) == '0-255/tcp'


def test_ival_port_summary2():
    'port summary of overlapping intervals'
    ivals = ['0-7/tcp', '3-8/tcp', '5-10/tcp']
    summ = Ival.port_summary([Ival.port_str(i) for i in ivals])
    assert len(summ) == 1
    assert str(summ[0]) == '0-10/tcp'

    ivals = ['0-7/tcp', '1-2/tcp', '2-5/tcp']
    summ = Ival.port_summary([Ival.port_str(i) for i in ivals])
    assert len(summ) == 1
    assert str(summ[0]) == '0-7/tcp'


def test_ival_summary():
    'mixed ivals can be summarized as well'
    mixed = [Ival.ip_pfx('1.1.1.0/24'),
             Ival.port_str('0-12/tcp'),
             Ival.ip_pfx('1.1.0.0/24'),
             Ival.port_str('13-15/tcp')
             ]
    assert Ival.summary(mixed) == [Ival.ip_pfx('1.1.0.0/23'),
                                   Ival.port_str('0-15/tcp')]


def test_ival_summary2():
    'test pfx summary for only two nets'
    ivals = [Ival.ip_pfx('4.4.4.11/24'), Ival.ip_pfx('4.4.4.128/25')]
    assert Ival.summary(ivals) == [Ival.ip_pfx('4.4.4.0/24')]


def tst_ival_portproto_good():
    valids = [(0, 0),  # port 0 for proto 0
              (0, 1),  # port 0 for proto 1
              (65535, 255),  # max port for protocol reserved
              ]

    for port_proto in valids:
        Ival.port_proto(port_proto)


def test_ival_portproto_known():
    assert '80/tcp' == str(Ival.port_proto(80, 6))
    assert Ival.port_proto(3216, 6) == Ival.port_str('3216/tcp')
    assert '3216/tcp' == str(Ival.port_proto(3216, 6))


def test_bad_portprotos():
    invalids = [(-1, 0),      # port nr too small
                (65536, 0),  # port nr too large
                (0, -1),     # proto nr too small
                (0, 256)    # proto nr too large
                ]

    with pytest.raises(ValueError):
        for port, proto in invalids:
            Ival.port_proto(port, proto)


def test_ival_splicing():
    'PORTSTRings need to be spliced into prefix-like ranges'
    ival = Ival.port_str('0-9/tcp')
    assert ival.splice() == [Ival.port_str('0-7/tcp'),
                             Ival.port_str('8-9/tcp')]

    ival = Ival.port_str('0-15/tcp')
    assert ival.splice() == [Ival.port_str('0-15/tcp')]

    ival = Ival.port_str('0-12/tcp')
    assert ival.splice() == [Ival.port_str('0-7/tcp'),
                             Ival.port_str('8-11/tcp'),
                             Ival.port_str('12/tcp')]

    assert Ival.port_str('0-13/tcp').splice() == [Ival.port_str('0-7/tcp'),
                                                  Ival.port_str('8-11/tcp'),
                                                  Ival.port_str('12-13/tcp')]


def test_ival_splice2():
    'splicing a port-range, '
    ranges = Ival.splice(Ival.port_str('0-65535/tcp'))
    assert len(ranges) == 1
    assert ranges[0] == Ival.port_str('any/tcp')


def test_ival_network():
    'network is new ival for 1st value in ival'
    # network() preserves mask/length
    x = Ival.ip_pfx('10.10.10.10/24')
    y = x.network()
    assert y is not x
    assert y == Ival.ip_pfx('10.10.10.0/24')

    # for a portrange, you get the range back
    x = Ival.port_str('123-125/tcp')
    y = x.network()
    assert y is not x
    assert y == Ival.port_str('123-125/tcp')

    assert Ival.ip_pfx('1.1.1.1/31').network() == Ival.ip_pfx('1.1.1.0/31')
    assert Ival.ip_pfx('1.1.1.1/32').network() == Ival.ip_pfx('1.1.1.1/32')

    x = Ival.ip_pfx('0.0.0.0/0')
    y = x.network()
    assert y is not x
    assert y == Ival.ip_pfx('0.0.0.0/0')


def test_ival_broadcast1():
    'broadcast yields new ival for last value in ival'
    # also preserves mask
    x = Ival.port_str('12-15/tcp')
    y = x.broadcast()  # a no-op for PORTSTRings
    assert y is not x
    assert y == Ival.port_str('12-15/tcp')


def test_ival_broadcast2():
    x = Ival.ip_pfx('255.255.255.0/24')
    y = x.broadcast()
    assert y is not x
    assert y == Ival.ip_pfx('255.255.255.255/24')


def test_ival_broadcast3():
    x = Ival.ip_pfx('0.0.0.0/0')
    y = x.broadcast()
    assert y is not x
    assert y == Ival.ip_pfx('255.255.255.255/0')
    assert y.address() == Ival.ip_pfx('255.255.255.255/32')


def test_mask_imask():
    masks = [('0.0.0.0', '255.255.255.255'), ('128.0.0.0', '127.255.255.255'),
             ('192.0.0.0', '63.255.255.255'), ('224.0.0.0', '31.255.255.255'),
             ('240.0.0.0', '15.255.255.255'), ('248.0.0.0', '7.255.255.255'),
             ('252.0.0.0', '3.255.255.255'), ('254.0.0.0', '1.255.255.255'),
             ('255.0.0.0', '0.255.255.255'), ('255.128.0.0', '0.127.255.255'),
             ('255.192.0.0', '0.63.255.255'), ('255.224.0.0', '0.31.255.255'),
             ('255.240.0.0', '0.15.255.255'), ('255.248.0.0', '0.7.255.255'),
             ('255.252.0.0', '0.3.255.255'), ('255.254.0.0', '0.1.255.255'),
             ('255.255.0.0', '0.0.255.255'), ('255.255.128.0', '0.0.127.255'),
             ('255.255.192.0', '0.0.63.255'), ('255.255.224.0', '0.0.31.255'),
             ('255.255.240.0', '0.0.15.255'), ('255.255.248.0', '0.0.7.255'),
             ('255.255.252.0', '0.0.3.255'), ('255.255.254.0', '0.0.1.255'),
             ('255.255.255.0', '0.0.0.255'), ('255.255.255.128', '0.0.0.127'),
             ('255.255.255.192', '0.0.0.63'), ('255.255.255.224', '0.0.0.31'),
             ('255.255.255.240', '0.0.0.15'), ('255.255.255.248', '0.0.0.7'),
             ('255.255.255.252', '0.0.0.3'), ('255.255.255.254', '0.0.0.1'),
             ('255.255.255.255', '0.0.0.0')]

    for addr in ['0.0.0.0', '255.0.0.0', '255.255.0.0', '255.255.255.0',
                 '255.255.255.255', '1.1.1.1', '0.0.0.255', '0.0.255.255',
                 '0.255.255.255', '128.128.128.128', '197.197.197.197']:
        for pfxlen in range(33):
            ival = Ival.ip_pfx('{}/{}'.format(addr, pfxlen))
            mask, imask = masks[pfxlen]
            assert ival.mask() == mask
            assert ival.imask() == imask
