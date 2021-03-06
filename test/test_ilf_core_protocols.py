'''
test Ip4Protocol
'''

import pytest
import sys
sys.path.insert(0, '..')
sys.path.insert(0, '.')

from jabs import ilf


KNOWN_PROTOS = [('icmp', 1),
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


def test_init():
    'initial object has 256 entries in all 3 hashes'
    ipp = ilf.Ip4Protocol()
    assert len(ipp._num_toname) == 256
    assert len(ipp._num_todesc) == 256
    assert len(ipp._name_tonum) == 256


def test_known():
    'test some known name/protocol number translations'
    ipp = ilf.Ip4Protocol()
    for name, proto in KNOWN_PROTOS:
        assert name == ipp.getnamebyproto(proto)
        assert proto == ipp.getprotobyname(name)


def test_roundtrip():
    'check roundtrip translation proto>name>proto'
    ipp = ilf.Ip4Protocol()
    PROT = ilf.numbers.IP4PROTOCOLS
    for proto, (name, desc) in PROT.items():
        assert name == ipp.getnamebyproto(proto)
        assert proto == ipp.getprotobyname(name)


def test_name_tonum():
    'name, acquired by number, maps back to same protocol number'
    ipp = ilf.Ip4Protocol()
    for num in range(255):
        name = ipp.getnamebyproto(num)
        assert num == ipp.getprotobyname(name)


def test_raise_valueerror():
    'invalid protocol numbers raise ValueError'
    ipp = ilf.Ip4Protocol()

    with pytest.raises(ValueError):
        ipp.getnamebyproto(256)

    with pytest.raises(ValueError):
        ipp.getnamebyproto(-1)
