#!/usr/bin/env python3


import sys
import random

import pytest

import ipf

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
        ipp = ipf.Ip4Proto()
        assert len(ipp._num_toname) == 0
        assert len(ipp._num_todesc) == 0
        assert len(ipp._name_tonum) == 0
        assert len(ipp._service_toports) == 0
        assert len(ipp._port_toservice) == 0

    def test_init_loading(self):
        ipp = ipf.Ip4Proto(proto_json='dta/ip4-protocols.json')
        assert len(ipp._num_toname) == 256
        assert len(ipp._num_todesc) == 256
        assert len(ipp._name_tonum) > 0

        ipp = ipf.Ip4Proto(services_json='dta/ip4-services.json')
        assert len(ipp._service_toports) > 0
        assert len(ipp._port_toservice) > 0


class TestIval_from_portstr(object):
    'test Ival.from_portstr'
    # portstr is:
    # any, any/protocol, port/protocol, port-port/protocol

    def test_any(self):
        # any port, any protocol -> length is 2**32 with base 0
        assert ipf.Ival.from_portstr('any') == ipf.Ival(0, 2**32)

    def test_any_proto(self):
        # any sctp port (port = 16 uint so 2**16 ports
        assert ipf.Ival.from_portstr('any/hopopt') == ipf.Ival(0, 2**16)
        assert ipf.Ival.from_portstr('any/tcp') == ipf.Ival(6 * 2**16, 2**16)
        assert ipf.Ival.from_portstr('any/udp') == ipf.Ival(17 * 2**16, 2**16)
        assert ipf.Ival.from_portstr('any/sctp') == ipf.Ival(132 * 2**16, 2**16)
        # only 255 has protocol name reserverd ... hmmm..
        assert ipf.Ival.from_portstr('any/reserved') == ipf.Ival(255 * 2**16, 2**16)

    def test_from_portstr_1port_protocol(self):
        assert ipf.Ival.from_portstr('0/sctp') == ipf.Ival(132 * 2**16 + 0, 1)
        assert ipf.Ival.from_portstr('1/sctp') == ipf.Ival(132 * 2**16 + 1, 1)
        assert ipf.Ival.from_portstr('65535/sctp') == ipf.Ival(132 * 2**16 +
                                                               65535, 1)

    def test_from_portstr_nports_protocol(self):
        # still 1 port
        assert ipf.Ival.from_portstr('0-0/sctp') == ipf.Ival(132 * 2**16, 1)
        # two ports
        assert ipf.Ival.from_portstr('0-1/sctp') == ipf.Ival(132 * 2**16, 2)
        # 128 ports
        assert ipf.Ival.from_portstr('0-127/sctp') == ipf.Ival(132 * 2**16, 128)
        # 130 ports (not a power of 2)
        assert ipf.Ival.from_portstr('1-130/sctp') == ipf.Ival(132 * 2**16 + 1, 130)



class TestIval_to_portstr(object):
    'test Ival.to_portstr'

    def test_any(self):
        assert ipf.Ival(0, 2**32).to_portstr() == 'any'




