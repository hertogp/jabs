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

    def test_intial_info(self):
        p = ipf.Ip4Proto()
        assert len(p._n2p) > 0
        assert len(p._n2p) == len(p._p2n)
        assert len(p._n2p) == len(p._n2d)
        assert len(p._s2pp) > 0
        assert len(p._pp2s) > 0

    def _test_protos(self, p):
        'test proto_ functions using specific instance p'
        for num, name in p._n2p.items():
            assert p.proto_toname(num) == name
            assert p.proto_byname(name) == num

        for name, num in p._p2n.items():
            assert p.proto_byname(name) == num
            assert p.proto_toname(num) == name


    def test_protos_initial(self):
        'test proto_xxname functions'
        p = ipf.Ip4Proto()
        self._test_protos(p)

    def test_loaded_protos(self):
        p = ipf.Ip4Proto().load_files()
        self._test_protos(p)

    def test_initital_known_protos(self):
        'test protocol names initially known'
        p = ipf.Ip4Proto()
        for name, proto in self.known_protos:
            assert p.proto_byname(name) == proto
            assert p.proto_toname(proto) == name

    def test_loaded_protos(self):
        'test some protocol names after loading files'
        p = ipf.Ip4Proto().load_files()
        for name, proto in self.known_protos:
            assert p.proto_byname(name) == proto
            assert p.proto_toname(proto) == name

    def _test_services(self, p):
        'test pp_xxservice functions'
        for s, pps in p._s2pp.items():
            # service -> [(port, proto), ..], e.g. https, [(443, 6), (443, 17)]
            # check pp_byservice returns the proper set of (p,p)'s given a name
            assert set(pps) == set(p.pp_byservice(s))
            for pp in pps:
                # check pp_toservice returns correct service given a (p,p)
                assert s == p.pp_toservice(*pp)

    def test_initial_services(self):
        p = ipf.Ip4Proto()
        self._test_services(p)

    def test_loaded_services(self):
        p = ipf.Ip4Proto().load_files()
        self._test_services(p)

    def test_initial_known_services(self):
        'test some original services known'
        p = ipf.Ip4Proto()
        known_services = [('https', [(443, 6), (443, 17)]),
                          ('http', [(80, 6), (80, 17)]),
                          ('snmp', [(161, 17)]),
                          ('smtp', [(25, 6)]),
                          ('dns', [(53, 6), (53,17)]),
                          ]
        for s, pps in known_services:
            for pp in pps:
                assert s == p.pp_toservice(*pp)
                assert set(pps) == set(p.pp_byservice(s))

    def test_proto_dct_integrity(self):
        'check ._n2p and _.p2n maps are complementary'
        p = ipf.Ip4Proto().load_files()
        # protocol name <-> protocol number
        for name, num in p._p2n.items():
            assert num in p._n2p
            assert name == p._n2p[num]
        # protocol number <-> protocol name
        for num, name in p._n2p.items():
            assert name in p._p2n
            assert num == p._p2n[name]

    def test_serv_dct_integrity(self):
        'check ._pp2s and ._s2pp maps are complementary'
        p = ipf.Ip4Proto().load_files()
        # (port, protocols) <-> name
        for pp, name in p._pp2s.items():
            assert name in p._s2pp
            assert pp in p._s2pp[name]
        # name <-> [(port, protocol), ..]
        for name, pps in p._s2pp.items():
            for pp in pps:
                assert p._pp2s[pp] == name

    def _test_ports(self, p):
        'test ports "num/protocol"-string <-> (num, protonr)'
        # self._n2p and self._p2n are complementary

        for name, proto_num in p._p2n.items():
            port_num = random.randrange(65535)
            port = '{}/{}'.format(port_num, name)
            # 80/tcp -> (80, 6)
            assert (port_num, proto_num) == p.pp_byport(port)
            # (80, 6) -> 80/tcp
            assert port == p.pp_toport(port_num, proto_num)

    def test_initial_ports(self):
        p = ipf.Ip4Proto()
        self._test_ports(p)

    def test_loaded_ports(self):
        p = ipf.Ip4Proto().load_files()
        self._test_ports(p)

    def test_some_common_ports(self):
        'simply to show usage of pp_byport'
        p = ipf.Ip4Proto().load_files()
        assert p.pp_byport('80/tcp') == (80, 6)
        assert p.pp_byport('443/tcp') == (443, 6)
        assert p.pp_byport('25/tcp') == (25, 6)

        assert p.pp_byport('53/udp') == (53, 17)
        assert p.pp_byport('161/udp') == (161, 17)

    def test_some_common_services(self):
        'simply to show usage of pp_byservice'
        p = ipf.Ip4Proto().load_files()
        assert (53, 17) in p.pp_byservice('domain')
        assert (443, 6) in p.pp_byservice('https')
        assert (22, 6) in p.pp_byservice('ssh')

    def test_names_are_case_insensitive(self):
        'check lookups are performed case-insensitive'
        p = ipf.Ip4Proto().load_files()
        assert (22, 6) in p.pp_byservice('SsH')
        assert (443, 6) in p.pp_byservice('HtTpS')

        assert 6 == p.proto_byname('TcP')
        assert 17 == p.proto_byname('uDp')

        assert (80, 6) == p.pp_byport('80/TcP')

    def test_failed_ports(self):
        'check error values when lookup fails'
        p = ipf.Ip4Proto().load_files()
        assert (1, -1) == p.pp_byport('1/xxx')      # unknown protocol name
        assert (-1, -1) == p.pp_byport('25')        # missing protocol name
        assert (-1, -1) == p.pp_byport('tcp')       # missing port number
        assert (-1, 6) == p.pp_byport('65536/tcp')  # illegal port number
        assert (-1, -1) == p.pp_byport(123)         # wrong type of arg
        assert (-1, -1) == p.pp_byport(12.3)         # wrong type of arg

        assert '25/invalid' == p.pp_toport(25, 256) # illegal protocol number
        assert '-1/tcp' == p.pp_toport(65536, 6)    # illegal port number
        assert '-1/invalid' == p.pp_toport(65536, 256) # both illegal
        with pytest.raises(TypeError):
            p.pp_toport(25, '256')
            p.pp_toport('25', 60)

    def test_failed_services(self):
        'check error values when lookup fails'
        p = ipf.Ip4Proto().load_files()

        assert [(-1, -1)] == p.pp_byservice('xxx')  # unknown service

        assert 'invalid' == p.pp_toservice(65536, 6) # illegal port nr
        assert 'invalid' == p.pp_toservice(-1, 6)
        assert 'invalid' == p.pp_toservice(25, 256)  # illegal proto nr
        assert 'invalid' == p.pp_toservice(25, -1)
        assert 'invalid' == p.pp_toservice(65536, 256) # both illegal
        assert 'invalid' == p.pp_toservice(-1, -1) # both illegal

        with pytest.raises(TypeError):
            p.pp_toservice(25, '6')
            p.pp_toservice('25', 6)
            p.pp_toservice('25', '6')


    def test_failed_protocols(self):
        'check error values when lookup fails'
        p = ipf.Ip4Proto().load_files()

        assert 'invalid' == p.proto_toname(-1)       # illegal proto nr
        assert 'invalid' == p.proto_toname(256)

        assert -1 == p.proto_byname('xxx')           # unknown proto name

        with pytest.raises(TypeError):
            p.proto_toname('1')
            p.proto_byname(16)

