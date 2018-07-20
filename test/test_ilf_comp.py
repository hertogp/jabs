'''
test ilf compiler
'''

import pytest
import sys
sys.path.insert(0, '..')
sys.path.insert(0, '.')


from jabs.ilf.comp import compile

# tmp
from jabs.ilf.core import Ival, pp2portstr, Ip4Filter

def test_bad_input():
    pass


def test_good_input():
    txt = """
        dns 53/udp, 53/tcp, 10.10.10.10, 10.10.11.11
        web 80/tcp, 443/tcp, 8080/tcp, 15-21/tcp, 18-31/tcp
        ~ 10/8 > 11/8 @ web : permit = { "color": "green"}
        ~ (dns) any <> dns  @ dns : permit = 10
    """
    ipf = compile(txt)

    m = ipf.match('10.1.2.3', '11.11.11.11', '8080/tcp')
    assert m.rule == 0
    assert m.action == 'permit'
    assert m.name == ''
    assert m.object == { "color": "green" }

    m = ipf.match('1.2.3.4', '10.10.10.10', '53/udp')
    assert m.rule == 1
    assert m.action == 'permit'
    assert m.name == 'dns'
    assert m.object == 10

    print(ipf.ruleset('1.2.3.4', '10.10.10.10', '53/udp'))
    print(ipf.ruleset('1.2.3.4', '10.10.10.10', None))
    print(ipf.ruleset(None, '10.10.10.10', None))
    print(ipf.ruleset(None, None, None))
    print(ipf.ruleset(None, None, '99/tcp'))



def test_csv_roundtrip():
    txt = """
        winAD 389/tcp, 135/udp, 135/tcp, 123/udp, 1.1.1.0/27, 445/tcp
        web 80/tcp, 8080/tcp, 443/tcp, 10.10.10.0/24
        ~ (auth) web > winAD @ winAD : permit = {"type": "auth"}
        ~ (webbers) any > web @ web : permit
    """
    ipf = compile(txt)
    csv1 = ipf.to_csv()
    csv2 = Ip4Filter().from_csv(csv1).to_csv()
    assert csv1 == csv2
    print(ipf.ruleset('10.10.10.10', '1.1.1.1', None))


def test_pp2portstr():
    assert '18/udp' == pp2portstr(18, 17)
    with pytest.raises(ValueError):
        assert '18/udp' == pp2portstr(-1, 17)
