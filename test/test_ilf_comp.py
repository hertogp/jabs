'''
test ilf compiler
'''

import sys
sys.path.insert(0, '..')
sys.path.insert(0, '.')

from jabs.ilf.comp import compile

# tmp
from jabs.ilf.core import Ival, lowest_bit

def test_bad_input():
    pass

def test_good_input():
    txt = """
        dns 53/udp, 53/tcp, 10.10.10.10, 10.10.11.11
        web 80/tcp, 443/tcp, 8080/tcp, 15-21/tcp, 22-31/tcp
        ~ (web) 10/8 > 11/8 @ web : permit { "tag": "web"}
        ~ (dns) any <> dns  @ dns : permit
    """
    ip4f = compile(txt)
    assert ip4f.match('1.1.1.1', '10.10.10.10', '53/udp') == True
    src, dst, dport = '10.10.10.10', '11.11.11.11', '8080/tcp'
    print(src, '>', dst, '@', dport, '->', ip4f.get(src, dst, dport))
    src = None
    print(src, '>', dst, '@', dport, '->', ip4f.get(src, dst, dport))



