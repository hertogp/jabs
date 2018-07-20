'''
test Ip4Filter
'''

import sys
sys.path.insert(0, '..')
sys.path.insert(0, '.')
import pytest

from jabs import ilf

# -- INIT tests

def test_init():
    'test simple init and initial values'
    ipf = ilf.Ip4Filter()
    assert ipf._nomatch == None
    assert len(ipf) == 0


def test_init_nomatch():
    'test different nomatch-values on init'
    class myMatch(object):
        pass

    def myFunc():
        pass

    nomatches = [
        'a string',
        ['a', 'list'],
        {'a': 'dict'},
        object(),  # an object
        None,
        True,
        False,
        myMatch(),  # an instance
        myMatch,    # a class
        myFunc      # a function
    ]

    for nomatch in nomatches:
        ipf = ilf.Ip4Filter(nomatch)
        assert ipf._nomatch is nomatch  # same object (!)

# -- ADD

def test_add_simple():
    'simple rule addition'
    ipf = ilf.Ip4Filter()

    ipf.add(0, ['10/8'], ['11/8'], ['80-81/tcp'], 'deny', 'NoGo', None)
    assert len(ipf) == 1
    dct = ipf.as_dict
    assert dct[0]['src'] == ['10.0.0.0/8']
    assert dct[0]['dst'] == ['11.0.0.0/8']
    assert dct[0]['srv'] == ['80-81/tcp']
    assert dct[0]['name'] == 'NoGo'
    assert dct[0]['action'] == 'deny'
    assert dct[0]['obj'] is None


def test_add_to_src():
    'add to src only'
    ipf = ilf.Ip4Filter()

    ipf.add(0, ['10/8'], ['11/8'], ['80-81/tcp'], 'deny', 'NoGo', None)
    ipf.add(0, ['9/8'], [], [])
    assert len(ipf) == 1

    dct = ipf.as_dict
    assert '9.0.0.0/8' in dct[0]['src']
    assert '10.0.0.0/8' in dct[0]['src']


def test_add_to_dst():
    'add to dst only'
    ipf = ilf.Ip4Filter()

    ipf.add(0, ['10/8'], ['11/8'], ['80-81/tcp'], 'deny', 'NoGo', None)
    ipf.add(0, [], ['12/8'], [])
    assert len(ipf) == 1

    dct = ipf.as_dict
    assert '11.0.0.0/8' in dct[0]['dst']
    assert '12.0.0.0/8' in dct[0]['dst']


def test_add_to_srv():
    'add to services only'
    ipf = ilf.Ip4Filter()

    ipf.add(0, ['10/8'], ['11/8'], ['80-81/tcp'], 'deny', 'NoGo', None)
    ipf.add(0, [], [], ['99/udp'])
    assert len(ipf) == 1

    dct = ipf.as_dict
    assert '99/udp' in dct[0]['srv']
    assert '80-81/tcp' in dct[0]['srv']


def test_partial_add_respects_action():
    "a partial add does not change a rule's action"
    ipf = ilf.Ip4Filter()

    ipf.add(0, ['10/8'], ['11/8'], ['80-81/tcp'], 'deny', 'NoGo', None)
    ipf.add(0, [],[],[], action='not-deny-anymore')
    assert len(ipf) == 1

    dct = ipf.as_dict
    assert dct[0]['action'] == 'deny'


def test_partial_add_respects_name():
    "a partial add does not change a rule's name"
    ipf = ilf.Ip4Filter()

    ipf.add(0, ['10/8'], ['11/8'], ['80-81/tcp'], 'deny', 'NoGo', None)
    ipf.add(0, [],[],[], name='not-NoGo-anymore')
    assert len(ipf) == 1

    dct = ipf.as_dict
    assert len(ipf) == 1
    assert dct[0]['name'] == 'NoGo'


def test_partial_add_respects_obj():
    "a partial add does not change a rule's object"
    ipf = ilf.Ip4Filter()

    ipf.add(0, ['10/8'], ['11/8'], ['80-81/tcp'], 'deny', 'NoGo', None)
    ipf.add(0, [],[],[], obj='not-None-anymore')
    assert len(ipf) == 1

    dct = ipf.as_dict
    assert dct[0]['obj'] is None


def test_add_bad_src():
    'a bad src list yields an exception'
    # bad digit(s)
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, ['256/8'], [], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, ['1.256/8'], [], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, ['1.1.256/8'], [], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, ['1.1.1.256/8'], [], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, ['1.1.1.1.256/8'], [], [])

    # bad length
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, ['1.1.1.1/38'], [], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, ['1.1.1.1/-1'], [], [])


def test_add_bad_dst():
    'a bad dst list yields an exception'

    # wrong value for address digit
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], ['256/8'], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], ['1.256/8'], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], ['1.1.256/8'], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], ['1.1.1.256/8'], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], ['1.1.1.1.256/8'], [])

    # wrong value for prefix length
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], ['1.1.1.1/-1'], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], ['1.1.1.1/eight'], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], ['1.1.1.1/'], [])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], ['1.1.1.1/33'], [])



def test_add_bad_srv():
    'a bad srv list yields an exception'
    # bad port number
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], [], ['65536/udp'])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], [], ['hundred/udp'])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], [], ['-1/udp'])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], [], ['1e3/udp'])

    # bad proto name
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], [], ['256/not-a-proto-name'])
    with pytest.raises(ValueError):
        ilf.Ip4Filter().add(42, [], [], ['100/17'])


def test_action_lowercased():
    ipf = ilf.Ip4Filter()

    ipf.add(0, ['10/8'], ['11/8'], ['80-81/tcp'], action='PermiT')
    dct = ipf.as_dict
    assert dct[0]['action'] == 'permit'



# -- AS_DICT

def test_as_dict():
    'changing as_dict property does not change Ip4Filter'
    ipf = ilf.Ip4Filter()
    ipf.add(0, ['1.1.1.1'], ['2.2.2.2'], ['80/tcp'])
    m0 = ipf.as_dict
    ipf.as_dict[2] = None
    m1 = ipf.as_dict
    assert m0 == m1

# -- MATCH



# -- CSV


