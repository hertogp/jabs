'''
test parser
'''

import io
import sys
sys.path.insert(0, '.')
sys.path.insert(0, '..')
import jabs.ilf.parse as jp

# Notes:
# o statements are terminated by a new line
# o jabs.ilf.parse.parse expects a file-like object
# ast = [(pos, stmt), ..]

# GROUP
# ('GROUP', name, [items..])


def test_group1():
    'group single entry'
    fhdl = io.StringIO('dns 53/tcp\n')
    p = jp.parse(fhdl)
    assert p is not None
    assert len(p) == 1
    _, stmt = p[0]
    assert len(stmt) == 3
    assert stmt[0] == 'GROUP'
    assert stmt[1] == 'dns'
    assert len(stmt[2]) == 1
    assert stmt[2][0] == ('PORTSTR', '53/tcp')


def test_group2():
    'group multiple entries'
    fhdl = io.StringIO('dns 53/tcp, 53/udp\n')
    p = jp.parse(fhdl)
    assert p is not None
    assert len(p) == 1
    _, stmt = p[0]
    assert len(stmt) == 3
    assert stmt[0] == 'GROUP'
    assert stmt[1] == 'dns'
    assert len(stmt[2]) == 2
    assert ('PORTSTR', '53/tcp') in stmt[2]
    assert ('PORTSTR', '53/udp') in stmt[2]


def test_group3():
    'group accepts IP, PORTSTR and STRs'
    fhdl = io.StringIO('dns 53/tcp, 53/udp, 1.2.3.4, 4.3.2.1, dns-01\n')
    p = jp.parse(fhdl)
    assert p is not None
    assert len(p) == 1
    _, stmt = p[0]
    assert len(stmt) == 3
    assert stmt[0] == 'GROUP'
    assert stmt[1] == 'dns'
    assert len(stmt[2]) == 5
    assert ('PORTSTR', '53/tcp') in stmt[2]
    assert ('PORTSTR', '53/udp') in stmt[2]
    assert ('IP', '1.2.3.4') in stmt[2]
    assert ('IP', '4.3.2.1') in stmt[2]
    assert ('STR', 'dns-01') in stmt[2]

# -- INCLUDE


def test_include1():
    'filename is PARENSTR, matches all inside parens'
    fname = 'a:weird@file>name'
    fhdl = io.StringIO('include ({})\n'.format(fname))
    p = jp.parse(fhdl)
    assert p is not None
    assert len(p) == 1
    _, stmt = p[0]
    assert stmt == ('INCLUDE', fname)


def test_include2():
    'empty filename is not an error'
    fname = ''
    fhdl = io.StringIO('include ({})\n'.format(fname))
    p = jp.parse(fhdl)
    assert p is not None
    assert len(p) == 1
    _, stmt = p[0]
    assert stmt == ('INCLUDE', fname)


def test_include_error():
    'unbalanced parens, missing open'
    fname = ''
    fhdl = io.StringIO('include {})\n'.format(fname))
    p = jp.parse(fhdl)
    assert p is not None
    assert len(p) == 1
    _, stmt = p[0]
    # ('ERROR', 'INCLUDE', 'some description')
    assert stmt[0:2] == ('ERROR', 'INCLUDE')


# -- RULE

def test_rule_good():
    'RULE stmt always has 8 fields'
    # ('RULE', tag, src-list, DIR, dst-list, port-list, action, json)
    lines = [
        '~ src > dst @ port : drop\n',
        '~ (my-tag) src <> dst @ ports : permit {"name": "duh"}\n',
        '~ () src, src2 > dst,dst2 @ ports,ports2 : drop\n',
        ]
    for line in lines:
        fhdl = io.StringIO(line)
        p = jp.parse(fhdl)
        assert p is not None
        print(p)
        assert len(p) == 1
        _, stmt = p[0]
        assert len(stmt) == 8
        assert stmt[0] == 'RULE'


def test_rule_good_compact():
    'RULE stmt can be compact'
    # ('RULE', tag, src-list, DIR, dst-list, port-list, action, json)
    lines = [
        '~src>dst@port:drop\n',
        '~(my-tag)src<>dst@ports:permit{"name":"duh"}\n',
        '~()src,src2>dst,dst2@ports,ports2:drop{}\n',
        ]
    for line in lines:
        fhdl = io.StringIO(line)
        p = jp.parse(fhdl)
        assert p is not None
        print(p)
        assert len(p) == 1
        _, stmt = p[0]
        assert len(stmt) == 8
        assert stmt[0] == 'RULE'


# -- RULEPLUS


def test_ruleplus_src():
    'add sources to a rule'
    fhdl = io.StringIO('+ < net1, net2\n')
    p = jp.parse(fhdl)
    assert p is not None
    assert len(p) == 1
    _, stmt = p[0]
    assert stmt[0] == 'RULEPLUS'
    assert stmt[1] == '<'
    assert stmt[2] == [('STR', 'net1'), ('STR', 'net2')]


def test_ruleplus_dst():
    'add dsts to a rule'
    fhdl = io.StringIO('+ > net1, net2\n')
    p = jp.parse(fhdl)
    assert p is not None
    assert len(p) == 1
    _, stmt = p[0]
    assert stmt[0] == 'RULEPLUS'
    assert stmt[1] == '>'
    assert stmt[2] == [('STR', 'net1'), ('STR', 'net2')]


def test_ruleplus_service():
    'add services to a rule'
    fhdl = io.StringIO('+ @ 80/tcp, portset2\n')
    p = jp.parse(fhdl)
    assert p is not None
    assert len(p) == 1
    _, stmt = p[0]
    assert stmt[0] == 'RULEPLUS'
    assert stmt[1] == '@'
    assert stmt[2] == [('PORTSTR', '80/tcp'), ('STR', 'portset2')]
    print(p)


# -- ILF SCRIPT


def test_multi_line1():
    'test a sample filter script'
    lines = [
        'dns 53/udp, 53/tcp, 1.2.3.4, 4.3.2.1',
        'web www-http, 80/tcp, 8080/tcp',
        'include (std-services.ilf)',
        'include (block-rules)',
        '~ home > dns @ dns : permit',
        '~ home > web @ any : permit',
        '~ any > home @ any : drop',
        '~ any <> any @ any : discard'
        ]
    # need to terminate last statement with '\n' as well.
    script = '\n'.join(lines) + '\n'
    fhdl = io.StringIO(script)
    p = jp.parse(fhdl)
    for pos, stmt in p:
        print(stmt)
    assert p is not None
    assert len(p) == 8
    stypes = [stmt[0] for _, stmt in p]
    assert stypes == ['GROUP', 'GROUP', 'INCLUDE', 'INCLUDE',
                      'RULE', 'RULE', 'RULE', 'RULE']

