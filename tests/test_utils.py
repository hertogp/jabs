#!/usr/bin/env python3


import sys
import random

import pytest

import utils


class TestStr2List(object):
    'test str2list'

    def test_str2list(self):
        'should split a string on <space> or <comma>'
        str2list = utils.str2list
        assert str2list('') == []
        assert str2list('a b') == ['a', 'b']
        assert str2list('a,B') == ['a', 'B']

class TestPfxStringHandlers(object):

    def test_pfx_proper(self):
        'pfx_proper ensures a well-formatted prefix string'
        # Does not turn ip addres into this-network address
        pfx_proper = utils.pfx_proper
        assert '10.0.0.0/8' == pfx_proper('10/8')
        assert '10.10.0.0/8' == pfx_proper('10.10/8')
        assert '10.10.10.0/8' == pfx_proper('10.10.10/8')
        assert '10.10.10.10/8' == pfx_proper('10.10.10.10/8')

        assert '0.0.0.0/0' == pfx_proper('0/0')
        assert '0.0.0.0/0' == pfx_proper('0.0/0')
        assert '0.0.0.0/0' == pfx_proper('0.0.0/0')
        assert '0.0.0.0/0' == pfx_proper('0.0.0.0/0')

class TestPfxSummarization(object):

    def test_ival_combine(self):
        'check intervals are combined properly'
        combi = utils.ival_combine
        # combine adjacent intervals of equal length
        assert ((10,12), None) == combi((10,6), (16,6))
        assert ((10,12), None) == combi((16,6), (10,6))

        # combine intervals where x in y or y in x
        assert ((10,5), None) == combi((10,5), (10,2))
        assert ((10,5), None) == combi((10,2), (10,5))

        # combine intervals where x == y
        assert ((10,5), None) == combi((10,5), (10,5))

    def test_pfx_summary_adjacent(self):
        'check how ip nrs are summarized'
        summ = utils.pfx_summary
        assert ['1.1.1.0/24'] == summ(['1.1.1.0/25', '1.1.1.128/25'])
        assert ['1.1.1.0/24'] == summ(['1.1.1.0/25', '1.1.1.128/25'])
        assert ['1.1.1.0/24'] == summ(['1.1.1.0/26', '1.1.1.64/26',
                                       '1.1.1.128/26', '1.1.1.192/26'])
        assert ['1.1.1.0/24'] == summ(['1.1.1.0/27', '1.1.1.32/27',
                                       '1.1.1.64/27', '1.1.1.96/27',
                                       '1.1.1.128/27', '1.1.1.160/27',
                                       '1.1.1.192/27', '1.1.1.224/27'])
        # same, scrambled ordering
        assert ['1.1.1.0/24'] == summ(['1.1.1.128/27',
                                       '1.1.1.32/27',
                                       '1.1.1.160/27',
                                       '1.1.1.64/27',
                                       '1.1.1.96/27',
                                       '1.1.1.224/27',
                                       '1.1.1.0/27',
                                       '1.1.1.192/27'])
        assert ['1.1.1.0/24'] == summ(['1.1.1.{}'.format(x) for x in
                                       range(0,256)])
        assert ['1.1.1.0/24'] == summ(['1.1.1.{}/24'.format(x) for x in
                                       range(0,256)])
        assert ['1.1.1.0/24'] == summ(['1.1.1.{}/25'.format(x) for x in
                                       range(0,256)])
        assert ['1.1.1.0/24'] == summ(['1.1.1.{}/30'.format(x) for x in
                                       range(0,256)])
        assert ['1.1.1.0/24'] == summ(['1.1.1.{}/32'.format(x) for x in
                                       range(0,256)])

    def test_pfx_summary_overlapping(self):
        summ = utils.pfx_summary
        assert ['1.1.1.0/24'] == summ(['1.1.1.0/24', '1.1.1.0/24'])
        assert ['1.1.1.0/24'] == summ(['1.1.1/24',
                                       '1.1.1.128/30'
                                       ])
        assert ['1.1.1.0/24'] == summ(['1.1.1/24',
                                       '1.1.1.8/30',
                                       '1.1.1.4/30',
                                       '1.1.1/30',
                                       '1.1.1.128/30',
                                       ])
        assert ['255.255.255.0/24'] == summ(['255.255.255/24',
                                             '255.255.255.255'])
        assert ['0.0.0.0/0'] == summ(['10.0.0.0/8','0/0'])

    def test_pfx_summary_nonoverlapping(self):
        summ = utils.pfx_summary
        assert ['1.1.1.0/25', '2.2.2.128/25'] == summ(['2.2.2.128/26',
                                                       '1.1.1/26',
                                                       '2.2.2.192/26',
                                                       '1.1.1.64/26',
                                                       ])
        assert ['1.0.0.0/8', '2.0.0.0/24'] == summ(['1/9', '1.128/9', '2/24'])
        assert ['1.1.1.250/30'] == summ(['1.1.1.250/32', '1.1.1.251/32',
                                      '1.1.1.252/32', '1.1.1.253/32'])


class TestCmdTokenizer(object):

    def test_whitespace(self):
        'whitespace in fields remains intact'
        toks = utils.cmd_tokens
        l = toks('f1,f2 f3,f4 f5')
        assert l == [(',', 'f1'), (',', 'f2 f3'), ('', 'f4 f5')]

    def test_single_word(self):
        'a single value is passed back without separator'
        toks = utils.cmd_tokens
        l = toks('f')
        assert l == [('', 'f')]

    def test_sep_comma(self):
        toks = utils.cmd_tokens
        l = toks('f1,f2,f1')
        assert l == [(',', 'f1'), (',', 'f2'), ('','f1')]

    def test_sep_equal(self):
        toks = utils.cmd_tokens
        l = toks('f1=f2')
        assert l == [('=', 'f1'), ('', 'f2')]

    def test_sep_doublecolon(self):
        toks = utils.cmd_tokens
        l = toks('func:a1')
        assert l == [(':', 'func'), ('', 'a1')]

    def test_sep_tilde(self):
        toks = utils.cmd_tokens
        l = toks('f1~f2')
        assert l == [('~', 'f1'), ('', 'f2')]

    def test_escaping(self):
        toks = utils.cmd_tokens
        # escape \,
        l = toks('f\,1,f2')
        assert l == [(',', 'f,1'), ('','f2')]
        # escape \=
        l = toks('val\=ue=func')
        assert l == [('=', 'val=ue'), ('', 'func')]
        # escape \:
        l = toks('f1:/val\:ue/')
        assert l == [(':', 'f1'), ('', '/val:ue/')]
        # escape \~
        l = toks('f1~val\~ue')
        assert l == [('~', 'f1'), ('', 'val~ue')]


class TestCmdParser(object):
    'check generic commands are parsed correctly'
    # syntax is f1,..=func:a1,.., where some fields are optional
    # - so in general: lhs=func:rhs
    # - f1,f2  - keep only these fields
    # - f=func: - call func and assign value to f
    # - f=func:a - same, but feed func arg a
    # - func:    - simply call func
    #
    # cmd_parser(cmd_str) ->[cmd_str, command, lhs-fields, rhs-fields]

    def test_default_cmd(self):
        parse = utils.cmd_parser
        tokens = utils.cmd_tokens
        cmd, lhs, rhs = parse(tokens('f1'))
        assert cmd == 'keep'
        assert lhs == ['f1']
        assert rhs == []

    def test_only_fields(self):
        parse = utils.cmd_parser
        tokens = utils.cmd_tokens
        cmd, lhs, rhs = parse(tokens('f1,f2'))
        assert cmd == 'keep'
        assert lhs == ['f1','f2']
        assert rhs == []

    def test_only_function(self):
        parse = utils.cmd_parser
        tokens = utils.cmd_tokens
        cmd, lhs, rhs = parse(tokens('func:'))
        assert cmd == 'func'
        assert lhs == []
        assert rhs == []

        cmd, lhs, rhs = parse(tokens('=func'))
        assert cmd == 'func'
        assert lhs == []
        assert rhs == []

        cmd, lhs, rhs = parse(tokens('=func:'))
        assert cmd == 'func'
        assert lhs == []
        assert rhs == []

    def test_lhs(self):
        parse = utils.cmd_parser
        tokens = utils.cmd_tokens
        cmd, lhs, rhs = parse(tokens('f1,f2=func:'))
        assert cmd == 'func'
        assert lhs == ['f1', 'f2']
        assert rhs == []

    def test_rhs(self):
        parse = utils.cmd_parser
        tokens = utils.cmd_tokens
        cmd, lhs, rhs = parse(tokens('func:a1,a2'))
        assert cmd == 'func'
        assert lhs == []
        assert rhs == ['a1', 'a2']

    def test_full_cmds(self):
        parse = utils.cmd_parser
        tokens = utils.cmd_tokens

        # call a func with args and assing to multiple fields
        cmd, lhs, rhs = parse(tokens('f1,f2=func:a1,a2'))
        assert cmd == 'func'
        assert lhs == ['f1', 'f2']
        assert rhs == ['a1', 'a2']

        # run regex against multiple fields
        cmd, lhs, rhs = parse(tokens('f1,f2~a1,a2'))
        assert cmd == 'regex'
        assert lhs == ['f1', 'f2']
        assert rhs == ['a1', 'a2']

        # same with =~
        cmd, lhs, rhs = parse(tokens('f1,f2=~a1,a2'))
        assert cmd == 'regex'
        assert lhs == ['f1', 'f2']
        assert rhs == ['a1', 'a2']

    def test_cmd_roundtrip(self):
        'command reconstruction from [cmd, lhs, rhs]'
        # utils.cmd_str(cmd, lhs, rhs) -> lhs=cmd:rhs
        parse = utils.cmd_parser
        tokens = utils.cmd_tokens
        tokens = utils.cmd_tokens
        recon = utils.cmd_str    # reconstruct from [cmd, lhs, rhs]

        cmd = 'f1~a1'  # -> command name regex
        assert recon(*parse(tokens(cmd))) == 'f1=regex:a1'

        cmd = '~a'
        assert recon(*parse(tokens(cmd))) == '=regex:a'

        cmd = 'f1,f2'  # -> default command keep (fields)
        assert recon(*parse(tokens(cmd))) == 'f1,f2=keep:'

        cmd = '=func'
        assert recon(*parse(tokens(cmd))) == cmd + ':'

        cmd = '=func:'
        assert recon(*parse(tokens(cmd))) == cmd

        cmd = 'f1,f2=func'
        assert recon(*parse(tokens(cmd))) == cmd + ':'

        cmd = 'f1,f2=func:'
        assert recon(*parse(tokens(cmd))) == cmd

        cmd = '=func:a1,a2'
        assert recon(*parse(tokens(cmd))) == cmd

        cmd = 'f,f2=func:a1,a2'
        assert recon(*parse(tokens(cmd))) == cmd



class TestUnitConversions(object):

    def test_uint2dotq(self):
        uint2dotq = utils.uint2dotq

        assert '0.0.0.0' == uint2dotq(0)
        assert '0.0.0.255' == uint2dotq(0x000000FF)
        assert '0.0.255.0' == uint2dotq(0x0000FF00)
        assert '0.255.0.0' == uint2dotq(0x00FF0000)
        assert '255.0.0.0' == uint2dotq(0xFF000000)

        assert '255.255.255.255' == uint2dotq(0xFFFFFFFF)
        assert '255.255.255.0' == uint2dotq(0xFFFFFF00)
        assert '255.255.0.255' == uint2dotq(0xFFFF00FF)
        assert '255.0.255.255' == uint2dotq(0xFF00FFFF)
        assert '0.255.255.255' == uint2dotq(0x00FFFFFF)

        assert '255.255.255.254' == uint2dotq(0xFFFFFFFE)
        assert '255.255.255.253' == uint2dotq(0xFFFFFFFD)
        assert '255.255.255.252' == uint2dotq(0xFFFFFFFC)

        with pytest.raises(ValueError):
            uint2dotq(-1)

        with pytest.raises(ValueError):
            uint2dotq(2**32)

    def test_dotq2uint(self):
        dotq2uint = utils.dotq2uint

        # include shorthand notation
        assert 0 == dotq2uint('0.0.0.0')
        assert 0 == dotq2uint('0.0.0')
        assert 0 == dotq2uint('0.0')
        assert 0 == dotq2uint('0')

        assert 0x000000FF == dotq2uint('0.0.0.255')
        assert 0x0000FFFF == dotq2uint('0.0.255.255')
        assert 0x00FFFFFF == dotq2uint('0.255.255.255')
        assert 0xFFFFFFFF == dotq2uint('255.255.255.255')

        # include shorthand notation
        assert 0xFF000000 == dotq2uint('255.0.0.0')
        assert 0xFF000000 == dotq2uint('255.0.0')
        assert 0xFF000000 == dotq2uint('255.0')
        assert 0xFF000000 == dotq2uint('255')

        assert 0x0A0B0C0D == dotq2uint('10.11.12.13')
        assert 0x01020304 == dotq2uint('1.2.3.4')

        with pytest.raises(ValueError):
            dotq2uint('')
        with pytest.raises(ValueError):
            dotq2uint('.')
        with pytest.raises(ValueError):
            dotq2uint('1.1.1.x')

    def test_len2mask(self):
        len2mask = utils.len2mask

        assert 0x0 == len2mask(0)
        assert 0xFF000000 == len2mask(8)
        assert 0xFFFF0000 == len2mask(16)
        assert 0xFFFFFF00 == len2mask(24)
        assert 0xFFFFFFFF == len2mask(32)

    def test_mask2len(self):
        mask2len = utils.mask2len

        assert mask2len(0x0) == 0
        assert mask2len(0xFF000000) == 8
        assert mask2len(0xFFFF0000) == 16
        assert mask2len(0xFFFFFF00) == 24
        assert mask2len(0xFFFFFFFF) == 32

    def test_len2imask(self):
        len2imask = utils.len2imask

        assert 0xFFFFFFFF == len2imask(0)
        assert 0x00FFFFFF == len2imask(8)
        assert 0x0000FFFF == len2imask(16)
        assert 0x000000FF == len2imask(24)
        assert 0x00000000 == len2imask(32)

    def test_imask2len(self):
        imask2len = utils.imask2len

        assert imask2len(0xFFFFFFFF) == 0
        assert imask2len(0x00FFFFFF) == 8
        assert imask2len(0x0000FFFF) == 16
        assert imask2len(0x000000FF) == 24
        assert imask2len(0x00000000) == 32



