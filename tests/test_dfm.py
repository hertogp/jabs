#!/usr/bin/env python3

import sys
import pytest

import dfm


class TestParseArgs(object):
    'test cli argument parsing'

    def test_verbose_flag(self):
        'test verbose flag'
        # by default verbose is 0
        opts = dfm.parse_args('dfm -i dummy.csv'.split())
        assert opts.v == 0

        # nx -v or -v*n should lead to verbose=n
        opts = dfm.parse_args('dfm -v -i dummy.csv'.split())
        assert opts.v == 1
        opts = dfm.parse_args('dfm -vv -i dummy.csv'.split())
        assert opts.v == 2
        opts = dfm.parse_args('dfm -v -v -v -i dummy.csv'.split())
        assert opts.v == 3

    def test_output_file_flag(self):
        opts = dfm.parse_args('dfm -i dummy.csv'.split())
        assert opts.o == sys.stdout  # default to stdout
        opts = dfm.parse_args('dfm -i dummy.csv -o output.csv'.split())
        assert opts.o == 'output.csv'
        opts = dfm.parse_args('dfm -i dummy.csv -o ouTPut.csv'.split())
        assert opts.o == 'ouTPut.csv'


    def test_input_file_flag(self):
        'test -i file.csv flag'
        with pytest.raises(SystemExit):
            opts = dfm.parse_args('dfm -v src,dst'.split())

    def test_defaults(self):
        'test defaults for dfm flags'
        opts = dfm.parse_args('dfm -i dummy.csv'.split())
        assert opts.v == 0
        assert opts.o == sys.stdout
        assert opts.cmds == []
        assert opts.commands == []
        assert opts.prog == 'dfm'
        with pytest.raises(SystemExit):
            opts = dfm.parse_args('dfm -i a.csv --version'.split())

    def test_good_cmds(self):
        'check some generic simple command parsing'
        calls = ['dfm -i a.csv f1,f2',
                 'dfm -i a.csv f1,f2=func:a1,a2',
                 'dfm -i a.csv f1,f2 f1',
                 'dfm -i a.csv f1,f2=func:a1,a2 f1,f2']
        for cli in calls:
            args = cli.split()
            opts = dfm.parse_args(args)
            assert len(opts.cmds) == len(opts.commands)
            # note: minus the ['dfm' '-i' 'a.csv']
            assert len(opts.cmds) == len(args) - 3

    def test_bad_cmds(self):
        'check some generic bad commands'
        # these calls should bail out and abort the program
        calls = ['dfm a.csv f1,f2',
                 'dfm -i a.csv -o']

        for cli in calls:
            args = cli.split()
            with pytest.raises(SystemExit):
                opts = dfm.parse_args(args)

class TestCmdTokenizer(object):

    def test_whitespace(self):
        'whitespace in fields remains intact'
        toks = dfm.tokenizer
        l = toks('f1,f2 f3,f4 f5')
        assert l == [(',', 'f1'), (',', 'f2 f3'), ('', 'f4 f5')]

    def test_single_word(self):
        'a single value is passed back without separator'
        toks = dfm.tokenizer
        l = toks('f')
        assert l == [('', 'f')]

    def test_sep_comma(self):
        toks = dfm.tokenizer
        l = toks('f1,f2,f1')
        assert l == [(',', 'f1'), (',', 'f2'), ('','f1')]

    def test_sep_equal(self):
        toks = dfm.tokenizer
        l = toks('f1=f2')
        assert l == [('=', 'f1'), ('', 'f2')]

    def test_sep_doublecolon(self):
        toks = dfm.tokenizer
        l = toks('func:a1')
        assert l == [(':', 'func'), ('', 'a1')]

    def test_sep_tilde(self):
        toks = dfm.tokenizer
        l = toks('f1~f2')
        assert l == [('~', 'f1'), ('', 'f2')]

    def test_escaping(self):
        toks = dfm.tokenizer
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
    # parse_cmd(cmd_str) ->[cmd_str, command, lhs-fields, rhs-fields]

    def test_default_cmd(self):
        pc = dfm.parse_cmd
        org, cmd, lhs, rhs = pc('f1')
        assert org == 'f1'
        assert cmd == 'keep'
        assert lhs == ['f1']
        assert rhs == []

    def test_only_fields(self):
        pc = dfm.parse_cmd
        org, cmd, lhs, rhs = pc('f1,f2')
        assert org == 'f1,f2'
        assert cmd == 'keep'
        assert lhs == ['f1','f2']
        assert rhs == []

    def test_only_function(self):
        pc = dfm.parse_cmd
        org, cmd, lhs, rhs = pc('func:')
        assert org == 'func:'
        assert cmd == 'func'
        assert lhs == []
        assert rhs == []

        org, cmd, lhs, rhs = pc('=func')
        assert org == '=func'
        assert cmd == 'func'
        assert lhs == []
        assert rhs == []

        org, cmd, lhs, rhs = pc('=func:')
        assert org == '=func:'
        assert cmd == 'func'
        assert lhs == []
        assert rhs == []

    def test_lhs(self):
        pc = dfm.parse_cmd
        org, cmd, lhs, rhs = pc('f1,f2=func:')
        assert org == 'f1,f2=func:'
        assert cmd == 'func'
        assert lhs == ['f1', 'f2']
        assert rhs == []

    def test_rhs(self):
        pc = dfm.parse_cmd
        org, cmd, lhs, rhs = pc('func:a1,a2')
        assert org == 'func:a1,a2'
        assert cmd == 'func'
        assert lhs == []
        assert rhs == ['a1', 'a2']

    def test_full_cmds(self):
        pc = dfm.parse_cmd

        # call a func with args and assing to multiple fields
        org, cmd, lhs, rhs = pc('f1,f2=func:a1,a2')
        assert org == 'f1,f2=func:a1,a2'
        assert cmd == 'func'
        assert lhs == ['f1', 'f2']
        assert rhs == ['a1', 'a2']

        # run regex against multiple fields
        org, cmd, lhs, rhs = pc('f1,f2~a1,a2')
        assert org == 'f1,f2~a1,a2'
        assert cmd == 'regex'
        assert lhs == ['f1', 'f2']
        assert rhs == ['a1', 'a2']

        # same with =~
        org, cmd, lhs, rhs = pc('f1,f2=~a1,a2')
        assert org == 'f1,f2=~a1,a2'
        assert cmd == 'regex'
        assert lhs == ['f1', 'f2']
        assert rhs == ['a1', 'a2']

    def test_cmd_roundtrip(self):
        'command reconstruction from [cmd, lhs, rhs]'
        # dfm.cmd_str(cmd, lhs, rhs) -> lhs=cmd:rhs
        p = dfm.parse_cmd  # parse command -> [org, cmd, lhs, rhs]
        r = dfm.cmd_str    # reconstruct from [cmd, lhs, rhs]

        cmd = 'f1~a1'  # -> command name regex
        assert r(*p(cmd)[1:]) == 'f1=regex:a1'

        cmd = '~a1'
        assert r(*p(cmd)[1:]) == '=regex:a1'

        cmd = 'f1,f2'  # -> default command keep (fields)
        assert r(*p(cmd)[1:]) == 'f1,f2=keep:'

        cmd = '=func'
        assert r(*p(cmd)[1:]) == cmd + ':'

        cmd = '=func:'
        assert r(*p(cmd)[1:]) == cmd

        cmd = 'func:'
        assert r(*p(cmd)[1:]) == '=func:'

        cmd = 'f1,f2=func'
        assert r(*p(cmd)[1:]) == cmd + ':'

        cmd = 'f1,f2=func:'
        assert r(*p(cmd)[1:]) == cmd

        cmd = '=func:a1,a2'
        assert r(*p(cmd)[1:]) == cmd

        cmd = 'f1,f2=func:a1,a2'
        assert r(*p(cmd)[1:]) == cmd




