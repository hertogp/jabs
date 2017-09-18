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
        calls = ['dfm a.csv f1,f2',  # no -i flag
                 'dfm -i a.csv -o']  # no output file for -o flag

        for cli in calls:
            args = cli.split()
            with pytest.raises(SystemExit):
                opts = dfm.parse_args(args)



