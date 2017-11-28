'''
test dfm script
'''

import logging
import sys
sys.path.insert(0, '../jabs')  # in case we run test inside test dir

import dfm


def test_verbose_warn():
    'test verbose flag'
    # by default verbose is 0
    opts = dfm.parse_args('dfm r:dummy.csv'.split())
    assert opts.log_level == logging.WARNING

def test_verbose_info():
    opts = dfm.parse_args('dfm -v r:dummy.csv'.split())
    assert opts.log_level == logging.INFO

def test_verbose_debug():
    opts = dfm.parse_args('dfm -d r:dummy.csv'.split())
    assert opts.log_level == logging.DEBUG

def test_good_cmds():
    'check some generic simple command parsing'
    calls = ['dfm r:a.csv f1,f2',
             'dfm r:a.csv f1,f2=func:a1,a2',
             'dfm r:a.csv f1,f2 f1',
             'dfm r:a.csv f1,f2=func:a1,a2 f1,f2']
    for cli in calls:
        args = cli.split()
        opts = dfm.parse_args(args)
        assert len(opts.cmds) == len(opts.command)
        assert len(opts.cmds) == len(args) - 1
