#!/usr/bin/env python3

import sys

print(sys.path)
import dfm


class TestParseArgs(object):
    'test cli argument parsing'

    def test_verbose_flag(self):
        opts = dfm.parse_args(['dfm', '-v', '-v'])
        assert opts.v == 2




