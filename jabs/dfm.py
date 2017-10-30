#!/usr/bin/env python3

'''
syntax: dfm command ...
info: read, manipulate and write datasets using pandas
descr:
    Read a dataset from disk, apply various commands and write results to stdout
    or a given filename.

    dfm r:logs.csv svpn=ipl:vpn_nets,src_ip w:logs-named.csv

    dfm executes the commands left-to-right and reads the logs.csv file into a
    pandas dataframe, then it applies an iplookup on src_ip in a network table
    named vpn_nets[.csv] and assigns any name found to a new column svpn.  This
    basically adds a column to the logs, listing the vpn's the src_ip address
    belongs to.

    dfm help:         - will list all available commands
    dfm help:cmd,..   - lists help on the commands listed.

    All commands more or less follow the convention:

    f1,..=func:a1,...

    The columns to create/modify on the left-hand-side, and the command
    arguments on the right-hand-side.  Each command checks its arguments and
    interprets them in a way that hopefully makes sense for that particular
    command.  For some commands lhs/rhs fields are optional or forbidden.

    Some further examples are:

    dfm r:people.csv email~/\.eu$/      - lists people w/ eu emails
    dfm r:people.csv name=join:-,first,last - new column with first-last names
    dfm r:people.csv name,phone         - lists only the name and phone columns
    dfm r:people.csv age=inrange:10,19  - list the teens
    dfm r:people.csv age=gte:20         - 20 years or older
    dfm r:people.csv eyes=in:blue,green - people with blue or green eyes
    dfm r:people.csv name,phone w:cell.csv - create cell.csv w/ only 2 fields
    dfm help:                           - lists all available commands
    dfm help:nan,ipl                    - list help for two commands

    dfm makes it possible to:
    - add columns to csv-data using lookups (e.g using longest prefix matches)
    - cut columns from the csv-data
    - count rows using a groupby some columns
    - sum an existing count using a groupby some columns
    - filter rows using a regular expression
    - filter rows using lte,gte,inrange numeric expressions
    - filter rows using a simple value list
    - forward/backward fill columns using known good values

    All of which can be done using other tools, but using those usually required
    privileges outside my reach or a lot of repetitive manual labor.

'''

# TODO
# add f1[,..]=fillna:value
# solve dfm help:func: parses to []=func:[], should be []=help:[func:]
#  - also means we need to strip off any trailing ':'
#
import os
import sys
import time
import argparse
import re
import logging
import configparser

from functools import wraps, partial

import pandas as pd
import numpy as np
import pytricia as pt

from ilf import Ip4Protocol, Ip4Filter, Ival
import utils as ut

#-- Logging

# default log setup, only __main__ may add handlers
# in case we're used as a module rather than script
log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

#-- Glob
__version__ = '0.1'

#-- CMD Registry

def console_logging(log_level):
    'setup console logging to level given by args.v'
    console_fmt = logging.Formatter('%(funcName)s %(levelname)s: %(message)s')
    console_hdl = logging.StreamHandler(stream=sys.stderr)
    console_hdl.set_name('console')
    console_hdl.setFormatter(console_fmt)
    console_hdl.setLevel(log_level)
    log.setLevel(log_level)
    log.addHandler(console_hdl)

def get_handler(name):
    'get handler by name'
    for h in log.handlers:
        if h.name == name:
            return h
    return None

def log_switch(logger_lvl=None, console_lvl=None, console_fmt=None):
    'switch to new logging levels and console formatter, return orgv values'

    # get original values
    console_hdlr = get_handler('console')
    org_logger_level = log.getEffectiveLevel()
    org_console_level = console_hdlr.level
    org_console_fmt = console_hdlr.formatter

    # - set new values
    logger_lvl = logger_lvl if logger_lvl else org_logger_lvl
    console_lvl = console_lvl if console_lvl else org_console_lvl
    console_fmt = console_fmt if console_fmt else org_console_fmt

    log.setLevel(logger_lvl)
    console_hdlr.setLevel(console_lvl)
    console_hdlr.setFormatter(console_fmt)

    # - return original values
    return [org_logger_level, org_console_level, org_console_fmt]

def parse_args(argv):
    'parse commandline arguments, return arguments Namespace'
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    padd = p.add_argument
    padd('-v', '--verbose', action='store_const', dest='log_level',
         const=logging.INFO, default=logging.WARNING,
         help='show informational messages')
    padd('-d', '--debug', action='store_const', dest='log_level',
         const=logging.DEBUG, help='show debug messages')
    padd('-V', '--Version', action='version',
         version='{} {}'.format(argv[0], __version__))
    padd('command', nargs='*')

    # parse & sanitize the arguments
    arg = p.parse_args(argv[1:])
    arg.prog = argv[0]
    arg.cmds = []
    for cmd in arg.command:
        arg.cmds.append([cmd, *ut.cmd_parser(ut.cmd_tokens(cmd))])

    return arg

#-- commands
class Commander(object):
    'Manipulate the heck out of a dataframe'

    def __init__(self, filename=None):
        self.ipl = {}                          # {name} -> ip lookup
        self.ipf = {}                          # {name} -> ip filter
        self.ipt = {}                          # {name} -> ip tagger
        self.filename = filename
        self.dfm = None
        self.saved = False                     # True when cmd_write has run
        if filename:
            self.dfm = self.load_csv(filename)

        # create help dict for available commands
        self.hlp = {}
        cp = configparser.ConfigParser()
        for attr in [x for x in dir(self) if x.startswith('cmd_')]:
            func = getattr(self, attr)
            doc = func.__doc__ if func.__doc__ else ''
            cp.read_string('[doc]\n' + doc)
            self.hlp[attr] = {
                'syntax': cp['doc'].get('syntax', 'n/a').strip(),
                'info': cp['doc'].get('info', 'n/a').strip(),
                'descr': cp['doc'].get('descr', 'n/a').strip()
            }
        # also load doc string of the class as generic help for dfm command
        cp.read_string('[doc]\n' + __doc__)
        self.hlp['dfm'] = {
            'syntax': cp['doc'].get('syntax', 'n/a').strip(),
            'info': cp['doc'].get('info', 'n/a').strip(),
            'descr': cp['doc'].get('descr', 'n/a').strip(),
        }


    def load_csv(self, fname):
        'return a dataframe loaded from a csv file, w/ normalized column names'
        filename = fname if os.path.isfile(fname) else '{}.csv'.format(fname)
        errors = []
        try:
            df = pd.read_csv(filename, skipinitialspace=True)
        except (IOError, OSError):
            errors.append('loading csv request for {!r}'.format(fname))
            errors.append('could not read {!r}'.format(fname))
            errors.append('also could not read alt-name {!r}'.format(filename))
            self.fatal(errors, None, None)

        log.debug('original columns names  : {}'.format(df.columns.values))
        df.columns = [ut.normalize(n) for n in df.columns]
        log.debug('normalized columns names: {}'.format(df.columns.values))

        return df

    def from_csv(self, fname):
        self.dfm = self.load_csv(fname)
        self.filename = fname
        return self

    def load_ipl(self, name):
        'load an ip lookup table <name>[.csv] from disk or return a cached one'
        # return a cached version, if available
        if self.ipl.has_key(name):
            return self.ipl[name]

        # no joy on cache, so load from disk
        errors = []
        fname = name if os.path.isfile(name) else '{}.csv'.format(name)
        try:
            ipl = load_csv(fname)
        except (OSError, IOError) as e:
            errors.append('tried {!r}, but no joy'.format(name))
            errors.append('tried {!r} as well, still no joy'.format(filename))
            self.fatal(errors, None, None)

        # find suitable field
        tmp = pt.PyTricia()
        for field in df.columns:
            try:
                tmp[df[field].iloc[0]] = 'test'
                ip_field = field
                break
            except ValueError:
                continue

        # tidy the ip_field lookup column (also remove leading zeros?)
        df[ip_field] = df[ip_field].str.replace(' ', '')

        ipt = pt.PyTricia()
        for idx, row in df.iterrows():
            try:
                ip_idx = row[ip_field]
                # ensure /32 for bare addresses
                ip_idx = ip_idx if '/' in ip_idx else '{}/{}'.format(ip_idx, 32)
                if ipt.has_key(ip_idx):  # noqa W601
                    # has_key must be used to do an exact match, because
                    # the "if ip_idx in ipt:" does a longest pfx match,
                    # which is not what we want here...
                    # prn(0, '>> ignoring duplicate entry for {}'.format(ip_idx))
                    # prn(0, ' - already have', ','.join(str(x) for x in ipt[ip_idx]))
                    # prn(0, ' - ignoring data', ','.join(str(x) for x in row))
                    continue
                ipt[ip_idx] = row  # stores reference to the Series
            except ValueError:
                # prn(0, 'Fatal, cannot create ip lookup table from dataframe')
                # prn(0, 'its index is not an ip address?')
                # prn(0, df.index)
                # prn(0, 'current index element: {}'.format(idx))
                # prn(0, 'current row is', row)
                sys.exit(1)

        return ipl

    def to_csv(self, output=sys.stdout):
        'output self.dfm to sys.stdout or a file'
        if self.dfm is not None:
            self.dfm.to_csv(output, index=False, mode='w')
        else:
            log.info('nothing to write.')
        return self

    def check_fields(self, errors, fields):
        'check for missing fields, report by appending to errors'
        oldlen = len(errors)
        for field in [x for x in fields if x not in self.dfm.columns]:
            errors.append('field {!r} not available at this time'.format(field))
        if len(errors) > oldlen:
            errors.append('valid fields: {}'.format(self.dfm.columns.values))
        return self

    def fatal(self, errors, lhs=None, rhs=None):
        'log fatal errors and exit(1) if any'
        if len(errors):
            caller = sys._getframe(1).f_code.co_name.replace('cmd_', '')

            if lhs is None and rhs is None:
                log.error('{} aborting:'.format(caller))
            else:
                log.error('{}={}:{} aborting:'.format(lhs, caller, rhs))

            for error in errors:
                log.error('{}: {}'.format(caller,error))

            sys.exit(1)

        return self

    def run(self, cmd, lhs, rhs):
        log.debug('running cmd {}={}:{}'.format(lhs, cmd, rhs))
        func = getattr(self, 'cmd_{}'.format(cmd.lower()), None)
        if func:
            return func(lhs, rhs)
        else:
            log.warn('skipping unknown cmd {}'.format(cmd))

        return self

    def cmd_r(self, lhs, rhs):
        '''
        syntax: r:f,...
        info: r is short for read, reads 1+csv-file(s)
        descr:
           see read
        '''
        return self.cmd_read(lhs, rhs)

    def org_cmd_read(self, lhs, rhs):
        '''
        syntax: read:filename
        info: discard any existing dataframe and load new one from csv-file
        descr:
          Usually the first command in a stream that loads a dataset.
        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) != 0:
            errors.append('no lhs-fields allowed')
        if len(rhs) !=1:
            errors.append('need exactly 1 rhs-field')

        fname = rhs[0] if rhs[0].endswith('csv') else '{}.csv'.format(rhs[0])
        if os.path.isfile(rhs[0]):
            fname = rhs[0]
        elif os.path.isfile('{}.csv'.format(rhs[0])):
            fname = '{}.csv'.format(rhs[0])
        else:
            errors.append('cannot read {!r}'.format(rhs[0]))

        self.fatal(errors, lhs, rhs)

        try:
            self.dfm = self.load_csv(fname)
            log.info('read {}'.format(fname))
            log.info('rows, columns is {}'.format(self.dfm.shape))
            log.info('column names: {}'.format(self.dfm.columns.values))

        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        self.saved = False
        return self

    def cmd_read(self, lhs, rhs):
        '''
        syntax: read:f,..
        info: discard any existing dataframe and load new one from 1+ csv-files
        descr:
          Loads data from csv-file(s), rhs-fields may list files or
          glob-patterns.

          rmany:a.csv,b*.csv  - read a.csv and all b-csv's into 1 dataframe.
          rmany:a,b*          - same thing, .csv extension is tested for as well

          Note that strange things may happen if the csv-files have different
          column names.

          For convenience, the abbreviation r: is an alias for rmany.
        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) != 0:
            errors.append('no lhs-fields allowed')
        if len(rhs) < 1:
            errors.append('need 1+ rhs-field')

        import glob
        fnames = []
        for fname in rhs:
            flist = glob.glob(fname) or glob.glob('{}.csv'.format(fname))
            if len(flist) == 0:
                errors.append('cant read {}'.format(fname))
            else:
                fnames.extend(flist)
        self.fatal(errors, lhs, rhs)

        try:
            self.dfm = pd.DataFrame()
            dflist = []
            for fname in fnames:
                df = self.load_csv(fname)
                log.info('read {}'.format(fname))
                log.info('rows, columns is {}'.format(df.shape))
                log.info('column names: {}'.format(df.columns.values))
                dflist.append(df)
            self.dfm = pd.concat(dflist)
            log.info('rows, columns is {}'.format(self.dfm.shape))
            log.info('column names: {}'.format(self.dfm.columns.values))

        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        self.saved = False
        return self

    def cmd_w(self, lhs, rhs):
        '''
        syntax: w:[filename]
        info: w is short for write
        descr:
          See write
        '''
        return self.cmd_write(lhs, rhs)

    def cmd_write(self, lhs, rhs):
        '''
        syntax: write:[filename]
        info: write any existing dataframe in csv-format out to filename/stdout
        descr:
          Usually the last command in a stream that loads a dataset. But can
          also be used to store/show the dataframe in the various stages of
          processing.

          If no filename is given, the dataframe is written to stdout.

          For convenience, the abbreviation w:[filename] is an alias for write:
        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) != 0:
            errors.append('no lhs-fields allowed')
        if len(rhs) == 0:
            fname = sys.stdout
        elif len(rhs) == 1:
            fname = rhs[0]
        else:
            errors.append('need exactly 0 or 1 rhs-field')
        self.fatal(errors, lhs, rhs)

        try:
            self.to_csv(fname)
            if fname is not sys.stdout:
                log.info('wrote {!r}'.format(fname))
                log.info('rows, columns is {}'.format(self.dfm.shape))

        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        self.saved = True
        return self

    def _dot_hierarchy(self, fields, fh):
        'create nodes in a hierarchy in dot, if fields > 1'

        if len(fields) > 1:
            # create hierarchy of subgraphs (clusters)
            df = self.dfm[fields].sort_values(fields, axis=0)
            df = df.drop_duplicates(keep='first')
            df.set_index(fields[:-1], inplace=True)
            prev, idx = (), ()
            for idx, row in df.itertuples():
                idx = idx if isinstance(idx, tuple) else tuple([idx])
                if prev != idx:
                    for g in prev:
                        if g not in idx:
                            print('}', file=fh)
                    for n,g in enumerate(idx):
                        if g not in prev:
                            print('{}subgraph "cluster_{}" {}'.format('     '*(1+n) ,g, '{'), file=fh)
                            print('{}label="{}";'.format('     '*(1+n), g), file=fh)
                    prev = idx
                print('"{}";'.format(row), file=fh)
            for g in idx:
                print('}', file=fh)

        return 0

    def _dot_edges(self, src, dst, label, attrs, fh):
        'print edges to fh, possibly with edge attributes'
        # edge = [label, attr1, attr2, ..]
        # -> turns into [label=label attr1 attr2 ..]
        attrs = [] if attrs is None else attrs
        label = '' if label is None else label

        cols = [src, dst]
        if len(label):
            cols.append(label)
        if len(attrs):
            cols.extend(attrs)
        df = self.dfm[cols]
        df = df.sort_values(cols, axis=0)
        df = df.drop_duplicates(keep='first')
        for idx, row in df.iterrows():
            pattrs = []
            if label is not None and len(label):
                pattrs.append('label="{}"'.format(row[label]))
            for attr in attrs:
                pattrs.append(row[attr])
            pedge = '[{}]'.format(' '.join(pattrs)) if len(pattrs) else ''
            print('"{}" -> "{}"{};'.format(row[src], row[dst], pedge), file=fh)

    def cmd_dotify(self, lhs, rhs):
        '''
        syntax:  fname[,title]=dotify:srcs,dsts[,attrs]
        info: write a dotfile to file 'fname' using src,dst fields
        descr:
          'dotify:' will write a 'fname' file using srcs,dsts to define the
          graph, possible using attrs to decorate edges.

          `srcs`=[fx^[fy]]^fz  is split on '^' to find 1 or more fields to use
          as source nodes of the graph.  The last field will create the actual
          node, any preceeding fields will be used to encapsulate the node in a
          subgraph named cluster_fy, which is then enclosed in cluster_fx and so
          on. All fields used in `srcs` must exist in the dataframe.

          `dsts`=[fb^[fc^]]fd  is treated likewise, but for destiation nodes.

          `attrs` is also split on '^' and should list label and/or edge
          attriutes.

          Example:

          apps.dot,web-traffic=dot:sorg^svpn^src_net,dorg^dvpn^dst_net,service^edge

             This would create source nodes form the src_net df-column, using
             the svpn and sorg for enveloping.  Likewise for dst_net, dvpn and
             dorg.  The attrs 'service^edge' takes the 'service' column as label
             fr edges and puts the 'edge' field as edge attributes, so it should
             contain values like 'color=blue', i.e. a string listing valid dot
             edge attributes separated by spaces.

        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) not in (1, 2):
            errors.append('need 1 or 2 lhs fields')
        if len(rhs) not in (2,3):
            errors.append('need 2 or 3 rhs fields')
        self.fatal(errors, lhs, rhs)

        # decompose rhs and check for errors
        srcs = list(filter(None, rhs[0].split('^')))
        self.check_fields(errors, srcs)

        dsts = list(filter(None, rhs[1].split('^')))
        self.check_fields(errors, dsts)

        label=''
        if len(rhs) == 3:
            label, *attrs = rhs[2].split('^')
            if len(label):
                self.check_fields(errors, [label])
            else:
                label = None

            attrs = list(filter(None, attrs))
            if len(attrs):
                self.check_fields(errors, attrs)
            else:
                attrs = None

        self.fatal(errors, lhs, rhs)

        log.debug('writing dot file {!r}'.format(lhs, rhs[0]))
        log.debug('source columns {}'.format(srcs))
        log.debug('destination columns {}'.format(dsts))

        fname = lhs[0]
        title = None if len(lhs) == 1 else lhs[1]
        fh = open(fname, 'wt') if len(fname) else sys.stdout
        # fh = sys.stdout
        # standard header
        print('digraph dfm {', file=fh)
        print('    overlap=scale;', file=fh)
        print('    ranksep="1.5 equally";', file=fh)
        print('    rankdir=LR;', file=fh)
        if title is not None:
            print('    labelloc="t";', file=fh)
            print('    label="{}";'.format(title), file=fh)

        self._dot_hierarchy(srcs, fh)
        self._dot_hierarchy(dsts, fh)
        self._dot_edges(srcs[-1], dsts[-1], label, attrs, fh)

        print('}', file=fh)  # close the digraph

        if fh != sys.stdout:
            fh.close()

        try:
            pass
        except (TypeError, ValueError) as e:
            errors.append('runtime error {!r}'.format(e))
            self.fatal(errors, lhs, rhs)

        return self

    def cmd_help(self, lhs, rhs):
        '''
        syntax: help:[cmd,..]
        info: print help documentation and exit
        descr:
            'help:' will print documentation for all available commands, or just
            for those listed.  This command takes precedence over all other
            commands in the command stream on the cli.  That is, if given only
            this command will run and the program terminates with exit(0).

        '''
        log_switch(logging.INFO, logging.INFO,
                   logging.Formatter('%(message)s'))

        log.info('\n')
        if len(lhs):
            log.info('ignoring {}'.format(lhs))
            log.info('see help syntax')

        rhs = rhs if len(rhs) else [x for x in self.hlp.keys()]
        for cmd in rhs:
            hlp = self.hlp.get(cmd, None) or self.hlp.get('cmd_{}'.format(cmd),
                                                          None)
            if hlp:
                msg = '{:.9} - {}'.format(cmd.replace('cmd_', ''),
                                          hlp['syntax'])
                log.info(msg)
                log.info('-'*len(msg))
                log.info('information: {}'.format(hlp['info']))
                log.info('\ndescription:')
                for line in hlp['descr'].splitlines():
                    log.info('  {}'.format(line))
            else:
                log.info('{!r} not a command, available are:'.format(cmd))
                for idx, hlp in self.hlp.items():
                    idx = idx.replace('cmd_', '')
                    log.info(' - {}: {}'.format(idx, hlp['info']))
                continue

            log.info('\n')

        sys.exit(0)

    def cmd_info(self, lhs, rhs):
        '''
        syntax: info:
        info: prints information about current invocation and exits
        descr:
            When called, 'info:' will print out information about how the
            program was called and what the command stream looks like.  This may
            be helpful to check how a command line invocation is being
            interpreted.  Note that this command takes precedence over all other
            commands except 'help'.  'info:' also terminates with exit(0).
        '''

        log.info('\n' + '-'*30)
        # switch loglevels so all log.info always show up on console
        org_levels = log_switch(logging.INFO, logging.INFO,
                                logging.Formatter('%(message)s'))

        log.info(args.prog)

        log.info( '\nflags:')
        log.info( ' log level (-v or -d) {}'.format(
            logging.getLevelName(args.log_level)))

        if len(args.command):
            log.info( '\ncli command stream:')
            maxl = max(len(c) for c in args.command)
            for idx, (org, cmd, lhs, rhs) in enumerate(args.cmds):
                log.info(' cmd {:02} '.format(idx) +
                         '{:{w}}  => {}={}:{}) '.format(org, lhs, cmd, rhs,
                                                        w=maxl))

        log.info( '\navailable cmds:')
        for k, v in sorted(self.hlp.items()):
            log.info('{} - {}'.format(k[4:], v['info']))

        if self.dfm is not None:
            log.info( '\nCurrent DataFrame:')
            log.info( ' {} rows by {} columns'.format(*self.dfm.shape))
            maxl = max(len(c) for c in self.dfm.columns.values)+2  # +2 for !r quotes
            log.info( ' {:{w}} - {}'.format('Column', 'DataType', w=maxl))
            for col in self.dfm.columns:
                log.info(' {!r:{w}}   {}'.format(col, self.dfm[col].dtype, w=maxl))
            log.info(' {:{w}}   {}'.format('<index>', self.dfm.index.dtype, w=maxl))
            log.info('\nFirst 3 rows:')
            log.info(self.dfm.head(3))

        log.info( '\n' + '-'*60 + 'info end\n')

        sys.exit(0)

    def cmd_show(self, lhs, rhs):
        '''
        syntax: show:[start,stop]
        info: prints dataframe information and some rows to stderr
        descr:
            Each time show: is used in a command stream, it will log information
            about the dataframe in its current state to stderr.  This may be
            helpful when analyzing what a series of commands is doing with the
            dataframe.

            Sample rows are printed via df.iloc[start:stop], where
            start,stop = 0,5 if not given.  If only 1 number is given, shows
            that many lines from start or till the end of the frame, depending
            on whether a negative number is used.

            Negative start or stop numbers are recalculated to their positive
            row numbers based on the dataframe's current length.

            Examples are:
              show:5     - show first 5 lines (actually the default)
              show:10,15 - show 5 rows, starting with the 10'th row
              show:-1    - show the last row
              show:-3    - show the last 3 rows
              show:-4,-1 - also shows the last 3 rows
        '''

        # switch loglevels so all log.info always show up on console
        org_levels = log_switch(logging.INFO, logging.INFO,
                                logging.Formatter('%(message)s'))
        log.info('\n' + '-'*30 + ' show')

        start, stop = 0, 5
        try:
            if len(rhs) == 1:
                stop = int(rhs[0])
            elif len(rhs) > 1:
                start, stop = int(rhs[0]), int(rhs[1])
        except ValueError as e:
            log.warn('show WARN: ignoring invalid start/stop indices {!r}'.format(rhs))
            start, stop = 0, 5

        start = start if start > 0 else len(self.dfm) + start
        stop = stop if stop > 0 else len(self.dfm) + stop
        start, stop = (start, stop) if stop > start else (stop, start)

        if self.dfm is not None:
            log.info( '\nCurrent DataFrame:')
            log.info( ' {} rows by {} columns'.format(*self.dfm.shape))
            maxl = max(len(c) for c in self.dfm.columns.values)+2  # +2 for !r quotes
            log.info( ' {:{w}} - {}'.format('Column', 'DataType', w=maxl))
            for col in self.dfm.columns:
                log.info(' {!r:{w}}   {}'.format(col, self.dfm[col].dtype, w=maxl))
            log.info(' {:{w}}   {}'.format('<index>', self.dfm.index.dtype, w=maxl))
            log.info('\nrows[{}:{}]:'.format(start, stop))
            log.info(self.dfm.iloc[start:stop])
        else:
            log.warn('dataframe not present at this time')

        log.info( '\n' + '-'*30)

        log_switch(*org_levels)

        return self

    def cmd_copy(self, lhs, rhs):
        '''
        syntax: fx,..=copy:fy,..
        info: copy fy,.. over to fx,..
        descr:
            Assign the values of the rhs-columns to the lhs-columns, possibly
            creating new columns or overwrite existing ones.  The lhs-fields
            fx,.. correspond 1-on-1 to the rhs-fields fy,.. so both sides need
            to list the same number of columns.  All rhs-fields must exist.

            Example:
            newCol,oldCol=copy:f1,f2  - df[newCol]=df[f1] and df[oldCol]=df[f2]

        '''
        # sanity check lhs, rhs
        errors = []
        if len(rhs) < 1:
            errors.append('need 1+ rhs fields')
        if len(lhs) < 1:
            errors.append('need 1+ lhs fields')
        if len(lhs) != len(rhs):
            errors.append('need same number of lhs:rhs fields')
        self.check_fields(errors, rhs)
        self.fatal(errors, lhs, rhs)

        try:
            for dst,src in zip(lhs, rhs):
                log.info('df[{}] = df[{}]'.format(dst, src))
                self.dfm[dst] = self.dfm[src]
        except Exception as e:
            log.critical('error: {!r}'.format(e))
            sys.exit(1)

        return self


    def cmd_lower(self, lhs, rhs):
        '''
        syntax: fx,..=lower:[fy,..]
        info: lower-case fields or assign lower(fy),.. to fx,..'
        descr:
           'lower:' will lowercase all the lhs-fields if no rhs-fields are
           given. In this case, all lhs-fields must exist.

           If rhs-fields are used, however, their lower-cased values are
           assigned to the lhs-fields in a 1-on-1 correspondence.  In this case
           the rhs-fields must all exist and any non-existing lhs-fields will be
           created.

           Example:
            name,last=lower: - will lower-case existing fields name,lower
            host=lower:name - creates new column host with lowercased name
            a,b=lower:c,c   - creates/sets columns a,b to lowercased value of c
        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need 1+ lhs-fields')
        srcs = lhs if len(rhs) == 0 else rhs
        if len(srcs) != len(lhs):
            errors.append('num(rhs-fields) must equal num(lhs-fields)')
        self.check_fields(errors, srcs)
        self.fatal(errors, lhs, rhs)

        try:
            for dst,src in zip(lhs, srcs):
                log.info('- df[{}] = df[{}].str.lower()'.format(dst, src))
                self.dfm[dst] = self.dfm[src].str.lower()
        except KeyError:
            self.fatal(['Unknown runtime error {!r}'.format(e)], lhs, rhs)

        return self


    def cmd_upper(self, lhs, rhs):
        '''
        syntax: fx,..=upper[:fy,..]
        info: upper-case fields or assign upper(fy),.. to fx,..
        descr:
           'upper:' will uppercase all the lhs-fields if no rhs-fields are
           given. In this case, all lhs-fields must exist.

           If rhs-fields are used, however, their upper-cased values are
           assigned to the lhs-fields in a 1-on-1 correspondence.  In this case
           the rhs-fields must all exist and any non-existing lhs-fields will be
           created.

           Example:
            name,last=upper: - will upper-case existing fields name,upper
            host=upper:name - creates new column host with uppercased name
            a,b=upper:c,c   - creates/sets columns a,b to uppercased value of c

        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need 1+ lhs fields')
        srcs = lhs if len(rhs) == 0 else rhs
        if len(srcs) != len(lhs):
            errors.append('num(lhs-fields) must equal num(rhs-fields)')
        self.check_fields(errors, srcs)
        self.fatal(errors, lhs, rhs)

        try:
            for dst,src in zip(lhs, srcs):
                log.info('- df[{}] = df[{}].str.upper()'.format(dst, src))
                self.dfm[dst] = self.dfm[src].str.upper()
        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        return self

    def cmd_keep(self, lhs, rhs):
        '''
        syntax: fx,..[=keep:[fy,..]]
        info: keep only fx,.. fields or keep fy,.. fields & rename to fx,..
        descr:
          Discard all columns except the ones listed.  The command name 'keep:'
          is optional (is used by default if no command is given), in which case
          all lhs-fiels must exist.

          If rhs-fields are used, then all other columns are discarded after
          which the columns are renamed to lhs-fieldnames.  In this case there
          is a 1-on-1 correspondence between lhs- and rhs-fields.

          Example:
            name,age=keep:  - keep only these two columns
            name,age        - same effect
            name,age=keep:Name,Years - keep Name,Years & rename to name,age

        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need 1+ lhs fields to keep')
        srcs = lhs if len(rhs) == 0 else rhs
        if len(srcs) != len(lhs):
            errors.append('num(lhs-fields) must equal num(rhs-fields)')
        self.check_fields(errors, srcs)
        self.fatal(errors, lhs, rhs)

        try:
            self.dfm = self.dfm[srcs]
            self.dfm.columns = lhs

        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        return self

    def cmd_del(self, lhs, rhs):
        '''
        syntax: fx,..=del:
        info: delete fx,.. fields
        descr:
           Delete some specifically named fields.
        '''

        # sanity check lhs, rhs
        errors = []
        if len(rhs) > 0:
            errors.append('no rhs fields allowed')
        if len(lhs) < 1:
            errors.append('need 1+ lhs fields')
        self.check_fields(errors, lhs)
        self.fatal(errors, lhs, rhs)

        try:
            for field in lhs:
                self.dfm.drop(field, axis=1, inplace=True)
        except (KeyError, ValueError) as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        return self


    def cmd_nan(self, lhs, rhs):
        '''
        syntax: [fx,..=]nan:s1,..
        info: replace values s<x> with null value in dst/all fields
        descr:
          'nan:' will replace listed string values with a np.nan value in the
          dataframe.  Either in all columns, or just in the ones listed in the
          lhs-field list.  The rhs-list is a csv-list of string values to
          replace with np.nan.

          Usefull if the dataset has some fixed 'filler' values you want to get
          rid of in order to drop them later on or have them replaced by the
          map: command.
          '''

        # sanity check lhs, rhs
        errors = []
        self.check_fields(errors, lhs)
        self.fatal(errors, lhs, rhs)

        try:
            if len(lhs) == 0:
                for replacer in rhs:
                    self.dfm.replace(replacer, np.nan, inplace=True)
            else:
                for dst in lhs:
                    for replacer in rhs:
                        self.dfm[dst].replace(replacer, np.nan, inplace=True)

        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        return self

    def cmd_portstr(self, lhs, rhs):
        '''
        syntax: fx=port:fy,fz
        info: turn fy,fyz (port, protocol numbers, eg 80,6) into a portstring like 80/tcp
        descr:
           Sometimes is better to get just port, protocol nr from the logs and
           convert those to a ipv4-port/service using the iana assigned numbers.
           portstr: does exactly that.

           Example:
           dfm r:logs service=port:port,proto

           The above will create/overwrite columns 'service' with a port string
           constructed from the port number and protocol number:

              service,port,proto
              80/tcp,"80","6"
              53/udp,53,17

        '''

        # sanity check lhs, rhs
        errors = []
        if len(lhs) != 1:
            errors.append('need exactly 1 lhs field')
        if len(rhs) !=2:
            errors.append('need exactly 2 rhs fields')
        dst = lhs[0]
        self.check_fields(errors, rhs)
        self.fatal(errors, lhs, rhs)
        fport, fproto = rhs

        def safe_port(row):
            try:
                port, proto = row[fport], row[fproto]
                return Ival.from_portproto(port, proto).to_portstr()
            except ValueError:
                return np.nan

        try:
            self.dfm[dst] = self.dfm.apply(safe_port, axis=1)
        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        return self

    def cmd_servicename(self, lhs, rhs):
        '''
        syntax: fx=service:fportstr
        info: fx := iana service name via portstring
        descr:
           Looks up the portstring (eg 80/tcp) or port,protocols nrs (eg 80, 6)
           in a table and returns the iana assigned name and/or description.

           Example:
           dfm r:logs application,descr=portname:service
           dfm r:logs ,descr=portname:service

           dfm r:logs application,descr=portname:port,proto
           dfm r:logs ,descr=portname:port,proto

           The first command assigns the iana service name and its description
           to (possibly) new fields application,descr using the df-column
           service which should contain portstrings like '80/tcp'.  The second
           command only assigns the description.

           The 3rd and 4th commands do the same, but using port nr and protocol
           nr columns instead (where port, proto would refer to eg 80, 6).

        '''

        # sanity check lhs, rhs
        errors = []
        if len(lhs) > 2:
            errors.append('need 1 or 2 lhs fields')
        if len(rhs) != 1:
            errors.append('need 1 rhs field')
        self.check_fields(errors, rhs)
        self.fatal(errors, lhs, rhs)
        log.info('loading services ...')
        ipp = Ip4Protocol(load_services=True)
        log.info('... done!')
        fdst, fport = lhs[0], rhs[0]

        def get_name(row):
            try:
                portstr = row[fport]
                if portstr is not np.nan and len(portstr):
                    name = ipp.service_byport(portstr)
                    if name is None or len(name) == 0:
                        return portstr
                    return name
                return 'unknown'
            except ValueError:
                return 'err'

        try:
            self.dfm[fdst] = self.dfm.apply(get_name, axis=1)
        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        return self

    def cmd_join(self, lhs, rhs):
        '''
        syntax: fx=join:sep,fy,fz,..
        info: join 2+ fields using sep
        descr:
           Create new column fx (or overwrite existing one) by joining the
           string values of columns fy,fz,.. using the string <sep>.

           Only 1 lhs-field is allowed and a minimum of 3 rhs-fields are
           required.  All rhs-fiels, except the <sep>-string must be existing
           fields in the dataframe.

           Example:
            |  a num
            |  a 1
            |  a 2

           Using b=join:\\:a,num will get you

            |  a num b
            |  a 1   a:1
            |  a 2   a:2

           Usually you'll need to double the escape '\'-char on the command
           line. (note: ':~=' are special characters for the command parser).

        '''

        # sanity check lhs, rhs
        errors = []
        if len(rhs) < 3:
            errors.append('need 3+ fields in rhs: sep,f1,f2,...')
        if len(lhs) != 1:
            errors.append('need exactly 1 lhs field')
        dst = lhs[0]
        sep, srcs = rhs[0], rhs[1:]
        self.check_fields(errors, srcs)
        self.fatal(errors, lhs, rhs)

        try:
            self.dfm[dst] = self.dfm[srcs].apply(lambda x: sep.join(str(f) for f in x), axis=1)
        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        return self

    def cmd_map(self, lhs, rhs):
        '''
        syntax: fx,..=map:fy
        info: create (fy,fx)-map and apply to existing fx,..
        descr:
           'map:' is a sort of forced forward/backward fill, using column fy to
           create a dictionary of fy->fx valid-values-mapping (retaining first mapping
           found) and them apply that to column fx.  The process is repeated for
           any additional lhs-fields, which must all exist.

           Only fx-nan-values are replaced by a known fx-valid-value given the
           value of fy in that row.

           Example:

            |  hostname      ip            count
            |  nan           68.178.213.61  10
            |  www.ietf.com  68.178.213.61  12

           Using hostname=map:ip, will get you:

            |  hostname      ip            count
            |  www.ietf.com  68.178.213.61  10
            |  www.ietf.com  68.178.213.61  12

           Mostly useful when the dataset is derived from events with common
           fields, but where not all events have all the fields all the time.
        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need at least 1 lhs field to assign to')
        if len(rhs) != 1:
            errors.append('need exactly 1 rhs field as map source')
        self.check_fields(errors, lhs + rhs)
        self.fatal(errors, lhs, rhs)

        src = rhs[0]
        dst = [c for c in lhs if c != src]  # avoid source control column
        fix = self.dfm.set_index(src)             # src value mappings to other columns
        log.info('- control column {}'.format(src))
        for col in dst:
            dct = fix[[col]].dropna().to_dict()[col]  # null's should be NaNs!
            log.info('- mapping to {!r} with {} unique maps'.format(col,
                                                                  len(dct)))
            self.dfm[col] = self.dfm[src].map(dct)

        return self

    def cmd_regex(self, lhs, rhs):
        '''
        syntax: [fx=]fy~/abc/[ABC/][i]
        info: create/modify fx or filter by fy
        descr:
          'regex:' can be used to either:
           - filter rows by matching fy to a regular expression
           - perform a substitution on fy via a regular expression, or
           - assign the value of the substitution to a new/existing column.

          Example:
          status~/up/down/  - flip 'up' to 'down' in status column
          host=name~/-[^-]+$//  - bare hostname with last part stripped
          status~/up/i - keep rows where status contains 'up' (case-insensitive)

          The following flags are picked up on:
          /i = re.I - case insensitive
          /a = re.A - ascii-only matching instead of full unicode for \w, \W ..
          /s = re.S - make '.' match newline as well
          /m = re.M - make '^','$' also match at beginning/end of each line
          /r = reverse meaning in case of matching/filtering
        '''
        # regexp work on strings, not numbers. At the moment, str(x) is used to
        # ensure a column field value is a string.  Not needed when its already
        # string-like.  So a speed-up is handy by first checking if the field
        # being matched/search is already string-like (save str(x) on every
        # value in a column ....

        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need at least 1 field to work with')
        if len(rhs) < 1:
            errors.append('missing field or regexp')
        self.check_fields(errors, rhs[:-1])
        self.fatal(errors, lhs, rhs)

        expression = rhs.pop()
        parts = re.split('(/)', expression)  # keep delim / in parts
        delim = parts[1::2]                  # either 2 or 3 /'s are valid!
        terms = list(parts[::2])
        rgx_inverse = False
        flags = 0
        for f in terms[-1]:
            f = f.lower()
            if f == 'i':
                flags |= re.I
            elif f == 'a':
                flags |= re.A
            elif f == 's':
                flags |= re.S
            elif f == 'm':
                flags |= re.M
            elif f == 'r':
                rgx_inverse = True
            else:
                errors.append('regexp, unknown flag in {!r}'.format(f))
        if len(errors):
            self.fatal(errors, lhs, rhs)

        try:
            rgx = re.compile(terms[1], flags)
        except Exception as e:
            errors.append('Failed to compile expression {!}'.format(expression))
            errors.append(' - error: {}'.format(repr(e)))
            self.fatal(errors, lhs, rhs)

        log.info('- {!r}'.format(rgx))

        if len(delim) == 2:
            if len(rhs) == 0:
                # f1[,f2,..]~/expr/ -> rows where expr matches 1 of f1[f2,..]

                self.check_fields(errors, lhs)  # ensure lhs-fields exist
                self.fatal(errors, lhs, rhs)
                log.info("- filter rows by re.search on '{}'".format(lhs))
                n1 = len(self.dfm.index)

                if rgx_inverse:
                    match = lambda r: any(not rgx.search(str(f)) for f in r)
                else:
                    match = lambda r: any(rgx.search(str(f)) for f in r)

                self.dfm = self.dfm[self.dfm[lhs].apply(match, axis=1)]

                n2 = len(self.dfm.index)
                fmt = 'filtering {!r}: {} -> {} rows (delta {})'
                log.info(fmt.format(lhs, n1, n2, n1-n2))
            else:
                # f1[,f2,..]=f3~/expr/ -> if f3 matches, assign it to f1 [AND f2,..],
                #                         otherwise assign np.nan to f1 [AND f2,..]
                if len(rhs) != 1:
                    errors.append('too many rhs fields')
                    self.fatal(errors, lhs, rhs)
                src = rhs[0]
                log.info('- {}={} when re.search matches'.format(lhs, src))

                if rgx_inverse:
                    match = lambda x: str(x) if not rgx.search(str(x)) else np.nan
                else:
                    match = lambda x: str(x) if rgx.search(str(x)) else np.nan

                newcol = self.dfm[src].apply(match)
                for dst in lhs:
                    self.dfm[dst] = newcol
                    log.info('- {} new {} fields filled'.format(len(
                        self.dfm[dst].dropna()), dst))

        elif len(delim) == 3:
            # [f1=]f2~/expr/repl/[flags]  to replace in f2 and/or assign to f1
            # when substituting, rgx_inverse flag cannot be used
            repl = terms[2]
            if len(rhs) == 0:
                srcs = lhs
            elif len(rhs) == 1:
                srcs = rhs * len(lhs)
            else:
                errors.append('max 1 rhs field allowed')
                # self.fatal(errors, lhs, rhs + [expression]) # why so early?

            self.check_fields(errors, srcs)
            if rgx_inverse:
                errors.append('cannot use reverse-flag when substituting')
            self.fatal(errors, lhs, rhs + [expression])

            for src,dst in zip(srcs,lhs):
                log.info('- {}={}.sub({},{!r})'.format(dst, rgx, src, repl))
                self.dfm[dst] = self.dfm[src].apply(
                    lambda x: rgx.sub(repl, str(x)))
        else:
            errors.append('- dunno what to do with this')
            self.fatal(errors, lhs, rhs + [expression])

        return self


    def cmd_in(self, lhs, rhs):
        '''
        syntax: fx,..=in:v1,..
        info: select rows where any lhs-field has a value in the rhs-list
        descr:
          'in:' will keep rows where at least one of the lhs-fields, which all
          must exist, has a value listed in the rhs-list of values.

          Example:
          color=in:green,yellow  - keep only the green or yellow ones
          f1,f2=in:apple,pear - keep rows with apple and/or pear in f1 or f2

        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need 1+ lhs fields')
        if len(rhs) < 1:
            errors.append('need 1+ rhs fields')
        self.check_fields(errors, lhs)
        self.fatal(errors, lhs, rhs)

        log.info('filter rows by range {!r} on fields {!r}'.format(rhs, lhs))
        n1 = len(self.dfm.index)
        self.dfm = self.dfm[self.dfm[lhs].apply(lambda r: any(str(f) in rhs for f in r), axis=1)]
        n2 = len(self.dfm.index)
        fmt = 'filtering {!r}: {} -> {} rows (delta {})'
        log.info(fmt.format(lhs, n1, n2, n1-n2))

        return self

    def cmd_inrange(self, lhs, rhs):
        '''
        syntax: fx,..=inrange:v1,v2
        info: select rows where v1 <= any lhs-field <= v2
        descr:
          'inrange:' keeps rows where any lhs-field is in range[v1,v2].
          There should be 2 rhs-fields giving the minimum and maximum values for
          the range.  Note that the lhs-fields must be numeric and must exist.

        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need 1+ lhs fields')
        if len(rhs) != 2:
            errors.append('need exactly 2 rhs fields for min,max')
        self.check_fields(errors, lhs)
        self.fatal(errors, lhs, rhs)

        log.debug('filtering rows by {!r} {} <= field <= {}'.format(lhs, *rhs))
        n1 = len(self.dfm.index)
        minval, maxval = list(map(int, rhs))  # ensure integers

        try:
            self.dfm = self.dfm[self.dfm[lhs].apply(
                lambda r: any(minval <= f <= maxval for f in r), axis=1)]
        except (TypeError, ValueError) as e:
            errors.append('{!r} has non-numeric data: {!r}'.format(lhs, e))
            self.fatal(errors, lhs, rhs)

        n2 = len(self.dfm.index)
        log.info('{} -> {} rows ({} filtered)'.format(n1, n2, n1-n2))

        return self

    def cmd_lte(self, lhs, rhs):
        '''
        syntax: fx,..=lte:v1
        info: rows where any lhs-field <= v1
        descr:
          'lte:' will keep rows where any lhs-field has a value less then, or
          equal to v1. All lhs-fields must be numeric and must exist.

        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need 1+ lhs fields')
        if len(rhs) != 1:
            errors.append('need exactly 1 rhs field')
        self.check_fields(errors, lhs)
        self.fatal(errors, lhs, rhs)

        log.debug('filtering rows by {!r} <= {}'.format(lhs, rhs[0]))
        n1 = len(self.dfm.index)
        maxval = int(rhs[0])  # ensure this is an integer

        try:
            self.dfm = self.dfm[self.dfm[lhs].apply(
                lambda r: any(f <= maxval for f in r), axis=1)]
        except (TypeError, ValueError) as e:
            errors.append('{!r} has non-numeric data: {!r}'.format(lhs, e))
            self.fatal(errors, lhs, rhs)

        n2 = len(self.dfm.index)
        log.info('{} -> {} rows ({} filtered)'.format(n1, n2, n1-n2))

        return self

    def cmd_gte(self, lhs, rhs):
        '''
        syntax: fx,..=gte:v1
        info: rows where any lhs-field <= v1
        descr:
          'gte:' will keep rows where any lhs-field has a value greater then, or
          equal to v1. All lhs-fields must be numeric and must exist.

        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need 1+ lhs fields')
        if len(rhs) != 1:
            errors.append('need exactly 1 rhs field')
        self.check_fields(errors, lhs)
        self.fatal(errors, lhs, rhs)

        log.debug('filtering rows by {!r} >= {}'.format(lhs, rhs[0]))
        n1 = len(self.dfm.index)
        minval = int(rhs[0])  # ensure this is an integer

        try:
            self.dfm = self.dfm[self.dfm[lhs].apply(
                lambda r: any(f >= minval for f in r), axis=1)]
        except (TypeError, ValueError) as e:
            errors.append('{!r} contains non-numeric data: {!r}'.format(lhs, e))
            self.fatal(errors, lhs, rhs)

        n2 = len(self.dfm.index)
        log.info('{} -> {} rows ({} filtered)'.format(n1, n2, n1-n2))

        return self


    def cmd_sum(self, lhs, rhs):
        '''
        syntax: fx=sum:[fy,..]
        info: sums or counts rows, possibly grouped on fy,..
        descr:
          'sum:' assigns the count of similar rows or the sum of fx-field of
          similar rows to the fx-column.

          If rhs-fields are listed, all other fields/columns are discarded and
          rows are grouped on the remaining columns listed in the rhs.
          Otherwise rows are grouped using all available columns.  Note that any
          listed rhs-field must exist in the dataframe.

          if a lhs-field is given, its values are summed for each group and
          assigned to this column.  Otherwise, a new column is created and the
          assigned value will be a count of similar rows in the groups.

          Example:

           |  host  error  count  - sample dataframe
           |  A     down   12
           |  B     crash  3
           |  A     crash  4
           |  B     down   6
           |  A     crash  3
           |  B     down   8

           seen=sum:host          - seen is count of host occurrences

           |  host seen
           |  A    3
           |  B    3

           count=sum:host         - total amount of any error per host

           |  host count
           |  A    16
           |  B    17

           count=sum:error        - total amount of errors across all hosts

           |  error  count
           |  down   26
           |  crash  10

           count=sum:host,error   - total amount of host,error combinations

           |  host error count
           |  A    crash 7
           |  A    down  12
           |  B    crash 3
           |  B    down  14

           seen=sum:host,error    - amount of entries per host,error combination

           |  host error seen
           |  A    crash 2
           |  A    down  1
           |  B    crash 1
           |  B    down  2

        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) != 1 or len(lhs[0]) < 1:
            errors.append('need exactly 1 lhs field')
        self.check_fields(errors, rhs)
        self.fatal(errors, lhs, rhs)

        dst = lhs[0]
        if len(rhs) == 0:
            log.debug('assuming all columns remain in result')
            rhs = [c for c in self.dfm.columns.values if c != dst]

        if dst not in self.dfm.columns:
            self.dfm[dst] = 1
        elif self.dfm[dst].dtype not in ['int64', 'float64']:
            errors.append('{!r} is not numeric'.format(dst))
            errors.append('available columns and types are:')
            for name, typ in self.dfm.dtypes.items():
                errors.append('{}:{}'.format(name, typ))
            self.fatal(errors, lhs, rhs)

        try:
            self.dfm = self.dfm.groupby(rhs, as_index=False).agg({dst: 'sum'})
        except (KeyError, ValueError) as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        return self


    def cmd_ipl(self, lhs, rhs):
        '''
        syntax: fx,..=ipl:table,fy,g1,..
        info: ip lookup fy in 'table', get g1,.. & assign to fx,..
        descr:
           'ipl:' uses the ip address or prefix in fy, to index into an ip
           lookup 'table'. From the data columns found, it will assign g1,.. to
           the dataframe columns listed in fx,... which must all exist.

           Example:
           sname=ipl:hosts,src_ip,hostname
            : Assumung hosts[.csv] contains at least an ip-column and hostname
            : as column, use the 'src_ip' field to lookup the associated
            : hostname and assign that value to a (possibly) new field 'sname'.

           snetwork,svpn=ipl:routes,src_ip,subnet,vpn
            : Assuming routes contains at least subnet,vpn use the 'src_ip' field
            : to lookup any associated subnet and vpn information and assign
            : those values to snetwork and svpn respectively.

           Note that 'table' is read from disk and then cached for future uses
           in the command stream on the cli.  The first column that parses as an
           ip addres of prefix is used as the index column for the table.
           The table name (with or without .csv) must correspond to a file on
           disk in csv-format.

           The index-field (2nd value in rhs-list) must exist in the dataframe
           and should be a string representing an ip address of prefix
           (a.b.c.d/len).  Shorthand notations like 10/8 are allowed.


        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need 1+ lhs fields to assign to')
        if len(rhs) != len(lhs) + 2:
            errors.append('need table, lookup-key & same number of rhs fields as in lhs')
        if not (os.path.isfile(rhs[0]) or
                os.path.isfile('{}.csv'.format(rhs[0]))):
            errors.append('cannot find ipl-table {!r} on disk'.format(rhs[0]))
        self.fatal(errors, lhs, rhs)

        table, src, *getfields = rhs
        # get cached table, or read from disk
        ipt = self.ipt.get(table, None)
        if ipt is None:
            log.info('reading {!r} from disk'.format(table))
            ipt = ut.load_ipt(table)
            self.ipt[table] = ipt
        else:
            log.info('table {!r} retrieved from cache'.format(table))
        log.info('- table {} has {} entries'.format(table, len(ipt.keys())))

        # sanity check ip lookup table
        if len(ipt) < 1:
            errors.append('lookup table appears empty')
        tmp = ipt[ipt.keys()[0]]   # get a sample row, must be Series or dict
        for unknown in [g for g in getfields if g not in tmp.keys()]:
            errors.append('field {!r} not available in {}'.format(unknown, table))
        self.check_fields(errors, [src])
        self.fatal(errors, lhs, rhs)

        def lookup(key):
            try:
                return ipt[key][getfield]
            except KeyError:
                return 'n/a'
            except ValueError:
                return 'err'
            except Exception as e:
                self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        try:
            # a lookup that returns ipt[key][getfields] all at once is actually
            # slower than getting field for field in a for loop, go figure ...
            for dst, getfield in zip(lhs, getfields):
                self.dfm[dst] = self.dfm[src].apply(lookup)
        except (KeyError, ValueError) as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)
        except Exception as e:
            self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        return self

    def cmd_ipf(self, lhs, rhs):
        '''
        syntax: [fx]=ipf:filter[.csv],src,dst[,port[,proto]]
        info: either filter rows or put the tag of matching rules in fx
        descr:
           'ipf:' loads the rule-set given by filter.csv and uses the listed
           src,dst,port-fields to try and match them against the filter.  The
           filter cached in case the same filter is used again for tagging
           instead of filtering (or vice versa).

           If no lhs-field fx is given, rows with a negative match will be
           filtered out.  Otherwise, the tag from the first rule to match will
           be assigned to fx.

           If you only use the port-field, it should be port/proto values, like
           80/tcp.  If both port, proto are given the should list the port,
           protocol numbers like 80, 17.

           The rhs-fields, except the first one which should refer to an
           existing filter file on disk, should be existing columns in the
           dataframe.

           The filter[.csv] file should list a rule-base with columns:
           rule, src_ip, dest_ip, dest_port, action, tag.  Something like:

             rule,src_ip,dest_ip,dest_port,action,tag
             1,10/8,10.10.10.10,80/tcp,permit,intranet1
             2,10/8,10.10.10.11,5000-6000/tcp,deny,drop-rule1
             ,10/8,10.10.10.12,,,
             3,any,any,any,deny,generic-drop

           Example:
           tag=ipf:myfilter,my_src,my_dest,dport         # dport is eg 80/tcp
           tag=ipf:myfilter,my_src,my_dest,dport,dproto  # dport,dproto = 80,17
        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) > 1:
            errors.append('at most 1 lhs field allowed')
        if len(rhs) not in (3,4,5):
            errors.append('rhs must specifiy 3, 4 or 5 fields')
            errors.append('filter-name, src and dst are mandatory')
            errors.append('- port if field has port/proto-string, eg 80/tcp')
            errors.append('- port,proto when they are protocol nrs, eg 80, 17')
            errors.append('got {!r} instead'.format(rhs))
        if not (os.path.isfile(rhs[0]) or
                os.path.isfile('{}.csv'.format(rhs[0]))):
            errors.append('cannot find ipf filter {!r} on disk'.format(rhs[0]))
        self.check_fields(errors, rhs[1:])  # all other rhs fields must exist
        self.fatal(errors, lhs, rhs)

        # process lhs, rhs
        # dest_field is used when tagging sessions instead of filtering
        dest_field = lhs[0] if len(lhs) == 1 else None
        # if port is None, then proto must be None as well
        ipfilter, src, dst, port, proto = (rhs + [None, None])[0:5]
        # get cached filter, or read from disk
        ipf = self.ipf.get(ipfilter, None)
        if ipf is None:
            log.info('reading {} from disk'.format(ipfilter))
            ipf = Ip4Filter(ipfilter)
            self.ipf[ipfilter] = ipf
        else:
            log.info('filter retrieved from cache')
        log.info('filter {} has {} rules'.format(ipfilter, len(ipf)))
        # sanity check ip filter
        if len(ipf) == 0:
            errors.append('filter appears to be empty, no rules')
        self.fatal(errors, lhs, rhs)

        if args.log_level == logging.DEBUG:
            for line in ipf.lines():
                log.debug(line)

        nomatch = '' if dest_field else False   # tag empty string for a miss
        old_nomatch = ipf.set_nomatch(nomatch)  # nomatch => filter session out
        ipfunc = ipf.get if dest_field else ipf.match

        def match(row):
            try:
                if port is None:  # not using any port information
                    return ipfunc(row[src], row[dst])
                elif proto is None:  # port is portstring, eg 80/tcp
                    return ipfunc(row[src], row[dst], row[port])
                else:  # port, proto are nrs, eg 80, 17
                    return ipfunc(row[src], row[dst], row[port], row[proto])
            except Exception as e:
                self.fatal(['runtime error1: {!r}'.format(e)], lhs, rhs)

        # try:
        if dest_field:
            self.dfm[dest_field] = self.dfm.apply(match, axis=1)
        else:
            self.dfm = self.dfm[self.dfm.apply(match, axis=1)]

        # except (KeyError, ValueError) as e:
        #     self.fatal(['runtime error: {!r}'.format(e)], lhs, rhs)

        ipf.set_nomatch(old_nomatch)  # restore old nomatch value
        return self

    def cmd_ipfget(self, lhs, rhs):
        '''
        syntax: fx,..=ipfget:filter[.csv],src,dst,service,g1,..
        info: get filter match object w/ data-fields gx,.. and assign to fx,..

        descr:
           'ipfget:' loads the rule-set given by filter.csv and uses the listed
           src,dst,service fields to try and match them against the filter.  The
           filter is cached in case the same filter is used again later on.

           Any existing lhs-fields will be overwritten and created otherwise.

           The rhs-fields must specify the columns to use for src ip,
           destination ip and service, followed by the fields to retrieve from
           the match object as specified by the ipf-filter.  All rhs-fields must
           exist, either in the dataframe (the first 3) or in het match object
           returned by the filter.  So its handy if the extra datafields of the
           filter are known (see below).

           An ipf filter is a csv file with mandatory fields:
           rule,src,dst,dport,action followed by optional data fields.

           The optional data fields can be retrieved using ipfget:

             |-- required filter fields ---------|-- data fields --
             rule,src_ip,dest_ip,dest_port,action,tag,attr
             1,10/8,10.10.10.10,80/tcp,permit,intranet1,color=green
             2,10/8,10.10.10.11,5000-6000/tcp,deny,drop-rule1,color=red
             ,10/8,10.10.10.12,,,,
             3,any,any,any,deny,generic-drop,color=blue

          my_tag,my_attr=ipfget:file.csv,src,dst,service,tag,attr
        '''
        # sanity check lhs, rhs
        errors = []
        if len(lhs) < 1:
            errors.append('need 1+ lhs field')
        if len(rhs) != len(lhs) + 4:
            errors.append('rhs-fields must specifiy:')
            errors.append('- a filter file')
            errors.append('- a src ip field')
            errors.append('- a dst ip field')
            errors.append('- a dst port field (eg 80/tcp')
            errors.append('- followed by dta-fields (to assign to lhs-fields')
            errors.append('got {!r} instead'.format(rhs))
        if not (os.path.isfile(rhs[0]) or
                os.path.isfile('{}.csv'.format(rhs[0]))):
            errors.append('cannot find ipf filter {!r} on disk'.format(rhs[0]))
        self.check_fields(errors, rhs[1:4])  # fields for src,dst,dport must exist
        self.fatal(errors, lhs, rhs)

        # decompose rhs
        ipfilter, src, dst, dport, dta_fields = rhs[0], rhs[1], rhs[2], rhs[3], rhs[4:]
        ipf = self.ipf.get(ipfilter, None)
        if ipf is None:
            log.info('reading {} from disk'.format(ipfilter))
            ipf = Ip4Filter(ipfilter)
            self.ipf[ipfilter] = ipf
        else:
            log.info('filter retrieved from cache')
        log.info('filter {} has {} rules'.format(ipfilter, len(ipf)))
        if len(ipf) == 0:  # check ipf is valid
            errors.append('filter appears to be empty, no rules')
        self.fatal(errors, lhs, rhs)

        if args.log_level == logging.DEBUG:
            for line in ipf.lines():
                log.debug(line)

        def match(row):
            try:
                dct = ipf.get(row[src], row[dst], row[dport])
                if dct is None:
                    return pd.Series(['err'] * len(dta_fields))
                return pd.Series([dct.get(k, 'err') for k in dta_fields])

            except Exception as e:
                errors.append('matched data has keys {}'.keys())
                errors.append('requested fields were {}'.dta_fields)
                errors.append('looks like some are missing in the filter data')
                errors.append('error: {}'.format(repr(e)))
                self.fatal(errors, lhs, rhs)

        # self.dfm[lhs] = self.dfm.apply(match, axis=1)

        def lookup(row):
            dct = ipf.get(row[src], row[dst], row[dport])
            if dct is None:
                return ''
            return dct.get(dta_field, 'err')

        for dst_field, dta_field in zip(lhs, dta_fields):
            self.dfm[dst_field] = self.dfm.apply(lookup, axis=1)

        return self


def main():
    'load csv and run it through the cli commands given'
    hdlr = Commander()

    if len(args.cmds) == 0:
        hdlr.run('help', [], ['dfm'])
        return 0

    # run any help commands and exit
    helpwanted = False
    for org, cmd, lhs, rhs in args.cmds:
        if cmd != 'help':
            continue
        helpwanted = True
        hdlr.run(cmd, lhs, rhs)
    if helpwanted:
        sys.exit(0)

    # run the real data mangling commands
    for org, cmd, lhs, rhs in args.cmds:
        log.debug('cli {!r}'.format(org))
        try:
            hdlr.run(cmd, lhs, rhs)
        except AttributeError as e:
            if hdlr.dfm is None:
                log.warn('Oops, forgot to read in a dataset?')
            else:
                log.warn('Oops, runtime error {}'.format(e))
            sys.exit(1)

    # gratutious output to stdout if not output cmd was seen
    if not args.cmds[-1][1] in ['w', 'write', 'show', 'dotify']:
        hdlr.run('write', [], [])

    return 0


if __name__ == '__main__':
    args = parse_args(sys.argv)
    console_logging(args.log_level)
    sys.exit(main())

