#!/usr/bin/env python3
# -*- coding: utf-8  -*-

r'''
          _\|/_
          (o o)
  +----oOO-{_}-OOo-----------Syslog-----------------------------+
  |          __                  __                             |
  |         / /_   ___   ____ _ / /_ ____ ___   ____ _ ____     |
  |        / __ \ / _ \ / __ `// __// __ `__ \ / __ `// __ \    |
  |       / / / //  __// /_/ // /_ / / / / / // /_/ // /_/ /    |
  |      /_/ /_/ \___/ \__,_/ \__//_/ /_/ /_/ \__,_// .___/     |
  |                                                /_/          |
  |              syslog.csv --[+]--> syslog.xlsx                |
  |                            ^                                |
  |                            |                                |
  |                       [cli options]                         |
  +-------------------------------------------------------------+
  Splunk query for a suitable syslog.csv:
    index=network sourcetype=syslog
     [hostname(s)/filter]
     | rex field=_raw ".*%?(?<code>.*?):\s*(?<msg>.*)"
     | table _time host code msg

   Example:
   sl.heatmap -i ifaces.csv syslog.csv

   If syslog covers 1 day, then create heatmap with 10m columns:
   sl.heatmap -i ifaces.csv -z ,,10T syslog.csv
'''

import os
import sys
import re

import argparse
import pandas as pd

from xlsxwriter.utility import xl_range_abs, xl_col_to_name


def parseargs(argv):
    'parse commandline arguments, return arguments Namespace'
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    padd = p.add_argument
    padd('--verbose', '-v', action='count', help='verbose flag', default=0)
    padd('--iface-map', '-i', required=False, type=str, default='',
         help='csv-file, fields: switch,iface,host[,..]')
    padd('--nokeep', '-n', required=False, action='store_true',
         help='donot keep ifaces without a mapping to a host')
    padd('--output', '-o', required=False, type=str, default='',
         help='output filename, default <infile>.xlsx')
    padd('--zoom', '-z', required=False, type=str, default='',
         help="start,stop,frequency csv-list to zoom in on")
    padd('--codes', '-c', required=False, type=str, 
         default='LINEPROTO-5-UPDOWN,LINK-3-UPDOWN',
         help="csv-list of codes to select for heatmap")
    padd('--sparse', '-s', action='store_true', required=False, default=False,
         help="drop columns with all zero's")
    padd('--timestrip', '-t', action='store_false', required=False,
         help="strip offsets in _time: yyyy-mm-ddThh:mm:ss+offset")
    padd('syslog', help='syslog csv-file, fields:_time,host,code,msg')

    arg = p.parse_args(argv)
    if not arg.syslog.endswith('csv'):
        msg(0, 'Fatal: only digest csv-files, not ' + repr(arg.syslog))
        sys.exit(1)

    if arg.codes:
        arg.codes = [x.strip() for x in arg.codes.split(',')]
    else:
        arg.codes = ['LINK-3-UPDOWN', 'LINEPROTO-5-UPDOWN']

    # read_syslog sets zoom start/end if its a NaT
    if arg.zoom:
        arg.zoom = arg.zoom.split(',')
        if len(arg.zoom) != 3:
            raise Exception('zoom needs start,end,freq as csv-list!')
        # either of both start,end may be omitted -> ends up as NaT
        # and syslog_read will set it to first/last+1 day found
        arg.zoom[:2] = pd.to_datetime(arg.zoom[0]), pd.to_datetime(arg.zoom[1])
    else:
        arg.zoom = [pd.NaT, pd.NaT, 'D']

    if not arg.output:
        arg.output = os.path.splitext(arg.syslog)[0] + '.xlsx'

    print('Running with:\n', arg)

    return arg


def read_syslog(fname):
    'turn syslog into dataframe with proper columns and a DatetimeIndex'
    try:
        df = pd.read_csv(fname)
    except (IOError, OSError):
        msg(0, 'Fatal: unreadable input file {}'.format(repr(args.syslog)))
        sys.exit(1)

    df.columns = df.columns.str.lower().str.replace('_', '')  # _time
    required = set('time host code msg'.split())
    intersect = set(df.columns.tolist()).intersection(required)
    if intersect != required:
        msg(0, 'Fatal: missing column(s): {}'.format(required - intersect))
        sys.exit(1)

    df = df.dropna()
    # From: https://answers.splunk.com/answers/224134/force-displayed-timezone-in-results-to-be-utc-not-1.html
    #
    # Splunk stores an event's time as an epochtime value, ie as the number of
    # seconds since 1/1/1970, and no timezone information is stored with it at
    # all.  Before that, as the event is indexed, when a string formatted time
    # is encountered in the raw data, Splunk of course relies on it's
    # configuration to tell what timezone it should interpret this string as,
    # before it converts it to an epochtime value.
    #
    # Then much later when the event is displayed in the Splunk UI, splunk will
    # at that moment convert the _time value from epochtime (big number of
    # seconds), to a string formatted time. Here of course it needs to pick a
    # timezone again and what it picks is the timezone of the Search Head.
    #
    # I think it's worth noting that UTC can sometimes be misinterpreted as a
    # synonym for "epochtime", which it is not. UTC is a timezone, basically GMT
    # with no daylight saving time ever. Sometimes you'll also come across the
    # idea that "epochtime is in UTC" which is nonsensical cause an epochtime is
    # just a number of seconds.
    #
    # Anyway, it's not uncommon for a whole splunk deployment to have everything
    # including search heads, living in the UTC timezone. In my experience this
    # is extremely confusing for many of the users, but it does work as
    # advertised; all displayed times would be in the UTC (ie GMT) timezone.

    # Nb: when looking at syslogs of the last 15 mins, the UI timestamps align
    # with my current wall-clock time, eg 10:15, but exporting to csv yields
    # 10:15+02:00, which is why args.timestrip is True by default.

    if args.timestrip:
        df.time = df.time.str.replace(r'\+.*$', '')
    df.time = pd.to_datetime(df.time)
    df.set_index('time', inplace=True)
    df.sort_index(inplace=True)

    # ensure valid zoom start/end (use syslog timestamps as needed)
    if pd.isnull(args.zoom[0]):
        args.zoom[0] = pd.to_datetime(df.index.min().floor('d'))
    if pd.isnull(args.zoom[1]):
        args.zoom[1] = pd.to_datetime(df.index.max().ceil('d'))

    msg(0,
        '\nread syslog file:',
        '\n- entries    :', len(df.index),
        '\n- first      :', df.index.min(),
        '\n- last       :', df.index.max(),
        '\n- zoom start :', args.zoom[0],
        '\n- zoom end   :', args.zoom[1],
        '\n')

    return df


def read_ifaces(fname):
    'turn iface map into dataframe with switch.iface as its index'
    try:
        df = pd.read_csv(fname)
    except (IOError, OSError):
        msg(0, 'iface map not provided or unreadable: skip this!')
        return pd.DataFrame()  # empty dataframe

    df.columns = df.columns.str.lower()
    required = set('switch iface host'.split())
    intersect = set(df.columns.tolist()).intersection(required)
    if intersect != required:
        msg(0, 'Non-fatal error in {}:'.format(args.iface_map),
            'missing column(s) {},'.format(required - intersect),
            'skipping interface map')
        return pd.DataFrame()

    # add idx-column as switch.iface, ensure iface is 1 letter + x/y/z
    rgx = re.compile('(?<=^.)[^0-9]+')
    df = df.assign(idx=df.switch.str.lower() +
                   '.' +
                   df.iface.str.lower().replace(to_replace=rgx,
                                                value='',
                                                regex=True))
    df.host = df.host.str.strip()
    # no dups in index -> df.loc[sw.iface] always returns a NaN or a
    # single row as a Series and never a dataframe (ie for dups).
    # - Required by get_heatmap's lookup
    df.drop_duplicates(subset='idx', keep='first', inplace=True)
    df.set_index('idx', inplace=True)
    df.sort_index(inplace=True)

    return df


def limit_codes(syslog, codes=None):
    'limit syslogs to list of codes'
    if 'code' not in syslog.columns:
        msg(0, 'hmm, syslog is missing code column for limiting syslogs')
        return syslog
    if codes:
        syslog = syslog[syslog.code.isin(codes)]
    return syslog


def limit_times(df, start, end):
    'select rows at or after start and before end'
    if pd.isnull(start) and pd.isnull(end):
        msg(0, 'no start,end, returning df')
        return df
    start = df.index.min() if pd.isnull(start) else start
    end = df.index.max() if pd.isnull(end) else end

    return df[(df.index >= start) & (df.index < end)]


def add_pkey_column(df, pkey='iface'):
    'add a named primary key column, (from host & iface from msg column)'
    if 'msg' not in df.columns:
        msg(0, 'hmmm, df is missing msg column for iface extraction')
        return df

    # new pkey col = long interface name extracted from msg column
    # TODO: currently rgx is for LINK-3-UPDOWN/LINEPROTO msg's
    #       other commands with interface <iface> without comma wont match!
    rgx = re.compile('(?i)(?:interface)(?P<ifpkey>[^,]+?),')
    df = df.assign(**{pkey: df.msg.str.extract(rgx, expand=True)})

    # then shorten iface-name and prepend host name
    rgx = re.compile('(?<=^..)[^0-9]+')
    df[pkey] = df[pkey].replace(to_replace=rgx, value='', regex=True)
    df[pkey] = df[pkey].fillna('?')
    df[pkey] = df[pkey].str.lower().str.strip()
    df[pkey] = df.host.str.lower() + '.' + df[pkey]
    df[pkey] = df[pkey].str.replace('\.\?', '')

    return df


def col_by_pkey_lookup(df, newcol, pkey, iface_map, drop=False):
    'replace or add a column in df by lookup up primary key in iface_map'
    if iface_map.empty:
        return df

    if not iface_map.index.is_unique:
        msg(0,
            '\nNon-fatal: dropping duplicated (!) entries',
            'from {}'.format(args.iface_map))
        # drop rows with duplicated index-entries
        iface_map = iface_map.groupby(iface_map.index).first()

    def lookup(iface):
        'lookup host by iface, return host, iface or None'
        try:
            row = iface_map.loc[iface]
        except KeyError:
            if drop:
                return None
            return iface

        return str(row.host).replace(' ', '_')

    df[newcol] = df[pkey].apply(lookup)

    if drop:
        return df.dropna()
    return df


def get_heatmap(df, column, start, end, freq):
    'Downsample Datetimeindex-d dataframe on col,return mx: colxtime->count'
    # TODO: fix all zeros when using default start/end from samples
    # - when you zoom, all is well -> non-zero entries
    # - when you donot zoom (start/end=syslog based) -> all zero's results?
    # df has datetime index and at least an iface column
    # -- start,end now alwyas set by read_syslog
    mx = df[(df.index >= start) & (df.index < end)]
    if column not in mx.columns:
        msg(0, 'fatal: missing column', column, 'for heatmap creation')
    # for idx, row in mx.iterrows():
    #     print(row.host, type(row.host))

    mx = mx.groupby([mx.index.name, column]).size()
    mx = mx.unstack(level=-1, fill_value=0)
    mx = mx.resample(freq).sum()
    # actual samples might not start/end on start/end
    ts = pd.date_range(start=start, end=end, freq=freq)
    mx = mx.reindex(ts).fillna(0).T
    if args.sparse:
        mx = mx.dropna(axis=1, how='all')
    else:
        mx = mx.fillna(0)
    return mx


def write_heatmap(fname, syslog, ifaces, heatmap):
    'write xlsx with sheets for heatmap, syslog and iface map'
    # nb: see https://xlsxwriter.readthedocs.io/format.html
    # - you can't format the dataframe's index in excell
    # - you cant read cell values with xslxwriter (its a writer)
    # - cell format > row format > column format
    writer = pd.ExcelWriter(fname)
    fmt_heatcells = writer.book.add_format({'align': 'center',
                                            'valign': 'vcenter',
                                            'bold': False,
                                            'font_name': 'mono',
                                            'font_size': 8})
    # heatmap sheet
    name, mx = 'heatmap', heatmap
    mx.to_excel(writer, name)
    sh = writer.sheets[name]
    sh.freeze_panes(1, 1)
    cells = xl_range_abs(1, 1, len(mx), len(mx.columns))
    sh.conditional_format(cells, {'type': '2_color_scale',
                                  'min_color': '#99ff99',
                                  'max_color': '#ff3300'})
    cols = 'B:{}'.format(xl_col_to_name(len(mx.columns)))
    sh.set_column('A:A', 40)
    sh.set_column(cols, 3, fmt_heatcells)

    # syslog sheet
    name, mx = 'syslog', syslog
    mx.to_excel(writer, name)
    sh = writer.sheets[name]
    sh.freeze_panes(1, 1)
    sh.set_column('A:A', 20)

    # ifaces sheet
    name, mx = 'ifaces', ifaces
    mx.to_excel(writer, name)
    sh = writer.sheets[name]
    sh.freeze_panes(1, 1)
    sh.set_column('A:A', 25)

    # Lastly, let the writer save it all
    writer.save()

    return 1


def msg(level, *a):
    'possibly print something'
    if args and level > args.verbose:
        return
    print(' '.join(str(i) for i in a), file=sys.stderr)


def main():
    'main func'
    try:
        syslog = read_syslog(args.syslog)     # index = DatetimeIndex (time)
        ifaces = read_ifaces(args.iface_map)  # index = switch.iface (idx)

        # filter by syslog codes
        slines = limit_codes(syslog, args.codes)
        if not(len(slines)):
            msg(0, 'fatal, code filter leaves no entries:', args.codes)
            sys.exit(1)

        # filter by syslog timestamps
        slines = limit_times(slines, *args.zoom[0:2])
        if not(len(slines)):
            msg(0, 'fatal: time filter leaves no entries:', args.zoom[0:2])
            sys.exit(1)

        slines = add_pkey_column(slines, 'pkey')
        slines = col_by_pkey_lookup(slines, 'host', 'pkey',
                                    ifaces, args.nokeep)
        heatmap = get_heatmap(slines, 'host', *args.zoom)

        msg(0, '\n---',
            '\nsyslog  - {} messages'.format(len(syslog.index)),
            '\nifaces  - {} mappings found'.format(len(ifaces.index)),
            '\nslines  - {} messages seen'.format(len(slines.index)),
            '\nzoom window',
            '\n - start:', args.zoom[0],
            '\n - end  :', args.zoom[1],
            '\n - freq :', args.zoom[2],
            '\nheatmap - device-rows, time-cols =', heatmap.shape,
            '\n---')

        # Make for nice time-headers in heatmap sheet
        freq = args.zoom[2]
        if 'M' in freq:
            tfmt = '%Y' + chr(10) + '%b'         # by month
        elif 'D' in freq:
            tfmt = '%b' + chr(10) + '%d'         # by day
        elif 'T' in freq:
            tfmt = '%d %b' + chr(10) + '%H:%M'   # by minute
        elif 'H' in freq:
            tfmt = '%d %b' + chr(10) + '%H:%M'   # by hour
        else:
            tfmt = '%Y%m%d' + chr(10) + '%H:%M'  # by default
        heatmap.columns = heatmap.columns.strftime(tfmt)

        # enrich unfiltered syslog with attached system, where possible
        syslog = add_pkey_column(syslog, 'system')
        syslog = col_by_pkey_lookup(syslog, 'system', 'system', ifaces)

        suc6 = write_heatmap(args.output, syslog, ifaces, heatmap)
        if suc6:
            msg(0, 'success - see {} for results'.format(args.output))

    except (OSError, IOError) as e:
        msg(0, 'Error', repr(e))
        return 1

    return 0


if __name__ == '__main__':
    args = parseargs(sys.argv[1:])
    sys.exit(main())
