#!/usr/bin/env python3
'''
Helper script:
 - reads IANA IPv4 proto numbers & services
 - writes numbers.py
'''

import sys
import argparse
import logging
import pandas as pd
import numpy as np

__version__ = '0.1'

log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

URL_BASE = 'https://www.iana.org/assignments'
URL_PROTOCOLS = '{}/protocol-numbers/protocol-numbers-1.csv'.format(URL_BASE)
# URL_SERVICES = '{}/service-names-port-numbers/service-names-port-numbers.csv'.format(URL_BASE)
URL_SERVICES = '{0}/{1}/{1}.csv'.format(URL_BASE, 'service-names-port-numbers')
PY_OUTFILE = 'numbers.py'


def console_logging(log_level):
    'set console logging to level given by args.v'
    console_fmt = logging.Formatter('%(funcName)s %(levelname)s: %(message)s')
    console_hdl = logging.StreamHandler(stream=sys.stderr)
    console_hdl.set_name('console')
    console_hdl.setFormatter(console_fmt)
    console_hdl.setLevel(log_level)
    log.setLevel(log_level)
    log.addHandler(console_hdl)


def load_csv(url):
    'load a csv into a df and normalize column names somewhat'
    df = pd.read_csv(url)
    df.columns = df.columns.str.lower()
    df.columns = df.columns.str.replace(r'\s+', '_')
    log.info('done reading url')
    return df


def load_protocols(url):
    'load protocol numbers from iana'
    try:
        df = load_csv(url)
        cols = 'decimal keyword protocol'.split()
        df = df[cols]
    except KeyError:
        raise Exception('Unexpected/different data, wrong url {}?'.format(url))

    # clean up values
    log.info('cleaning up strings')
    df['protocol'] = df['protocol'].str.replace(r'\s+', ' ')  # clean spaces
    df['keyword'] = df['keyword'].str.strip()
    df['keyword'] = df['keyword'].str.replace(r'\s.*$', '')  # 1st word
    df['keyword'] = df['keyword'].str.lower()
    df['decimal'] = df['decimal'].astype(str)   # ensure they're all strings!
    df['decimal'] = df['decimal'].str.replace(r'\s+', '')  # no whitespace
    df = df.drop_duplicates(subset='decimal', keep='first')  # drop dups

    # eliminate protocol-ranges by making them explicit
    log.info('making protocol ranges explicit')
    rows = []
    for idx, row in df[df['decimal'].str.contains('-')].iterrows():
        parts = row['decimal'].split('-')
        start = int(parts[0])
        stop = int(parts[-1])
        proto = row['protocol']
        orgkey = row['keyword']
        for num in range(start, stop+1):
            keyw = 'ip{}'.format(num) if pd.isnull(orgkey) else orgkey
            rows.append({'decimal': str(num),
                         'keyword': keyw,
                         'protocol': proto})

    df = df.append(rows, ignore_index=True)
    df = df[~df['decimal'].str.contains('-')]  # drop the 'start-max' entries

    # set any remaining NaN keywords to <nr>
    # donot use '{}/ip'.format(df['decimal']) <-- insert whole decimal column!
    log.info('filling empty strings (if any) with sane defaults')
    df['keyword'] = np.where(df['keyword'].isnull(),
                             'ip' + df['decimal'],
                             df['keyword'])

    # set any remaining NaN protocols to keyword
    df['protocol'] = np.where(df['protocol'].isnull(),
                              df['keyword'],
                              df['protocol'])
    return df


def load_services(url):
    'load ip4 services from iana'
    cols = 'port_number transport_protocol service_name'.split()
    df = load_csv(URL_SERVICES)
    log.info('keep only columns {!r}'.format(cols))
    df = df[cols]
    df = df.dropna()  # if any field is nan, drop the row

    log.info('cleaning up strings')
    for col in cols:
        df[col] = df[col].astype(str)                # ensure strings
        df[col] = df[col].str.lower()                # lowercase
        df[col] = df[col].str.replace(r'\s.*$', '')  # 1st word only
        df[col] = df[col].str.replace('_', '-')      # aliased names -/_

    # eliminate port-ranges by making them explicit
    log.info('make port-ranges explicit')
    rows = []
    for idx, row in df[df['port_number'].str.contains('-')].iterrows():
        parts = row['port_number'].split('-')
        start = int(parts[0])
        stop = int(parts[-1])
        proto = row['transport_protocol']
        if not proto:
            continue
        service = row['service_name']
        for num in range(start, stop+1):
            srv = service if service else 'p-{}'.format(num)
            rows.append(dict(zip(cols, [str(num), proto, srv])))

    df = df.append(rows, ignore_index=True)
    df = df[~df['port_number'].str.contains('-')]
    log.info('{} entries after clean up'.format(len(df.index)))
    return df


def protocol_topy(df, fh):
    'write protocols dict'
    df['decimal'] = df['decimal'].astype('int64')
    dd = df.set_index('decimal')
    dd = dd.drop_duplicates()
    dct = dict(zip(dd.index, zip(dd['keyword'], dd['protocol'])))
    print("", file=fh)
    print('IP4PROTOCOLS = {', file=fh)
    for k, v in sorted(dct.items()):
        print('    {}: {},'.format(k, v), file=fh)
    print('}', file=fh)
    log.info('wrote {} protocol numbers to {}'.format(len(dct), fh.name))


def services_topy(df, fh):
    'write services dict'
    dd = df.copy()
    pt = 'port_number transport_protocol'.split()
    dd['port'] = dd[pt].apply(lambda g: '/'.join(x for x in g), axis=1)
    dct = dict(zip(dd['port'], dd['service_name']))
    print("", file=fh)
    print('IP4SERVICES = {', file=fh)
    for k, v in sorted(dct.items()):
        print('    {!r}: {!r},'.format(k, v), file=fh)
    print('}', file=fh)
    log.info('wrote {} service entries to {}'.format(len(dct), fh.name))


def parse_args(argv):
    'parse command line arguments'
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

    arg = p.parse_args(argv[1:])
    arg.prog = argv[0]
    return arg


def main():

    with open(PY_OUTFILE, 'w') as outf:
        print("'''", file=outf)
        print('This file is generated by ' + __file__, file=outf)
        print('Donot edit, override entries via objects:', file=outf)
        print(' - ilf.IP4Protocols', file=outf)
        print(' - ilf.IP4Services', file=outf)
        print('Data retrieved from:', file=outf)
        print(' - {}'.format(URL_PROTOCOLS), file=outf)
        print(' - {}'.format(URL_SERVICES), file=outf)
        print("'''", file=outf)

        log.info('retrieving protocols, url {}'.format(URL_PROTOCOLS))
        dfp = load_protocols(URL_PROTOCOLS)
        protocol_topy(dfp, outf)
        log.info('retrieving services, url {}'.format(URL_SERVICES))
        dfs = load_services(URL_SERVICES)
        services_topy(dfs, outf)

    log.info('done!')


if __name__ == '__main__':
    args = parse_args(sys.argv)
    console_logging(args.log_level)
    sys.exit(main())
