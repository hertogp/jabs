#!/usr/bin/env python3
'''
helper module to update data in dta subdir

usage: ./updta.py
 - loads ip4 protocol numbers from iana
 - loads ip4 services from iana
'''

import sys
import argparse
import logging
import json
import pandas as pd
import numpy as np

__version__ = '0.1'
#-- logging
log = logging.getLogger(__name__)
log.setLevel(logging.WARNING)

URL_PROTOCOLS = 'https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv'
URL_SERVICES = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'

def console_logging(log_level):
    'setup console logging to level given by args.v'
    console_fmt = logging.Formatter('%(funcName)s %(levelname)s: %(message)s')
    console_hdl = logging.StreamHandler(stream=sys.stderr)
    console_hdl.set_name('console')
    console_hdl.setFormatter(console_fmt)
    console_hdl.setLevel(log_level)
    log.setLevel(log_level)
    log.addHandler(console_hdl)

def parse_args(argv):
    'parse commandline arguments, return arguments Namespace'
    p = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__)
    padd = p.add_argument
    padd('-p', '--protocols', action='store_false')
    padd('-s', '--services', action='store_true')
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

def load_csv(url):
    'load a csv into a df and normalize columns name somewhat'
    df = pd.read_csv(url)
    df.columns = df.columns.str.lower()
    df.columns = df.columns.str.replace(r'\s+', '_')
    log.info('done reading url')
    return df

def write_csv(df, fname):
    'write a csv without index for filename'
    df.to_csv(fname, index=False, mode='w')
    return df

def protocol_tojson(df, fname):
    'write protocols to json files'
    # store ip protocol info in json, so we dont need pandas afterwards
    dd = df.set_index('decimal')
    dd = dd.drop_duplicates()
    dct = dict(zip(dd.index, zip(dd['keyword'], dd['protocol'])))
    with open(fname, 'w') as outfile:
        json.dump(dct, fp=outfile)
    log.info('saved {} entries'.format(len(dct)))

def services_tojson(df, fname):
    'write services to json files'
    # port/protocol -> service_name
    dd = df.copy()
    pt = 'port_number transport_protocol'.split()
    dd['port'] = dd[pt].apply(lambda g: '/'.join(x for x in g), axis=1)
    dct = dict(zip(dd['port'], dd['service_name']))
    with open(fname, 'w') as outfile:
        json.dump(dct, fp=outfile)
    log.info('saved {} unique entries'.format(len(dct)))


def load_protocols(url):
    'load protocol numbers from iana and prep a ip4-protocols.csv file'
    # get & prep IPv4 protocol names
    try:
        df = load_csv(url)
        cols = 'decimal keyword protocol'.split()
        df = df[cols]
    except KeyError:
        raise Exception('Unexpected/different data, wrong url {}?'.format(url))

    # clean up values
    log.info('cleaning up strings')
    df['protocol'] = df['protocol'].str.replace(r'\s+', ' ') # clean spaces

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
        stop  = int(parts[-1])
        proto = row['protocol']
        orgkey =  row['keyword']
        for num in range(start, stop+1):
            keyw = 'ip{}'.format(num) if pd.isnull(orgkey) else orgkey
            rows.append({'decimal': str(num),
                         'keyword': keyw,
                         'protocol': proto})

    df = df.append(rows, ignore_index=True)
    df = df[~df['decimal'].str.contains('-')]  # drop the 'start-max' entries

    # set any remaining NaN keywords to <nr>
    # donot use '{}/ip'.format(df['decimal']) <-- insert whole decimal column ..
    log.info('filling empty strings (if any) with sane defaults')
    df['keyword'] = np.where(df['keyword'].isnull(),
                             'ip' + df['decimal'],
                             df['keyword'])

    # set any remaining NaN protocols to keyword
    df['protocol'] = np.where(df['protocol'].isnull(),
                              df['keyword'],
                              df['protocol'])
    return df


def load_services(url, fname):
    'load ip4 services from iana and prep ip4-services.csv file'

    cols = 'port_number transport_protocol service_name'.split()
    df = load_csv(URL_SERVICES)
    log.info('keep only columns {!r}'.format(cols))
    df = df[cols]
    df = df.dropna() # if any field is nan, drop the row

    log.info('cleaning up strings')
    for col in cols:
        df[col] = df[col].astype(str)               # ensure strings
        df[col] = df[col].str.lower()               # lowercase
        df[col] = df[col].str.replace(r'\s.*$', '') # 1st word only
        df[col] = df[col].str.replace('_', '-')     # aliased names -/_

    # eliminate port-ranges by making them explicit
    log.info('make port-ranges explicit')
    rows = []
    for idx, row in df[df['port_number'].str.contains('-')].iterrows():
        parts = row['port_number'].split('-')
        start = int(parts[0])
        stop  = int(parts[-1])
        service = 'p-{}'.format(num) if not row['service_name'] else row['service_name']
        proto = row['transport_protocol']
        if not proto:
            continue
        for num in range(start, stop+1):
            rows.append(dict(zip(cols, [str(num), proto, service])))

    df = df.append(rows, ignore_index=True)
    df = df[~df['port_number'].str.contains('-')]
    log.info('{} entries after clean up'.format(len(df.index)))
    return df

def main():

    if args.protocols:
        log.info('retrieving protocols, url {}'.format(URL_PROTOCOLS))
        dfp = load_protocols(URL_PROTOCOLS)
        write_csv(dfp, 'dta/ip4-protocols.csv')
        protocol_tojson(dfp, 'ip4-protocols.json')
        log.info('-> done!')

    if args.services:
        log.info('retrieving services, url {}'.format(URL_SERVICES))
        dfs = load_services(URL_SERVICES, 'dta/ip4-services.csv')
        write_csv(dfs, 'dta/ip4-services.csv')
        services_tojson(dfs, 'ip4-services.json')
        log.info('-> done!')


if __name__ == '__main__':
    args = parse_args(sys.argv)
    console_logging(args.log_level)
    sys.exit(main())
