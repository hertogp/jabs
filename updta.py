#!/usr/bin/env python3
'''
helper module to update data in dta subdir

usage: ./updta.py
 - loads ip4 protocol numbers from iana
 - loads ip4 services from iana
'''

import sys
import pandas as pd
import numpy as np

URL_PROTOCOLS = 'https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv'
URL_SERVICES = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'


def load_csv(url):
    df = pd.read_csv(url)
    df.columns = df.columns.str.lower()
    df.columns = df.columns.str.replace(r'\s+', '_')
    return df

def write_csv(df, fname):
    df.to_csv(fname, index=False, mode='w')
    return df

def load_protocols(url, fname):
    'load protocol numbers from iana and prep a ip4-protocols.csv file'
    # get & prep IPv4 protocol names
    cols = 'decimal keyword protocol'.split()
    df = load_csv(url)

    # keep interesting columns & drop rows where decimal/keyword are nan's
    df = df[cols]
    df = df.dropna(subset=['decimal'])

    # clean up values
    df['protocol'] = df['protocol'].str.replace(r'\s+', ' ') # clean spaces
    df['keyword'] = df['keyword'].str.replace(r'\s.*$', '')  # 1st word
    df['keyword'] = df['keyword'].str.lower()
    df['decimal'] = df['decimal'].astype(str)   # ensure they're all strings!
    df['decimal'] = df['decimal'].str.replace(r'\s+', '')  # no whitespace
    df = df.drop_duplicates(subset='decimal', keep='first')  # drop dups

    # eliminate protocol-ranges by making them explicit
    rows = []
    for idx, row in df[df['decimal'].str.contains('-')].iterrows():
        parts = row['decimal'].split('-')
        start = int(parts[0])
        stop  = int(parts[-1])
        keyw = 'ip4-{}'.format(num) if not row['keyword'] else row['keyword']
        proto = row['protocol']
        for num in range(start, stop+1):
            rows.append({'decimal': str(num),
                         'keyword': keyw,
                         'protocol': proto})

    df = df.append(rows, ignore_index=True)
    df = df[~df['decimal'].str.contains('-')]
    # set NaN keywords to <nr>
    df['keyword'] = np.where(df['keyword'].isnull(),
                             '<' + df['decimal'] + '/ip>',
                             df['keyword'])

    df['protocol'] = np.where(df['protocol'].isnull(),
                              '<' + df['keyword'] +'>',
                              df['protocol'])
    write_csv(df, fname)

    return len(df)

def load_services(url, fname):
    'load ip4 services from iana and prep ip4-services.csv file'

    cols = 'port_number transport_protocol service_name'.split()
    df = load_csv(URL_SERVICES)
    df = df[cols]
    df = df.dropna() # if any field is nan, drop the row

    for col in cols:
        df[col] = df[col].astype(str)               # ensure strings
        df[col] = df[col].str.lower()               # lowercase
        df[col] = df[col].str.replace(r'\s.*$', '') # 1st word only
        df[col] = df[col].str.replace('_', '-')     # aliased names -/_

    # eliminate port-ranges by making them explicit
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

    write_csv(df, fname)

    return len(df)

if __name__ == '__main__':

    n = load_protocols(URL_PROTOCOLS, 'dta/ip4-protocols.csv')
    print('loaded {:5} ipv4-protocol entries'.format(n))

    n = load_services(URL_SERVICES, 'dta/ip4-services.csv')
    print('loaded {:5} ipv4-service entries'.format(n))

