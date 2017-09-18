#!/usr/bin/env python3
'''
helper module to update data in dta subdir

usage: ./updta.py
 - loads ip4 protocol numbers from iana
 - loads ip4 services from iana
'''

import sys
import json
import pandas as pd
import numpy as np

URL_PROTOCOLS = 'https://www.iana.org/assignments/protocol-numbers/protocol-numbers-1.csv'
URL_SERVICES = 'https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv'


def load_csv(url):
    'load a csv into a df and normalize columns name somewhat'
    df = pd.read_csv(url)
    df.columns = df.columns.str.lower()
    df.columns = df.columns.str.replace(r'\s+', '_')
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
        print('length', len(dct))

def services_tojson(df, fname):
    'write services to json files'
    # port/protocol -> service_name
    dd = df.copy()
    pt = 'port_number transport_protocol'.split()
    dd['port'] = dd[pt].apply(lambda g: '/'.join(x for x in g), axis=1)
    dct = dict(zip(dd['port'], dd['service_name']))
    with open(fname, 'w') as outfile:
        json.dump(dct, fp=outfile)


def load_protocols(url):
    'load protocol numbers from iana and prep a ip4-protocols.csv file'
    # get & prep IPv4 protocol names
    df = load_csv(url)
    cols = 'decimal keyword protocol'.split()
    df = df[cols]
    # df = df.dropna(subset=['keyword'])

    # clean up values
    df['protocol'] = df['protocol'].str.replace(r'\s+', ' ') # clean spaces

    df['keyword'] = df['keyword'].str.strip()
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
        proto = row['protocol']
        orgkey =  row['keyword']
        for num in range(start, stop+1):
            keyw = '{}/ip'.format(num) if pd.isnull(orgkey) else orgkey
            rows.append({'decimal': str(num),
                         'keyword': keyw,
                         'protocol': proto})

    df = df.append(rows, ignore_index=True)
    df = df[~df['decimal'].str.contains('-')]  # drop the 'start-max' entries

    # set any remaining NaN keywords to <nr>
    # donot use '{}/ip'.format(df['decimal']) <-- insert whole decimal column ..
    df['keyword'] = np.where(df['keyword'].isnull(),
                             df['decimal'] + '/ip',
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

    return df

if __name__ == '__main__':

    dfp = load_protocols(URL_PROTOCOLS)
    write_csv(dfp, 'dta/ip4-protocols.csv')
    protocol_tojson(dfp, 'dta/ip4-protocols.json')
    print('got & stored {:5} ipv4-protocol entries'.format(len(dfp.index)))

    dfs = load_services(URL_SERVICES, 'dta/ip4-services.csv')
    write_csv(dfs, 'dta/ip4-services.csv')
    services_tojson(dfs, 'dta/ip4-services.json')
    print('got & stored {:5} ipv4-service entries'.format(len(dfs.index)))

