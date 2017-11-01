#!/usr/bin/env python3
'''
Ip4Filter - filter ip sessions using src,dst and optionally portstr
'''
import os
import sys
import re
import math
import pandas as pd
import pytricia as pt
from itertools import zip_longest

#-- glob
__version__ = '0.1'
class Ip4Filter(object):
    '''
    A class for ip session lookup's via src, dst [,portstring]
    - match() -> True, False or no_match value (None by default)
    - get()   -> Ip4Match object {
                    'match': True or False or no_match value,
                    'data' : dta dict or empty dict (if any)
                    'ruleid': lowest matching rulenr or -1,
                    'ruleids': all matching rulenrs
                    }
    '''
    def __init__(self, filename=None):
        self._src = pt.PyTricia()  # pfx -> set(rids) - Ival(src ip pfx)
        self._dst = pt.PyTricia()  # pfx -> set(rids) - Ival(dst ip pfx)
        self._dpp = pt.PyTricia()  # pfx'-> set(rids) - Ival(dport/protocol)
        self._act = {}             # rid -> action (True of False)
        self._dta = {}             # rid -> dict data fields (if any)
        self._pp = Ip4Protocol()   # an Ip4Protocol object
        self._nomatch = None       # is returned when filter has no match
        self.filename = filename
        if filename:
            self.from_csv(filename)

    def __len__(self):
        return len(self._act)

    def _set_rid(self, rid, tbl, pfx):
        'set rule-id on single prefix in specific table'
        try:
            if tbl.has_key(pfx):        # find the exact prefix
                tbl[pfx].add(rid)       # add to existing prefix
            else:
                tbl[pfx] = set([rid])   # it's a new prefix

            # propagate rid to more specifics
            for kid in tbl.children(pfx):  # propagate rid to the more specifics
                tbl[kid].add(rid)

            # adopt rid's matched by less specific parent (if any)
            parent = tbl.parent(pfx)
            if parent:
                tbl[pfx] = tbl[pfx].union(tbl[parent])

        except ValueError as e:
            log.error('invalid prefix? {} :{}'.format(pfx, repr(e)))
            sys.exit(1)

    def set_nomatch(self, nomatch):
        'Sets the value for a no-match, returns the old value'
        self._nomatch, oldval = nomatch, self._nomatch
        return oldval

    def add(self, rid, srcs, dsts, ports, action='', dta={}):
        'add a new rule or just add src and/or dst to an existing rule'
        summary = Ival.pfx_summary
        for ival in summary(x.network() for x in map(Ival.from_pfx, srcs)):
            self._set_rid(rid, self._src, ival.to_pfx())

        for ival in summary(x.network() for x in map(Ival.from_pfx, dsts)):
            self._set_rid(rid, self._dst, ival.to_pfx())

        for ival in summary(x.network() for x in map(Ival.from_portstr, ports)):
            self._set_rid(rid, self._dpp, ival.to_pfx())

        fmt = 'warn: {}, {} swaps {!r} for new {!r}'

        # always set an action for rid: default to False
        new = action.lower() == 'permit' if action else self._act.get(rid, False)
        old = self._act.setdefault(rid, new)
        if old != new:
            self._act[rid] = new
            print(fmt.format(rid, 'action', old, new))

        # always set additional data dict (when it doesn't exist already)
        old = self._dta.get(rid, None)  # get the old value
        if old is None:
            self._dta[rid] = dta            # set the new value
            if old is not None and old != dta:  # if existing old != new, warn
                print(fmt.format(rid, 'dta', old, dta))

        return True

    def clear(self):
        'clear all the rules'
        self._src = pt.PyTricia()  # pfx -> set([rid's])
        self._dst = pt.PyTricia()  # pfx -> set([rid's])
        self._dpp = pt.PyTricai()  # pfx' -> set([rids])
        self._act = {}             # rid -> action (True of False)

    def get_rids(self, src, dst, port=None, proto=None):
        'return the set of rule ids matched by session-tuple'

        try:
            if port is None:
                dpp = None
            elif proto is None:
                dpp = Ival.from_portstr(port).to_pfx()
            else:
                dpp = Ival.from_portproto(int(port), int(proto)).to_pfx()
            rids = self._dst[dst]
            if dpp is not None:
                rids = rids.intersection(self._dpp[dpp])
            return rids.intersection(self._src[src])
        except (KeyError, ValueError):
            return set()
        except TypeError:  # invalid port, proto
            print('get rids error on port, proto', port, proto)
            return set()

    def match(self, src, dst, port=None, proto=None):
        'return True (permit), False (no permit) or the nomatch value'
        rids = self.get_rids(src, dst, port, proto)
        if len(rids) == 0:
            return self._nomatch
        # TODO: make it an error is a rule-id is missing from _act
        return self._act.get(min(rids), self._nomatch)

    def get(self, src, dst, port=None, proto=None):
        'return match object of the matching rule or the nomatch value'
        rids = self.get_rids(src, dst, port, proto)
        if len(rids) == 0:
            return self._nomatch

        # TODO: make it an error is a rule-id is missing from _act
        return self._dta.get(min(rids), self._nomatch)

    def rules(self):
        'reconstruct the rules in a dict of dicts'
        # {rule_id} -> {src:[srcs],
        #               dst:[dsts],
        #               dport: [ports],
        #               action: action,
        #               dta: {dta-dict}
        #              }
        rules = {}
        # note: a PyTricia dict has no items() method
        for pfx in self._src.keys():
            ruleset = self._src[pfx]
            for rulenr in ruleset:
                dct = rules.setdefault(rulenr, {})
                dct.setdefault('src', []).append(pfx)

        # by now, rules should have all available rule nrs
        errfmt = 'Malformed Filter for rule {}'
        for pfx in self._dst.keys():
            ruleset = self._dst[pfx]
            for rulenr in ruleset:
                dct = rules.setdefault(rulenr, {})
                if len(dct) == 0:
                    raise Exception(errfmt.format(rulenr))
                dct.setdefault('dst', []).append(pfx)

        for dpp in self._dpp.keys():
            ruleset = self._dpp[dpp]
            port = Ival.from_pfx(dpp).to_portstr()
            for rulenr in ruleset:
                dct = rules.setdefault(rulenr, {})
                if len(dct) == 0:
                    raise Exception(errfmt.format(rulenr))
                dct.setdefault('dport', []).append(port)

        for rulenr, action in self._act.items():
            dct = rules.get(rulenr, None)
            if dct is None:
                raise Exception(errfmt.format(rulenr))
            dct['action'] = action

        for rulenr, data in self._dta.items():
            dct = rules.get(rulenr, None)
            if dct is None:
                raise Exception(errfmt.format(rulenr))
            dct['dta'] = data

        # sanitize more specifics in a src/dst list of a rule
        for r, rule in rules.items():
            summ  = Ival.pfx_summary(map(Ival.from_pfx, rule['src']))
            rule['src'] = [x.to_pfx() for x in summ]

            summ  = Ival.pfx_summary(map(Ival.from_pfx, rule['dst']))
            rule['dst'] = [x.to_pfx() for x in summ]

            # TODO: minimize port ranges
            summ = Ival.port_summary(map(Ival.from_portstr, rule['dport']))
            rule['dport'] = [x.to_portstr() for x in summ]

        return rules

    def lines(self, csv=False):
        'return filter as lines for printing'
        # {rule_id} -> {src:[srcs],
        #               dst:[dsts],
        #               dport: [ports],
        #               action: action,
        #               dta: {dta-dict}
        #              }
        rules = sorted(self.rules().items())  # rules dict -> ordered [(k,v)]
        rdct=rules[-1][-1]  # a sample dta dict

        required_fields = 'rule src dst dport action'.split()
        dta_fields = sorted(rdct.get('dta', {}).keys())  # sorted dta keys
        dta_fields = [x for x in rdct['dta'].keys() if x not in required_fields]

        fmt = '{},{},{},{},{}' if csv else '{:<5} {:21} {:21} {:16} {:7}'
        dta_header = ',{}' if csv else ' {:15}'
        fmt += dta_header * len(dta_fields)

        all_fields = required_fields + dta_fields
        lines = [fmt.format(*all_fields)]   # csv-header of field names
        for nr, rule in rules:
            maxl = max(len(rule['src']), len(rule['dst']), len(rule['dport']))
            for lnr in range(0, maxl):
                src = rule['src'][lnr] if lnr < len(rule['src']) else ''
                dst = rule['dst'][lnr] if lnr < len(rule['dst']) else ''
                prt = rule['dport'][lnr] if lnr < len(rule['dport']) else ''
                if lnr == 0:
                    act = 'permit' if rule['action'] else 'deny'
                else:
                    act = ''
                if lnr == 0:
                    data = [rule['dta'][k] for k in dta_fields]
                else:
                    data = [''] * len(dta_fields)

                lines.append(fmt.format(nr, src, dst, prt, act, *data))
                nr = ''  # only list rule nr on first line
        return lines

    def to_csv(self, fname):
        'write ruleset to csv-file'
        try:
            outf = fname if fname is sys.stdout else open(fname, 'w')
            for line in self.lines(csv=True):
                print(line, file=outf)
            if outf is not sys.stdout:
                outf.close()
        except (IOError, OSError) as e:
            fmt = 'error saving {!}: {!r}'
            raise OSError(fmt.format(fname, e))
        return True


    def from_csv(self, fname):
        'read ruleset from csv-file'
        # TODO: check for empty df and presence of required fields
        inpfile = fname if os.path.isfile(fname) else '{}.csv'.format(fname)
        try:
            df = pd.read_csv(inpfile, skipinitialspace=True)
        except (IOError, OSError):
            df = pd.DataFrame()  # empty dataframe

        df.columns = [re.sub(r'(\s|\.)+', '_', n) for n in df.columns]
        # df = ut.load_csv(inpfile)
        if len(df.index) == 0:
            raise IOError('Ip4Filter cannot read {!r}'.format(fname))

        # checking columns and get superfluous cols into list for later dta dict
        required_columns = 'rule src dst dport action'.split()
        missing = [x for x in required_columns if x not in df.columns.values]
        dta_cols = [x for x in df.columns.values if x not in required_columns]
        dta_cols.extend(['rule', 'action'])  # add these -> match object

        if len(missing):
            raise ValueError('Ip4Filter is missing columns {}'.format(missing))

        try:
            df['rule'].fillna(method='ffill', inplace=True)
            df.fillna(value='', inplace=True)
            df['rule'] = df['rule'].astype(int)
            for idx, row in df.iterrows():
                rid = int(row['rule'])  # TODO: we did atype(int) already?
                srcs = [x.strip() for x in row['src'].split()]
                dsts = [x.strip() for x in row['dst'].split()]
                ports = [x.strip() for x in row['dport'].split()]
                act = row['action']
                dta = row[dta_cols].to_dict()
                self.add(rid, srcs, dsts, ports, act, dta)
        except Exception as e:
            print('oops', repr(e))
            sys.exit(1)
