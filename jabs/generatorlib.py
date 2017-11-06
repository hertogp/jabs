#!/usr/bin/env python

"""
Python2, generator functions for a variety of tasks.
"""

import os
import sys
import gzip, bz2
import types
import re

def g_find(pattern, top, recurse = True):
    """yield filenames matching a pattern or list of patterns"""
    if type(pattern) in types.StringTypes:
        pattern = [pattern]

    cpattern = [re.compile(p) for p in pattern]
    for path, dirlist, filelist in os.walk(top):
        for fname in filelist:
            for cp in cpattern:
                if cp.search(fname):
                    yield os.path.join(path, fname)
                    break
        if not recurse: break

def g_open(fnames, dbg=False, flags='r'):
    """yield a series of opened filehandles"""
    for fname in fnames:
        if dbg: print >> sys.stderr, "Opening %s" % fname
        if fname.endswith('.gz'):
            yield gzip.open(fname,flags)
        elif fname.endswith('.bz2'):
            yield bz2.BZ2File(fname)
        else:
            yield open(fname)

def g_cat(sources, max_num = 0):
    """yield items from each source, possibly only the first max_num items of each source"""
    for source in sources:
        num = 0
        for item in source:
            num += 1
            if max_num and num > max_num: break
            try:
                yield item.strip()
            except AttributeError:
                yield item

def g_grep(pattern, lines):
    """yield lines matching one or more patterns"""
    if type(pattern) in types.StringTypes: pattern = [pattern]
    cpattern = [re.compile(p) for p in pattern]
    for line in lines:
        for p in cpattern:
            if p.search(line): 
                yield line
                break

def g_cut(delimstr, lines, fields=None):
    """yield array of fields from lines after splitting on delimstr
    A delimstr of None is the same as line.split(),
    A fields==None will return all fields,
    Specifying field numbers (e.g. [0,2] yields first and third field"""
    for line in lines:
        flist = line.split(delimstr)
        flen = len(flist)
        if fields:
            yield [flist[i] if i<flen else '' for i in fields]
        else:
            yield flist

def g_tokens(delimstr, lines, sentinel = None):
    """split lines on delims and yield individual fields, ending with sentinel"""
    for line in lines:
        for field in line.split(delimstr):
            yield field
        if sentinel: yield sentinel

class storelast(object):
    'an iterator that stores the last value returned'
    def __init__(self,source):
        self.source = source
    def next(self):
        item = self.source.next()
        self.last = item
        return item
    def __iter__(self):
        return self
