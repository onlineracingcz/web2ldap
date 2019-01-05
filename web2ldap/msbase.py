# -*- coding: utf-8 -*-
"""
msbase.py - some basic stuff

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

from collections import defaultdict


def union(a, b):
    """
    Return union of two lists a, b.
    """
    temp = {}
    for elt in a:
        temp[elt.lower()] = elt
    for elt in b:
        temp[elt.lower()] = elt
    return temp.values()


class DefaultDict(defaultdict):
    """
    Dictionary which returns a default value for non-existent keys.
    """

    def __init__(self, d=None, default=None):
        defaultdict.__init__(self, default=default)
        self.__default__ = default
        d = d or {}
        for k, v in d.items():
            self.__setitem__(k, v)

    def __missing__(self,key):
        return self.__default__


class Str1stValueDict(DefaultDict):

    def __setitem__(self, k, v):
        DefaultDict.__setitem__(self, k, v[0])


class GrabKeys:
    """
    Class for grabbing the string-formatting keys out of a string
    """

    def __init__(self,s):
        self.keys = set([])
        s % self

    def __call__(self):
        return self.keys

    def __getitem__(self, name):
        self.keys.add(name)
        return 0 # 0 is apparently compatible with all % format characters


class CaseinsensitiveStringKeyDict(DefaultDict):
    """
    Dictionary class for case-insensitive string-keyed dictionaries
    """

    def __init__(self,default_dict=None,default=None):
        DefaultDict.__init__(self,default=default)
        self.update(default_dict or {})

    def __setitem__(self,key,value):
        DefaultDict.__setitem__(self,key.lower(),value)

    def __getitem__(self,key):
        return DefaultDict.__getitem__(self,key.lower())


def chunks(l,s):
    q, r = divmod(len(l), s)
    for i in range(q):
        yield l[i*s:(i+1)*s]
    if r:
        yield l[q*s:]


def ascii_dump(s):
    r = []
    for b in s:
        if ' ' <= b <= '~':
            r.append(b)
        else:
            r.append('.')
    return ''.join(r)
