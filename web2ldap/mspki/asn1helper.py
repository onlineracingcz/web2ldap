"""
asn1helper.py - some utilities to make life easier with asn1.py

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from web2ldap.pisces import asn1

oids = {}


def ParseCfg(dumpasn1cfg):
  """
  Read descriptions of OIDs either from
  Peter Gutmann's dumpasn1.cfg or a pickled copy.
  """
  f=open(dumpasn1cfg,'r')
  oids=asn1.parseCfg(f)
  f.close()
  return oids


def GetOIDDescription(oid,oids,includeoid=0):
  """
  returns description of oid if present in oids or stringed oid else
  """
  try:
    cfg_entry = oids[oid]
  except KeyError:
    return str(oid)
  else:
    descr = cfg_entry['Description']
    if includeoid:
      descr = '%s (%s)' % (descr,repr(oid))
    return descr
