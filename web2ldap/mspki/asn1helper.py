"""
asn1helper.py - some utilities to make life easier with asn1.py
(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)

This module requires at least sub-module asn1.py of package Pisces
found on http://www.cnri.reston.va.us/software/pisces/
"""

from pisces import asn1

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
