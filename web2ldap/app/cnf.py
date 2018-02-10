# -*- coding: utf-8 -*-
"""
web2ldap.app.cnf: read configuration data

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

from types import StringType

import ldap0,ldap0.ldapurl,ldap0.schema
from ldap0.cidict import cidict
from ldap0.ldapurl import LDAPUrl

import web2ldapcnf,web2ldapcnf.hosts,web2ldapcnf.misc,web2ldapcnf.standalone,web2ldapcnf.fastcgi,web2ldapcnf.countries
from web2ldapcnf import misc,hosts,standalone,fastcgi,countries
import web2ldap.ldapsession
from web2ldap.ldapsession import LDAPSession
import web2ldap.app.schema

class Web2LDAPConfigDict(cidict):

  def _normalizeKey(self,key):
    """Returns a normalized string for an LDAP URL"""
    if isinstance(key,LDAPSession):
      if key.uri is None:
        return '_'
      else:
        base_dn = key.currentSearchRoot.encode(key.charset)
        key = LDAPUrl(ldapUrl=key.uri)
        key.dn = base_dn
    elif isinstance(key,LDAPUrl):
      key = LDAPUrl(
        urlscheme=key.urlscheme.lower(),
        hostport=key.hostport,
        dn=key.dn,
        attrs=None,
        scope=None,
        filterstr=None,
        extensions=None,
        who=None,cred=None
      )
    elif type(key)==StringType:
      if key=='_':
        return '_'
      key = key.strip()
      key = LDAPUrl(key)
      key.attrs = None
      key.filterstr = None
      key.scope = None
      key.extensions = None
    else:
      raise TypeError,"Invalid type of argument 'key': %s" % (type(key))

    try:
      host,port = key.hostport.split(':')
    except ValueError:
      pass
    else:
      if (key.urlscheme=='ldap' and port=='389') or \
        (key.urlscheme=='ldaps' and port=='636'):
        key.hostport = host
    result = str(key)
    return result

  def __getitem__(self,key):
    return cidict.__getitem__(self,self._normalizeKey(key))

  def __delitem__(self,key):
    return cidict.__delitem__(self,self._normalizeKey(key))

  def __setitem__(self,key,value):
    return cidict.__setitem__(self,self._normalizeKey(key),value)

  def has_key(self,key):
    return cidict.has_key(self,self._normalizeKey(key))

  def GetParam(self,backend_key,param_key,default):
    lu_key = self._normalizeKey(backend_key or '_')
    try:
      return self[lu_key].__dict__[param_key]
    except KeyError:
      if lu_key=='_':
        return default
      else:
        try:
          return self[str(LDAPUrl(dn=LDAPUrl(lu_key).dn))].__dict__[param_key]
        except KeyError:
          try:
            return self[LDAPUrl(lu_key).initializeUrl()].__dict__[param_key]
          except KeyError:
            try:
              return self['_'].__dict__[param_key]
            except KeyError:
              return default

ldap_def = Web2LDAPConfigDict(web2ldapcnf.hosts.ldap_def)
web2ldap.app.schema.parse_fake_schema(ldap_def)


def PopulateCheckDict(ldap_uri_list):
  ldap_uri_list_check_dict = {}
  for ldap_uri in ldap_uri_list:
    try:
      ldap_uri,desc = ldap_uri
    except ValueError:
      pass
    lu = ldap0.ldapurl.LDAPUrl(ldap_uri)
    ldap_uri_list_check_dict[lu.initializeUrl()] = None
  return ldap_uri_list_check_dict # PopulateCheckDict()


def GetParam(ls,k,default):
  """
  Get a parameter determined by string-key k
  depending on current ls
  """
  return ldap_def.GetParam(ls,k,default)
