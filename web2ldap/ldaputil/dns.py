# -*- coding: utf-8 -*-
"""
ldaputil.dns - basic functions for dealing dc-style DNs and SRV RRs

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import socket

from .base import explode_dn

from dns import rdatatype, resolver

def dcdn2dnsdomain(dn=''):
  """convert dc-style DN to DNS domain name (see RFC 2247)"""
  dn_components = explode_dn(dn.lower())
  dns_components = []
  for i in range(len(dn_components)-1,-1,-1):
    attrtype,value = dn_components[i].split('=',1)
    if attrtype!='dc':
      break
    dns_components.append(value.strip())
  dns_components.reverse()
  return '.'.join(dns_components)


def dnsdomain2dcdn(domain=''):
  """convert DNS domain name to dc-style DN (see RFC 2247)"""
  return ','.join(
    [
      'dc=%s' % d
      for d in domain.split('.')
    ]
  )


def ldapSRV(dns_name,dns_resolver=None,srv_prefix='_ldap._tcp'):
  """
  Look up SRV RR with name _ldap._tcp.dns_name and return
  list of tuples of results.

  dns_name
        Domain name
  dns_resolver
        Address/port tuple of name server to use.
  """
  if not dns_name:
    return []
  srv_result = resolver.query('%s.%s' % (srv_prefix,dns_name.encode('idna')), 'SRV')
  if not srv_result:
    return []
  srv_result_answers = [
    # priority,weight,port,hostname
    (
      res.priority,
      res.weight,
      res.port,
      res.target.to_text().rstrip('.'),
    )
    for res in srv_result
#    if res['typename']=='SRV'
  ]
  srv_result_answers.sort()
  return srv_result_answers


def dcDNSLookup(dn):
  if dn:
    try:
      dns_result = ldapSRV(dcdn2dnsdomain(dn).encode('idna'))
    except (
      resolver.NoAnswer,
      resolver.NoNameservers,
      resolver.NotAbsolute,
      resolver.NoRootSOA,
      resolver.NXDOMAIN,
      socket.error,
    ):
      return []
    else:
      return [
        '%s%s' % (host,(':%d' % port)*(port!=389))
        for _,_,port,host in dns_result
      ]
  else:
    return []
