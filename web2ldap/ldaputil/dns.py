# -*- coding: utf-8 -*-
"""
ldaputil.dns - basic functions for dealing dc-style DNs and SRV RRs

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2020 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import socket

from ldap0.dn import DNObj

from dns import resolver

from web2ldap.log import logger


def srv_lookup(dns_name, srv_prefix: str = '_ldap._tcp'):
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
    query_name = ('%s.%s' % (srv_prefix, dns_name))
    logger.debug('Query DNS for SRV RR %r', query_name)
    srv_result = resolver.query(query_name, 'SRV')
    if not srv_result:
        return []
    srv_result_answers = [
        (
            res.priority,
            res.weight,
            res.port,
            res.target.to_text().rstrip('.'),
        )
        for res in srv_result
        #if res['typename'] == 'SRV'
    ]
    srv_result_answers.sort()
    logger.debug('DNS result for SRV RR %r: %r', query_name, srv_result_answers)
    return srv_result_answers


def dc_dn_lookup(dn):
    """
    Query DNS for _ldap._tcp SRV RR for the distinguished name in :dn:
    """
    if not dn:
        return []
    dns_domain = DNObj.from_str(dn).domain(only_dc=False)
    try:
        dns_result = srv_lookup(dns_domain)
    except (
            resolver.NoAnswer,
            resolver.NoNameservers,
            resolver.NotAbsolute,
            resolver.NoRootSOA,
            resolver.NXDOMAIN,
            socket.error,
        ) as dns_err:
        logger.warning('Error looking up SRV RR for %s: %s', dns_domain, dns_err)
        return []
    logger.debug('dns_result = %r', dns_result)
    return [
        '%s%s' % (host, (':%d' % port)*(port != 389))
        for _, _, port, host in dns_result
        if host
    ]
