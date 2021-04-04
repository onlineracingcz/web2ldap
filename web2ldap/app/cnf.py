# -*- coding: utf-8 -*-
"""
web2ldap.app.cnf: read configuration data

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import logging

from ldap0.ldapurl import LDAPUrl, is_ldapurl
from ldap0.dn import is_dn

from ..log import logger, LogHelper
from .. import VALID_CFG_PARAM_NAMES

import web2ldapcnf.hosts

from .schema import parse_fake_schema


class Web2LDAPConfigDict(LogHelper):
    """
    the configuration registry for site-specific parameters
    """
    __slots__ = (
        'cfg_data',
    )

    def __init__(self, cfg_dict):
        self.cfg_data = {}
        for key, val in cfg_dict.items():
            self.set_cfg(key, val)

    @staticmethod
    def normalize_key(key):
        """
        Returns a normalized string for an LDAP URL
        """
        if key == '_':
            return '_'
        if isinstance(key, str):
            if is_ldapurl(key):
                key = LDAPUrl(key)
            elif is_dn(key):
                key = LDAPUrl(dn=key.lower())
        assert isinstance(key, LDAPUrl), TypeError("Expected LDAPUrl in 'key', was %r" % (key))
        key.attrs = None
        key.filterstr = None
        key.scope = None
        key.extensions = None
        try:
            host, port = key.hostport.split(':')
        except ValueError:
            pass
        else:
            if (key.urlscheme == 'ldap' and port == '389') or \
               (key.urlscheme == 'ldaps' and port == '636'):
                key.hostport = host
        return (key.connect_uri().lower(), key.dn.lower())

    def set_cfg(self, cfg_uri, cfg_data):
        """
        store config data in internal dictionary
        """
        cfg_key = self.normalize_key(cfg_uri)
        self.log(logging.DEBUG, 'Store config for %r with key %r', cfg_uri, cfg_key)
        self.cfg_data[cfg_key] = cfg_data

    def get_param(self, uri, naming_context, param, default):
        """
        retrieve a site-specific config parameter
        """
        if param not in VALID_CFG_PARAM_NAMES:
            self.log(logging.ERROR, 'Unknown config parameter %r requested', param)
            raise ValueError('Unknown config parameter %r requested' % (param))
        uri = uri.lower()
        naming_context = str(naming_context).lower()
        result = default
        for cfg_key in (
                (uri, naming_context),
                ('ldap://', naming_context),
                (uri, ''),
                '_',
            ):
            if cfg_key in self.cfg_data and hasattr(self.cfg_data[cfg_key], param):
                result = getattr(self.cfg_data[cfg_key], param)
                self.log(
                    logging.DEBUG,
                    'get_param(%r, %r, %r, %r): Key %r -> %s',
                    uri,
                    naming_context,
                    param,
                    default,
                    cfg_key,
                    result,
                )
                break
        return result

logger.debug('Initialize ldap_def')
LDAP_DEF = Web2LDAPConfigDict(web2ldapcnf.hosts.ldap_def)
parse_fake_schema(LDAP_DEF)


def set_target_check_dict(ldap_uri_list):
    """
    generate a dictionary of known target servers
    with the string of the LDAP URI used as key
    """
    ldap_uri_list_check_dict = {}
    for ldap_uri in ldap_uri_list:
        try:
            ldap_uri, desc = ldap_uri
        except ValueError:
            pass
        lu_obj = LDAPUrl(ldap_uri)
        ldap_uri_list_check_dict[lu_obj.connect_uri()] = None
        logger.debug('Added target LDAP URI %s / %r', ldap_uri, desc)
    return ldap_uri_list_check_dict

# Set up configuration for restricting access to the preconfigured LDAP URI list
LDAP_URI_LIST_CHECK_DICT = set_target_check_dict(web2ldapcnf.hosts.ldap_uri_list)
