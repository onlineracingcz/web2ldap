# -*- coding: utf-8 -*-
"""
web2ldap.app.cnf: read configuration data

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

from pprint import pformat

from ldap0.ldapurl import LDAPUrl
from ldap0.dn import is_dn
from ldap0.ldapurl import isLDAPUrl

from web2ldap.log import logger


class Web2LDAPConfig(object):
    """
    Base class for a web2ldap host-/backend configuration section.
    """

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def get(self, name, default=None):
        self.__dict__.get(name, default)


# these imports must happen after declaring class Web2LDAPConfig!
import web2ldapcnf.hosts

from web2ldap.ldapsession import LDAPSession
import web2ldap.app.schema


class Web2LDAPConfigDict(object):

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
            if isLDAPUrl(key):
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
        return (key.initializeUrl().lower(), key.dn.lower())

    def set_cfg(self, cfg_uri, cfg_data):
        cfg_key = self.normalize_key(cfg_uri)
        self.cfg_data[cfg_key] = cfg_data

    def get_param(self, uri, dn, param_key, default):
        uri = uri.lower()
        dn = dn.lower()
        result = default
        for cfg_key in (
                (uri, dn),
                ('ldap://', dn),
                (uri, ''),
                '_',
            ):
            if cfg_key in self.cfg_data and hasattr(self.cfg_data[cfg_key], param_key):
                result = getattr(self.cfg_data[cfg_key], param_key)
                logger.debug(
                    'Found %r with key %r: %s',
                    param_key,
                    cfg_key,
                    pformat(result),
                )
                break
        return result

logger.debug('Initialize ldap_def')
ldap_def = Web2LDAPConfigDict(web2ldapcnf.hosts.ldap_def)
web2ldap.app.schema.parse_fake_schema(ldap_def)


def set_target_check_dict(ldap_uri_list):
    ldap_uri_list_check_dict = {}
    for ldap_uri in ldap_uri_list:
        try:
            ldap_uri, desc = ldap_uri
        except ValueError:
            pass
        lu_obj = LDAPUrl(ldap_uri)
        ldap_uri_list_check_dict[lu_obj.initializeUrl()] = None
    return ldap_uri_list_check_dict

# Set up configuration for restricting access to the preconfigured LDAP URI list
LDAP_URI_LIST_CHECK_DICT = set_target_check_dict(web2ldapcnf.hosts.ldap_uri_list)
