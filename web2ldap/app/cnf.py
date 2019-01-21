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


VALID_CFG_PARAM_NAMES = {
    'addform_entry_templates': dict,
    'addform_parent_attrs': tuple,
    'binddn_mapping': unicode,
    'boundas_template': dict,
    'bulkmod_delold': bool,
    'description': unicode,
    'dit_max_levels': int,
    'dit_search_sizelimit': int,
    'dit_search_timelimit': int,
    'groupadm_defs': dict,
    'groupadm_filterstr_template': str,
    'groupadm_optgroup_bounds': tuple,
    'inputform_supentrytemplate': dict,
    'input_template': dict,
    'login_template': str,
    'modify_constant_attrs': tuple,
    'naming_contexts': tuple,
    'passwd_genchars': unicode,
    'passwd_genlength': int,
    'passwd_hashtypes': tuple,
    'passwd_modlist': tuple,
    'passwd_template': str,
    'print_cols': int,
    'print_template': dict,
    'read_operationalattrstemplate': str,
    'read_tablemaxcount': dict,
    'read_template': dict,
    'rename_supsearchurl': dict,
    'rename_template': str,
    'requested_attrs': tuple,
    '_schema': None,
    'schema_supplement': str,
    'schema_strictcheck': int,
    'schema_uri': str,
    'search_attrs': tuple,
    'searchform_search_root_url': unicode,
    'searchform_template': dict,
    'searchoptions_template': str,
    'search_resultsperpage': int,
    'search_tdtemplate': dict,
    'session_track_control': bool,
    'starttls': int,
    'supplement_schema': str,
    'timeout': int,
    'tls_options': dict,
    'top_template': str,
    'vcard_template': dict,
}


class Web2LDAPConfig(object):
    """
    Base class for a web2ldap host-/backend configuration section.
    """

    def __init__(self, **params):
        for param_name, param_val in params.items():
            try:
                param_type = VALID_CFG_PARAM_NAMES[param_name]
            except KeyError:
                raise ValueError('Invalid config paramater %r.' % (param_name))
            if param_type is not None and not isinstance(param_val, param_type):
                raise TypeError(
                    'Invalid type for config paramater %r. Expected %r, got %r' % (
                        param_name,
                        param_type,
                        param_val,
                    )
                )
            setattr(self, param_name, param_val)

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

    def get_param(self, uri, dn, param, default):
        if param not in VALID_CFG_PARAM_NAMES:
            raise ValueError('Unknown config parameter %r requested' % (param))
        uri = uri.lower()
        dn = dn.lower()
        result = default
        for cfg_key in (
                (uri, dn),
                ('ldap://', dn),
                (uri, ''),
                '_',
            ):
            if cfg_key in self.cfg_data and hasattr(self.cfg_data[cfg_key], param):
                result = getattr(self.cfg_data[cfg_key], param)
                logger.debug(
                    'get_param(%r, %r, %r, %r): Key %r ->\n%s',
                    uri,
                    dn,
                    param,
                    default,
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
