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

import logging

from ldap0.ldapurl import LDAPUrl, is_ldapurl
from ldap0.dn import is_dn

from web2ldap.log import logger, LogHelper


VALID_CFG_PARAM_NAMES = {
    'addform_entry_templates': dict,
    'addform_parent_attrs': tuple,
    'binddn_mapping': str,
    'boundas_template': dict,
    'bulkmod_delold': bool,
    'description': str,
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
    'passwd_genchars': str,
    'passwd_genlength': int,
    'passwd_hashtypes': tuple,
    'passwd_modlist': tuple,
    'passwd_template': str,
    'print_cols': int,
    'print_template': dict,
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
    'searchform_search_root_url': str,
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


class Web2LDAPConfig(LogHelper):
    """
    Base class for a web2ldap host-/backend configuration section.
    """

    def __init__(self, **params):
        self.update(params)

    def update(self, params):
        """
        sets params as class attributes
        """
        for param_name, param_val in params.items():
#            self.log(logging.DEBUG, 'update() %r // %r', param_name, param_val)
            try:
                param_type = VALID_CFG_PARAM_NAMES[param_name]
            except KeyError:
                raise ValueError('Invalid config parameter %r.' % (param_name))
            if param_type is not None and not isinstance(param_val, param_type):
                raise TypeError(
                    'Invalid type for config parameter %r. Expected %r, got %r' % (
                        param_name,
                        param_type,
                        param_val,
                    )
                )
            setattr(self, param_name, param_val)

    def clone(self, **params):
        """
        returns a copy of the current Web2LDAPConfig
        with some more params set
        """
        old_params = dict([
            (param_name, getattr(self, param_name))
            for param_name in VALID_CFG_PARAM_NAMES
            if hasattr(self, param_name)
        ])
        new = Web2LDAPConfig(**old_params)
        new.update(params)
        self.log(
            logging.DEBUG,
            'Cloned config %s with %d parameters to %s with %d new params %s',
            id(self),
            len(old_params),
            id(new),
            len(params),
            params,
        )
        return new


# these imports must happen after declaring class Web2LDAPConfig!
import web2ldapcnf.hosts

import web2ldap.app.schema


class Web2LDAPConfigDict(LogHelper):
    """
    the configuration registry for site-specific parameters
    """

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
        naming_context = naming_context.lower()
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
web2ldap.app.schema.parse_fake_schema(LDAP_DEF)


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
