# -*- coding: utf-8 -*-
"""
ldapsession.py - higher-level class for handling LDAP connections

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import sys
import socket
import time
import codecs
from collections import deque

import ldap0
import ldap0.ldif
import ldap0.sasl
import ldap0.cidict
import ldap0.filter
import ldap0.dn
from ldap0.base import decode_list, decode_entry_dict
from ldap0.dn import DNObj
from ldap0.res import SearchResultEntry
from ldap0.ldapurl import LDAPUrl
from ldap0.ldapobject import ReconnectLDAPObject
from ldap0.schema.models import DITStructureRule
from ldap0.schema.subentry import SubschemaError, SubSchema, SCHEMA_ATTRS
from ldap0.controls.simple import ValueLessRequestControl, BooleanControl
from ldap0.controls.openldap import SearchNoOpControl
from ldap0.controls.libldap import AssertionControl
from ldap0.controls.readentry import PreReadControl, PostReadControl
from ldap0.controls.ppolicy import PasswordPolicyControl
from ldap0.controls.sessiontrack import SessionTrackingControl, SESSION_TRACKING_FORMAT_OID_USERNAME

from web2ldap.log import logger
from web2ldap.ldaputil.extldapurl import ExtendedLDAPUrl

START_TLS_NO = 0
START_TLS_TRY = 1
START_TLS_REQUIRED = 2

# IBM Directory Server
CONTROL_DONOTREPLICATE = '1.3.18.0.2.10.23'
# RFC 6171: Don't use copy
CONTROL_DONTUSECOPY = '1.3.6.1.1.22'
# OpenLDAP experimental: Don't use copy
CONTROL_DONTUSECOPY_OPENLDAP = '1.3.6.1.4.1.4203.666.5.15'
# draft-ietf-ldup-subentry-07.txt
CONTROL_LDUP_SUBENTRIES = '1.3.6.1.4.1.7628.5.101.1'
# RFC 3672
CONTROL_SUBENTRIES = '1.3.6.1.4.1.4203.1.10.1'
# RFC 3296
CONTROL_MANAGEDSAIT = '2.16.840.1.113730.3.4.2'
# draft-zeilenga-ldap-relax
CONTROL_RELAXRULES = '1.3.6.1.4.1.4203.666.5.12'
# IBM Directory Server
CONTROL_SERVERADMINISTRATION = '1.3.18.0.2.10.15'
# draft-armijo-ldap-treedelete
CONTROL_TREEDELETE = '1.2.840.113556.1.4.805'

AVAILABLE_BOOLEAN_CONTROLS = {
    CONTROL_SUBENTRIES: (
        ('search',), BooleanControl, True
    ),
    CONTROL_LDUP_SUBENTRIES: (
        ('search',), ValueLessRequestControl, None
    ),
    CONTROL_MANAGEDSAIT: (
        ('**all**',), ValueLessRequestControl, None
    ),
    CONTROL_RELAXRULES: (
        ('**write**',), ValueLessRequestControl, None
    ),
    CONTROL_DONOTREPLICATE: (
        ('**write**',), ValueLessRequestControl, None
    ),
    CONTROL_DONTUSECOPY: (
        ('**read**',), ValueLessRequestControl, None
    ),
    CONTROL_DONTUSECOPY_OPENLDAP: (
        ('**read**',), ValueLessRequestControl, None
    ),
    # IBM DS
    CONTROL_SERVERADMINISTRATION: (
        ('**write**',), ValueLessRequestControl, None
    ),
    # "real attributes only" control
    '2.16.840.1.113730.3.4.17': (
        ('**read**',), ValueLessRequestControl, None
    ),
    # "virtual attributes only" control
    '2.16.840.1.113730.3.4.19': (
        ('**read**',), ValueLessRequestControl, None
    ),
    # OpenLDAP's privateDB control for slapo-pcache
    '1.3.6.1.4.1.4203.666.11.9.5.1': (
        ('**all**',), ValueLessRequestControl, None
    ),
    # Omit group referential integrity control
    '1.3.18.0.2.10.26': (
        ('delete', 'rename'), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_EXTENDED_DN_OID
    '1.2.840.113556.1.4.529': (
        ('**read**',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_SHOW_DELETED_OID
    '1.2.840.113556.1.4.417': (
        ('**all**',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_SHOW_RECYCLED_OID
    '1.2.840.113556.1.4.2064': (
        ('search',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_DOMAIN_SCOPE_OID
    '1.2.840.113556.1.4.1339': (
        ('search',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_SHOW_DEACTIVATED_LINK_OID
    '1.2.840.113556.1.4.2065': (
        ('search',), ValueLessRequestControl, None
    ),
    # Effective Rights control
    '1.3.6.1.4.1.42.2.27.9.5.2': (
        ('search',), ValueLessRequestControl, None
    ),
    # Replication Repair Control
    '1.3.6.1.4.1.26027.1.5.2': (
        ('**write**',), ValueLessRequestControl, None
    ),
    # MS AD LDAP_SERVER_LAZY_COMMIT_OID
    '1.2.840.113556.1.4.619': (
        ('**write**',), ValueLessRequestControl, None
    ),
}

# Used attributes from RootDSE
ROOTDSE_ATTRS = (
    'objectClass',
    'altServer',
    'namingContexts',
    'ogSupportedProfile',
    'subschemaSubentry',
    'supportedControl',
    'supportedExtension',
    'supportedFeatures',
    'supportedLDAPVersion',
    'supportedSASLMechanisms',
    # RFC 3112
    'supportedAuthPasswordSchemes',
    # RFC 3045
    'vendorName', 'vendorVersion',
    # 'informational' attributes of OpenDS/OpenDJ
    'ds-private-naming-contexts',
    # 'informational' attributes of OpenLDAP
    'auditContext',
    'configContext',
    'monitorContext',
    # 'informational' attributes of Active Directory
    'configurationNamingContext',
    'defaultNamingContext',
    'defaultRnrDN',
    'dnsHostName',
    'schemaNamingContext',
    'supportedCapabilities',
    'supportedLDAPPolicies',
    # 'informational' attributes of IBM Directory Server
    'ibm-configurationnamingcontext',
    # see draft-good-ldap-changelog
    'changelog',
    # AE-DIR
    'aeRoot',
)


# Attributes to be read from user's entry
USER_ENTRY_ATTRIBUTES = (
    '*',
    'uid',
    'uidNumber',
    'gidNumber',
    'cn',
    'displayName',
    'sAMAccountName',
    'userPrincipalName',
    'employeeNumber',
    'employeeID',
    'preferredLanguage',
    'objectClass',
    'pwdExpire',
    'pwdLastSet',
    'badPasswordTime',
    'badPwdCount',
    'lastLogin',
    'shadowLastChange',
    'sambaPwdLastSet',
    'memberOf',
)

WHOAMI_FILTER_TMPL = (
    'ldap:///_??sub?'
    '(|'
        '(uid={user})'
        '(uidNumber={user})'
        '(sAMAccountName={user})'
        '(userPrincipalName={user})'
    ')'
)

LDAPLimitErrors = (
    ldap0.TIMEOUT,
    ldap0.TIMELIMIT_EXCEEDED,
    ldap0.SIZELIMIT_EXCEEDED,
    ldap0.ADMINLIMIT_EXCEEDED,
)

LDAP_DEFAULT_TIMEOUT = 60

COUNT_TIMEOUT = 5.0

LDAP0_RETRY_MAX = 8
LDAP0_RETRY_DELAY = 1.5
LDAP0_CACHE_TTL = 10.0


class MyLDAPObject(ReconnectLDAPObject):

    def __init__(
            self,
            uri,
            trace_level=0,
            retry_max=LDAP0_RETRY_MAX,
            retry_delay=LDAP0_RETRY_DELAY,
            cache_ttl=LDAP0_CACHE_TTL,
        ):
        self._req_ctrls = {
            # all LDAP operations
            '**all**': [],
            # all bind operations
            '**bind**': [],
            # compare,search
            '**read**': [],
            # add,delete,modify,rename
            '**write**': [],
            'abandon': [],
            'add': [],
            'compare': [],
            'delete': [],
            'modify': [],
            'passwd': [],
            'rename': [],
            'search': [],
            'unbind': [],
            'sasl_interactive_bind_s': [],
            'simple_bind': [],
        }
        self.flush_cache()
        ReconnectLDAPObject.__init__(
            self,
            uri,
            trace_level,
            retry_max=retry_max,
            retry_delay=retry_delay,
            cache_ttl=cache_ttl,
        )
        self.last_search_bases = deque(maxlen=30)

    def get_ctrls(self, method):
        all_s_ctrls = {}
        for ctrl in self._req_ctrls[method]:
            all_s_ctrls[ctrl.controlType] = ctrl
        return all_s_ctrls

    def add_server_control(self, method, lc):
        _s_ctrls = self.get_ctrls(method)
        _s_ctrls[lc.controlType] = lc
        self._req_ctrls[method] = list(_s_ctrls.values())

    def del_server_control(self, method, control_type):
        _s_ctrls = self.get_ctrls(method)
        try:
            del _s_ctrls[control_type]
        except KeyError:
            pass
        self._req_ctrls[method] = list(_s_ctrls.values())

    def abandon(self, msgid, req_ctrls=None):
        return ReconnectLDAPObject.abandon(
            self,
            msgid,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['abandon'],
        )

    def simple_bind(self, who='', cred='', req_ctrls=None):
        assert isinstance(who, str), TypeError("Type of argument 'who' must be str but was %r" % (who,))
        assert isinstance(cred, bytes), TypeError("Type of argument 'cred' must be bytes but was %r" % (cred,))
        self.flush_cache()
        return ReconnectLDAPObject.simple_bind(
            self,
            who,
            cred,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['**bind**']+self._req_ctrls['simple_bind'],
        )

    def sasl_interactive_bind_s(
            self,
            sasl_mech,
            auth,
            req_ctrls=None,
            sasl_flags=ldap0.SASL_QUIET
        ):
        assert isinstance(sasl_mech, str), TypeError("Type of argument 'sasl_mech' must be str but was %r" % (sasl_mech,))
        self.flush_cache()
        return ReconnectLDAPObject.sasl_interactive_bind_s(
            self,
            sasl_mech,
            auth,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['**bind**']+self._req_ctrls['sasl_interactive_bind_s'],
            sasl_flags
        )

    def add(self, dn, modlist, req_ctrls=None):
        assert isinstance(dn, str), TypeError("Type of argument 'dn' must be str but was %r" % (dn,))
        return ReconnectLDAPObject.add(
            self,
            dn,
            modlist,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['**write**']+self._req_ctrls['add'],
        )

    def compare(self, dn, attr, value, req_ctrls=None):
        assert isinstance(dn, str), TypeError("Type of argument 'dn' must be str but was %r" % (dn,))
        assert isinstance(attr, str), TypeError("Type of argument 'attr' must be str but was %r" % (attr,))
        assert isinstance(value, bytes), TypeError("Type of argument 'value' must be bytes but was %r" % (value,))
        return ReconnectLDAPObject.compare(
            self,
            dn,
            attr,
            value,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['**read**']+self._req_ctrls['compare'],
        )

    def delete(self, dn, req_ctrls=None):
        assert isinstance(dn, str), TypeError("Type of argument 'dn' must be str but was %r" % (dn,))
        return ReconnectLDAPObject.delete(
            self,
            dn,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['**write**']+self._req_ctrls['delete'],
        )

    def modify(self, dn, modlist, req_ctrls=None):
        assert isinstance(dn, str), TypeError("Type of argument 'dn' must be str but was %r" % (dn,))
        return ReconnectLDAPObject.modify(
            self,
            dn,
            modlist,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['**write**']+self._req_ctrls['modify'],
        )

    def passwd(self, user, oldpw, newpw, req_ctrls=None):
        assert isinstance(user, str), TypeError("Type of argument 'user' must be str but was %r" % user)
        assert oldpw is None or isinstance(oldpw, bytes), TypeError("Type of argument 'oldpw' must be None or bytes but was %r" % oldpw)
        assert isinstance(newpw, bytes), TypeError("Type of argument 'newpw' must be bytes but was %r" % newpw)
        return ReconnectLDAPObject.passwd(
            self,
            user,
            oldpw,
            newpw,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['**write**']+self._req_ctrls['passwd'],
        )

    def rename(self, dn, newrdn, newsuperior=None, delold=1, req_ctrls=None):
        assert isinstance(dn, str), TypeError("Type of argument 'dn' must be str but was %r" % (dn,))
        assert isinstance(newrdn, str), TypeError("Type of argument 'newrdn' must be str but was %r" % newrdn)
        return ReconnectLDAPObject.rename(
            self,
            dn,
            newrdn,
            newsuperior,
            delold,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['**write**']+self._req_ctrls['rename'],
        )

    def search(
            self,
            base,
            scope,
            filterstr='(objectClass=*)',
            attrlist=None,
            attrsonly=0,
            req_ctrls=None,
            timeout=-1,
            sizelimit=0,
        ):
        assert isinstance(base, str), \
            TypeError("Type of 'base' must be str, was %r" % (base,))
        assert isinstance(filterstr, str), \
            TypeError("Type of 'filterstr' must be str, was %r" % (filterstr,))
        if base not in self.last_search_bases:
            self.last_search_bases.append(base)
        return ReconnectLDAPObject.search(
            self,
            base,
            scope,
            filterstr,
            attrlist,
            attrsonly,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['**read**']+self._req_ctrls['search'],
            timeout,
            sizelimit,
        )

    def unbind(self, req_ctrls=None):
        return ReconnectLDAPObject.unbind(
            self,
            (req_ctrls or [])+self._req_ctrls['**all**']+self._req_ctrls['unbind'],
        )


class LDAPSessionException(ldap0.LDAPError):
    """
    Base exception class raised within this module
    """
    def __str__(self):
        return self.args[0]['desc']


class PasswordPolicyException(LDAPSessionException):
    """
    Base exception class for all password policy errors
    """

    def __init__(self, who=None, desc=None):
        self.who = who
        self.desc = desc

    def __str__(self):
        return self.desc


class PasswordChangeAfterReset(PasswordPolicyException):
    """
    Exception raised in case the user must change password after reset
    """


class InvalidSimpleBindDN(ldap0.INVALID_DN_SYNTAX):
    """
    Exception raised in case the bind DN was not valid
    """

    def __init__(self, who=None, desc=None):
        self.who = who
        self.desc = desc or 'Invalid bind DN'

    def __str__(self):
        return ': '.join((self.desc, self.who))


class UsernameNotFound(LDAPSessionException):
    """
    Simple exception class raised when get_bind_dn() does not
    find any entry matching search
    """


class UsernameNotUnique(LDAPSessionException):
    """
    Simple exception class raised when get_bind_dn() does not
    find more than one entry matching search
    """


class LDAPSession:
    """
    Class for handling LDAP connection objects
    """
    __slots__ = (
        '_audit_context',
        '_cache_ttl',
        'charset',
        'connStartTime',
        'cookie',
        'l',
        'namingContexts',
        'namingContexts',
        'onBehalf',
        'rootDSE',
        'sasl_auth',
        'sasl_mech',
        '_schema_cache',
        '_schema_dn_cache',
        'secureConn',
        'sessionStartTime',
        'startTLSOption',
        'supportedControl',
        'supportedExtension',
        'supportedFeatures',
        'supportedLDAPVersion',
        'supportedSASLMechanisms',
        'supportsAllOpAttr',
        'supportsAllOpAttr',
        'supportsAllOpAttr',
        '_traceLevel',
        'uc_decode',
        'uc_encode',
        'uri',
        'userEntry',
        'vendorName',
        'vendorVersion',
        'who',
    )
    subordinate_attrs = (
        'hasSubordinates',
        'subordinateCount',
        'numSubordinates',
        'numAllSubordinates',
        'msDS-Approx-Immed-Subordinates',
    )

    def __init__(self, onBehalf, traceLevel, cache_ttl):
        """Initialize a LDAPSession object"""
        self.l = None
        # Set to not connected
        self.uri = None
        self.namingContexts = set()
        self._audit_context = ldap0.cidict.CIDict()
        self._traceLevel = traceLevel
        # Character set/encoding of data stored on this particular host
        self.charset = 'utf-8'
        self.uc_encode, self.uc_decode, _, _ = codecs.lookup(self.charset)
        # initialize class attributes derived from rootDSE attributes later
        self._reset_rootdse_attrs()
        # security attributes of the connection
        self.secureConn = 0
        self.sasl_mech = None
        self.sasl_auth = None
        self.who = None
        self.userEntry = {}
        self.startTLSOption = 0
        self._schema_dn_cache = {}
        self._schema_cache = {}
        # Supports feature described in draft-zeilenga-ldap-opattrs
        self.supportsAllOpAttr = 0
        # IP address, host name or other free form information
        # of proxy client
        self.onBehalf = onBehalf
        self.sessionStartTime = time.time()
        self.connStartTime = None
        self._cache_ttl = cache_ttl
        # end of __init__()

    @property
    def relax_rules(self):
        return CONTROL_RELAXRULES in self.l.get_ctrls('**write**')

    @property
    def manage_dsa_it(self):
        return CONTROL_MANAGEDSAIT in self.l.get_ctrls('**all**')

    def _set_tls_options(self, tls_options=None):
        tls_options = tls_options or {}
        if self.uri.lower().startswith('ldapi:') or not ldap0.TLS_AVAIL:
            # Do not set TLS options
            return
        for ldap_opt, ldap_opt_value in list(tls_options.items()) + [
                (ldap0.OPT_X_TLS_REQUIRE_CERT, ldap0.OPT_X_TLS_DEMAND),
                (ldap0.OPT_X_TLS_NEWCTX, 0),
            ]:
            if isinstance(ldap_opt_value, str):
                ldap_opt_value = ldap_opt_value.encode(self.charset)
            try:
                self.l.set_option(ldap_opt, ldap_opt_value)
            except ValueError as value_error:
                if sys.platform != 'darwin' and str(value_error) != 'ValueError: option error':
                    raise
        # end of _set_tls_options()

    def _start_tls(self, startTLSOption):
        """
        StartTLS if possible and requested
        """
        self.secureConn = 0
        self.startTLSOption = 0
        if not startTLSOption:
            return
        try:
            self.l.start_tls_s()
        except (
                ldap0.UNAVAILABLE,
                ldap0.CONNECT_ERROR,
                ldap0.PROTOCOL_ERROR,
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.SERVER_DOWN,
            ) as ldap_err:
            if startTLSOption > 1:
                self.unbind()
                raise ldap_err
        else:
            self.startTLSOption = 2
            self.secureConn = 1
        # end of _start_tls()

    def _initialize(self, uri_list, tls_options=None):
        while uri_list:
            uri = uri_list[0].strip()
            # Try connecting to LDAP host
            try:
                self.l = MyLDAPObject(
                    uri,
                    trace_level=self._traceLevel,
                    cache_ttl=self._cache_ttl,
                )
                self.uri = uri
                self._set_tls_options(tls_options)
                # Default timeout 60 seconds
                self.l.set_option(ldap0.OPT_TIMEOUT, LDAP_DEFAULT_TIMEOUT)
                self.l.set_option(ldap0.OPT_NETWORK_TIMEOUT, LDAP_DEFAULT_TIMEOUT)
                self.who = None
            except ldap0.SERVER_DOWN:
                # Remove current host from list
                self.unbind()
                uri_list.pop(0)
                if uri_list:
                    # Try next host
                    continue
                raise
            else:
                break
        # end of _initialize()

    def open(
            self,
            uri,
            timeout,
            startTLS,
            env,
            enableSessionTracking,
            tls_options=None
        ):
        """
        Open a LDAP connection with separate DNS lookup

        uri
            Either a (Unicode) string or a list of strings
            containing LDAP URLs of host(s) to connect to.
            If host is a list connecting is tried until a
            connect to a host in the list was successful.
        """
        if not uri:
            raise ValueError('Empty value for uri')
        if isinstance(uri, str):
            uri_list = [uri]
        elif isinstance(uri, (list, tuple)):
            uri_list = uri
        else:
            raise TypeError('Expected either list of str or single str for uri, got %r.' % (uri,))
        self._initialize(uri_list, tls_options)
        if enableSessionTracking:
            session_tracking_ctrl = SessionTrackingControl(
                self.onBehalf,
                env.get(
                    'HTTP_HOST',
                    ':'.join((
                        env.get('SERVER_NAME', socket.getfqdn()),
                        env['SERVER_PORT'],
                    )),
                ),
                SESSION_TRACKING_FORMAT_OID_USERNAME,
                hex(hash(self.l)),
            )
            self.l.add_server_control('**all**', session_tracking_ctrl)
        if self.uri.lower().startswith('ldap:'):
            # Start TLS extended operation
            self._start_tls(startTLS)
        elif self.uri.lower().startswith('ldaps:') or self.uri.lower().startswith('ldapi:'):
            self.secureConn = 1
        self.connStartTime = time.time()
        self.init_rootdse()
        # end of open()

    def unbind(self):
        """Close LDAP connection object if necessary"""
        try:
            self.l.unbind_s()
            del self.l
        except ldap0.LDAPError:
            pass
        except AttributeError:
            pass
        self.uri = None # delete the LDAP connection URI
        # Flush old data from cache
        self.flush_cache()
        # end of unbind()

    def _reset_rootdse_attrs(self):
        """Forget all old RootDSE values"""
        self.supportsAllOpAttr = False
        self.namingContexts = set()
        self.rootDSE = ldap0.cidict.CIDict()
        # some rootDSE attributes made available as class attributes
        self.supportedLDAPVersion = frozenset([])
        self.supportedControl = frozenset([])
        self.supportedExtension = frozenset([])
        self.supportedFeatures = frozenset([])
        self.supportedSASLMechanisms = frozenset([])
        self.supportsAllOpAttr = False

    @property
    def is_openldap(self):
        return b'OpenLDAProotDSE' in self.rootDSE.get('objectClass', [])

    def _update_rootdse_attrs(self):
        """
        Derive some class attributes from rootDSE attributes
        """
        self.namingContexts = set()
        for rootdse_naming_attrtype in (
                'namingContexts',
                'configContext',
                'monitorContext',
                'ds-private-naming-contexts',
            ):
            self.namingContexts.update([
                DNObj.from_str('' if val == b'\x00' else val.decode(self.charset))
                for val in self.rootDSE.get(rootdse_naming_attrtype, [])
            ])
        for attr_type in (
                'supportedLDAPVersion',
                'supportedControl',
                'supportedExtension',
                'supportedFeatures',
                'supportedSASLMechanisms',
            ):
            setattr(
                self,
                attr_type,
                frozenset(
                    decode_list(
                        self.rootDSE.get(attr_type, []),
                        encoding='ascii'
                    )
                )
            )
        for attr_type in ('vendorName', 'vendorVersion'):
            if attr_type in self.rootDSE:
                setattr(self, attr_type, self.rootDSE[attr_type][0].decode(self.charset))
            else:
                setattr(self, attr_type, None)
        # determine whether server returns all operational attributes (RFC 3673)
        self.supportsAllOpAttr = (
            '1.3.6.1.4.1.4203.1.5.1' in self.supportedFeatures
            or self.is_openldap
        )
        # end of _update_rootdse_attrs()

    def init_rootdse(self):
        """Retrieve attributes from Root DSE"""
        self._reset_rootdse_attrs()
        try:
            ldap_res = self.l.read_rootdse_s(attrlist=ROOTDSE_ATTRS)
        except (
                ldap0.CONFIDENTIALITY_REQUIRED,
                ldap0.CONSTRAINT_VIOLATION,
                ldap0.INAPPROPRIATE_AUTH,
                ldap0.INAPPROPRIATE_MATCHING,
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.INVALID_CREDENTIALS,
                ldap0.NO_SUCH_OBJECT,
                ldap0.OPERATIONS_ERROR,
                ldap0.PARTIAL_RESULTS,
                ldap0.STRONG_AUTH_REQUIRED,
                ldap0.UNDEFINED_TYPE,
                ldap0.UNWILLING_TO_PERFORM,
                ldap0.PROTOCOL_ERROR,
                ldap0.UNAVAILABLE_CRITICAL_EXTENSION,
            ):
            self.rootDSE = {}
        else:
            if ldap_res is None:
                self.rootDSE = {}
            else:
                self.rootDSE = ldap_res.entry_as
        self._update_rootdse_attrs()
        # end of init_rootdse()

    def get_search_root(self, dn, naming_contexts=None):
        """
        Returns the namingContexts value matching best the
        distinguished name given in dn

        naming_contexts is used if not None and LDAPSession.namingContexts is empty
        """
        if naming_contexts:
            naming_contexts = [
                DNObj.from_str(nc)
                for nc in naming_contexts or []
            ]
        else:
            naming_contexts = self.namingContexts
        if self.namingContexts is None and self.l is not None:
            self.init_rootdse()
        if not naming_contexts or naming_contexts == {DNObj(())}:
            matched_dn = ''
        else:
            matched_dn = DNObj.from_str(dn).match(naming_contexts)
        return matched_dn
        # end of get_search_root()

    def count(
            self,
            dn,
            search_scope=ldap0.SCOPE_SUBTREE,
            search_filter='(objectClass=*)',
            timeout=COUNT_TIMEOUT,
            sizelimit=0,
        ):
        if SearchNoOpControl.controlType in self.supportedControl:
            num_entries, num_referrals = self.l.noop_search(
                dn,
                search_scope,
                search_filter,
                timeout=timeout,
            )
        else:
            msg_id = self.l.search(
                dn,
                search_scope,
                search_filter,
                attrlist=['1.1'],
                timeout=timeout,
                sizelimit=sizelimit,
            )
            count_dict = {
                ldap0.RES_SEARCH_ENTRY: 0,
                ldap0.RES_SEARCH_REFERENCE: 0,
                ldap0.RES_SEARCH_RESULT: 0,
            }
            for res in self.l.results(msg_id):
                count_dict[res.rtype] += len(res.rdata)
            num_entries = count_dict[ldap0.RES_SEARCH_ENTRY]
            num_referrals = count_dict[ldap0.RES_SEARCH_REFERENCE]
        return num_entries, num_referrals

    def get_sub_ordinates(self, dn):
        """
        Returns tuple (hasSubordinates, numSubordinates, numAllSubordinates)
        """
        # List of operational attributes suitable to determine non-leafs
        # First try to read operational attributes from entry itself
        # which might indicate whether there are subordinate entries
        hasSubordinates = numSubordinates = numAllSubordinates = numSubordinates_attr = None
        sre = self.l.read_s(dn, '(objectClass=*)', self.subordinate_attrs)
        if sre:
            for a in (
                    'subordinateCount',
                    'numSubordinates',
                    'msDS-Approx-Immed-Subordinates',
                ):
                if a in sre.entry_s:
                    numSubordinates = int(sre.entry_s[a][0])
                    numSubordinates_attr = a
                    break
            try:
                numAllSubordinates = int(sre.entry_s['numAllSubordinates'][0])
            except KeyError:
                if numSubordinates_attr is not None:
                    ldap_result = self.l.search_s(
                        dn,
                        ldap0.SCOPE_SUBTREE,
                        '(objectClass=*)',
                        attrlist=[numSubordinates_attr],
                        timeout=COUNT_TIMEOUT
                    )
                    numAllSubordinates = 0
                    for sre2 in ldap_result:
                        numAllSubordinates += int(sre2.entry_s.get(numSubordinates_attr, ['0'])[0])
            try:
                hasSubordinates = (sre.entry_s['hasSubordinates'][0].upper() == 'TRUE')
            except KeyError:
                if numSubordinates is not None or numAllSubordinates is not None:
                    hasSubordinates = bool(numSubordinates or numAllSubordinates)
        if hasSubordinates is None:
            # Explicitly search for subordinate entries
            ldap_result = self.l.search_s(
                self.uc_encode(dn)[0],
                ldap0.SCOPE_ONELEVEL,
                '(objectClass=*)',
                attrlist=['1.1'],
                sizelimit=1
            )
            hasSubordinates = bool(ldap_result and ldap_result.rdata)
        if SearchNoOpControl.controlType in self.supportedControl:
            if not numSubordinates:
                try:
                    numSubordinates, _ = self.l.noop_search(
                        dn,
                        ldap0.SCOPE_ONELEVEL,
                        timeout=COUNT_TIMEOUT,
                    )
                except LDAPLimitErrors:
                    pass
            if not numAllSubordinates:
                try:
                    numAllSubordinates, _ = self.l.noop_search(
                        dn,
                        ldap0.SCOPE_SUBTREE,
                        timeout=COUNT_TIMEOUT,
                    )
                except LDAPLimitErrors:
                    pass
        return (hasSubordinates, numSubordinates, numAllSubordinates)

    def _get_sub_schema_dn(self, dn):
        """
        Determine DN of sub schema sub entry for current part of DIT
        """
        if dn in self._schema_dn_cache:
            # grab DN of sub schema sub entry from schema DN cache
            return self._schema_dn_cache[dn]
        # Search the DN of sub schema sub entry
        try:
            subschemasubentry_dn = self.l.search_subschemasubentry_s(dn)
        except ldap0.LDAPError:
            subschemasubentry_dn = None
        if subschemasubentry_dn is None:
            try:
                subschemasubentry_dn = self.l.search_subschemasubentry_s('')
            except ldap0.LDAPError:
                subschemasubentry_dn = None
        # Store DN of sub schema sub entry in schema DN cache
        self._schema_dn_cache[dn] = subschemasubentry_dn
        return subschemasubentry_dn

    def get_sub_schema(self, dn, default, supplement_schema_ldif, strict_check=True):
        """Retrieve parsed sub schema sub entry for current part of DIT"""
        assert isinstance(default, SubSchema), \
            TypeError('Expected default to be instance of SubSchema, was %r' % (default,))
        if dn is None or self.l is None:
            # not properly connected to LDAP server yet
            return default
        subschemasubentry_dn = self._get_sub_schema_dn(dn)
        if subschemasubentry_dn is None:
            # No sub schema sub entry found => return default schema
            return default
        if subschemasubentry_dn in self._schema_cache:
            # Return parsed schema from cache
            return self._schema_cache[subschemasubentry_dn]
        try:
            # Read the sub schema sub entry
            subschemasubentry = self.l.read_subschemasubentry_s(
                subschemasubentry_dn,
                SCHEMA_ATTRS,
            )
        except ldap0.LDAPError:
            return default
        if subschemasubentry is None:
            return default
        # Parse the schema
        if supplement_schema_ldif:
            try:
                with open(supplement_schema_ldif, 'rb') as ldif_fileobj:
                    _, supplement_schema = list(
                        ldap0.ldif.LDIFParser(ldif_fileobj).parse_entry_records(max_entries=1)
                    )[0]
            except (IndexError, ValueError):
                pass
            else:
                subschemasubentry.update(decode_entry_dict(supplement_schema, encoding=self.charset) or {})
        try:
            sub_schema = ldap0.schema.subentry.SubSchema(
                subschemasubentry,
                subschemasubentry_dn,
                check_uniqueness=strict_check,
            )
        except SubschemaError:
            return default
        # Store parsed schema in schema cache
        self._schema_cache[subschemasubentry_dn] = sub_schema
        # Determine what to return
        return sub_schema

    def flush_cache(self):
        """Flushes all LDAP cache data"""
        self._schema_dn_cache = {}
        self._schema_cache = {}
        self._audit_context = ldap0.cidict.CIDict()
        try:
            self.l.flush_cache()
        except AttributeError:
            pass

    def modify(self, dn, modlist, req_ctrls=None, assertion_filter=None):
        """Modify single entry"""
        if not modlist:
            return
        req_ctrls = req_ctrls or []
        dn_str = str(dn)
        if AssertionControl.controlType in self.supportedControl and assertion_filter:
            if self.is_openldap:
                # work-around for OpenLDAP ITS#6916
                assertion_filter_tmpl = '(|{filter_str}(!(entryDN={dn_str})))'
            else:
                assertion_filter_tmpl = '{filter_str}'
            assertion_filter_str = assertion_filter_tmpl.format(
                filter_str=assertion_filter,
                dn_str=ldap0.filter.escape_str(dn),
            )
            req_ctrls.append(AssertionControl(self.is_openldap, assertion_filter_str))
        self.l.modify_s(dn_str, modlist, req_ctrls=req_ctrls)
        # end of LDAPSession.modify()

    def rename(self, dn, new_rdn, new_superior=None, delold=1):
        """Rename an entry"""
        self.l.uncache(dn)
        if not new_superior is None:
            self.l.uncache(new_superior)
        old_superior_dn = DNObj.from_str(dn).parent()
        if new_superior is not None:
            if old_superior_dn == DNObj.from_str(new_superior):
                new_superior_str = None
            else:
                new_superior_str = new_superior
        rename_req_ctrls = []
        if PreReadControl.controlType in self.supportedControl:
            rename_req_ctrls.append(PreReadControl(criticality=False, attrList=['entryUUID']))
        if PostReadControl.controlType in self.supportedControl:
            rename_req_ctrls.append(PostReadControl(criticality=False, attrList=['entryUUID']))
        rename_req_ctrls = rename_req_ctrls or None
        # Send ModRDNRequest
        rename_result = self.l.rename_s(
            dn,
            new_rdn,
            new_superior_str,
            delold,
            req_ctrls=rename_req_ctrls
        )
        # Try to extract Read Entry controls from response
        prec_ctrls = dict([
            (c.controlType, c)
            for c in rename_result.ctrls or []
            if c.controlType in (PreReadControl.controlType, PostReadControl.controlType)
        ])
        if prec_ctrls:
            new_dn = prec_ctrls[PostReadControl.controlType].res.dn_s
            try:
                entry_uuid = prec_ctrls[PostReadControl.controlType].res.entry_s['entryUUID'][0]
            except KeyError:
                entry_uuid = None
        else:
            new_dn = ','.join([new_rdn, new_superior or str(old_superior_dn)])
            entry_uuid = None
        return new_dn, entry_uuid
        # end of LDAPSession.rename()

    def get_audit_context(self, search_root_dn):
        if self.l is None:
            return None
        search_root_s = str(search_root_dn)
        if search_root_s in self._audit_context:
            return self._audit_context[search_root_s]
        try:
            result = self.l.read_s(
                search_root_s,
                attrlist=['auditContext'],
            )
        except ldap0.LDAPError:
            audit_context_dn = None
        else:
            if result:
                try:
                    audit_context_dn = ldap0.cidict.CIDict(
                        result.entry_s
                    )['auditContext'][0]
                except KeyError:
                    audit_context_dn = None
            else:
                audit_context_dn = None
        self._audit_context[search_root_s] = audit_context_dn
        return audit_context_dn # get_audit_context()

    def get_bind_dn(self, username, search_root, binddn_mapping):
        """
        Map username to a full bind DN if necessary
        """
        if not username:
            # seems to be anonymous bind
            return ''
        if ldap0.dn.is_dn(username):
            # already a bind-DN -> return it normalized
            return str(DNObj.from_str(username))
        if not binddn_mapping:
            # no bind-DN mapping URL -> just return username
            return username
        logger.debug(
            'Map user name %r to bind-DN with %r / search_root = %r',
            username,
            binddn_mapping,
            search_root,
        )
        search_root = search_root or self.rootDSE.get(
            'defaultNamingContext',
            [b''],
        )[0].decode(self.charset) or ''
        lu_obj = LDAPUrl(binddn_mapping)
        search_base = lu_obj.dn.format(user=ldap0.dn.escape_str(username))
        if search_base == '_':
            search_base = str(search_root)
        elif search_base.endswith(',_'):
            search_base = ''.join((search_base[:-1], str(search_root)))
        if lu_obj.scope == ldap0.SCOPE_BASE and lu_obj.filterstr is None:
            logger.debug('Directly mapped %r to %r', username, search_base)
            return search_base
        search_filter = lu_obj.filterstr.format(user=ldap0.filter.escape_str(username))
        logger.debug(
            'Searching user entry with base = %r / scope = %d / filter = %r',
            ldap0.filter.escape_str,
            lu_obj.scope,
            search_filter,
        )
        # Try to find a unique entry with binddn_mapping
        try:
            result = self.l.search_s(
                search_base,
                lu_obj.scope,
                search_filter,
                attrlist=['1.1'],
                sizelimit=2
            )
        except ldap0.SIZELIMIT_EXCEEDED as ldap_err:
            logger.warning('Searching user entry failed: %s', ldap_err)
            raise UsernameNotUnique({'desc':'More than one matching user entries.'})
        except ldap0.NO_SUCH_OBJECT as ldap_err:
            logger.warning('Searching user entry failed: %s', ldap_err)
            raise UsernameNotFound({'desc':'Login did not find a matching user entry.'})
        # Ignore search continuations in search result list
        result = [r for r in result if isinstance(r, SearchResultEntry)]
        if not result:
            logger.warning('No result when searching user entry')
            raise UsernameNotFound({'desc':'Login did not find a matching user entry.'})
        if len(result) != 1:
            logger.warning('More than one matching user entries: %r', result)
            raise UsernameNotUnique({'desc':'More than one matching user entries.'})
        logger.debug(
            'Found user entry %r with base = %r / scope = %d / filter = %r',
            result[0].dn_b,
            search_base,
            lu_obj.scope,
            search_filter,
        )
        return result[0].dn_s

    def bind(
            self,
            who,
            cred,
            sasl_mech,
            sasl_authzid,
            sasl_realm,
            binddn_mapping,
            whoami_filtertemplate=WHOAMI_FILTER_TMPL,
            loginSearchRoot=''
        ):
        """
        Send BindRequest to LDAP server
        """
        # Flush old data from cache
        self.flush_cache()
        uri = self.uri
        try:
            # Drop the bind call sent before stored in ReconnectLDAPObject's class attribute
            self.l._last_bind = None
            # Force reconnecting in ReconnectLDAPObject
            self.l.reconnect(uri)
        except ldap0.INAPPROPRIATE_AUTH:
            pass
        # Prepare extended controls attached to bind request
        bind_server_ctrls = []
        # Authorization Identity Request and Response Controls (RFC 3829)
        #bind_server_ctrls.append(AuthorizationIdentityRequestControl(0))
        # Password Policy Control (draft-behera-ldap-password-policy)
        bind_server_ctrls.append(PasswordPolicyControl())
        if sasl_mech:
            # SASL bind
            #-------------------------------
            if sasl_mech == 'GSSAPI':
                # disable SASL hostname canonicalization
                self.l.set_option(ldap0.OPT_X_SASL_NOCANON, 1)
            sasl_auth = ldap0.sasl.SaslAuth(
                {
                    ldap0.sasl.CB_AUTHNAME: (who or '').encode(self.charset),
                    ldap0.sasl.CB_PASS: (cred or '').encode(self.charset),
                    ldap0.sasl.CB_USER: (sasl_authzid or '').encode(self.charset),
                    ldap0.sasl.CB_GETREALM: (sasl_realm or '').encode(self.charset),
                },
            )
            if ldap0.SASL_AVAIL:
                self.l.sasl_interactive_bind_s(
                    sasl_mech,
                    sasl_auth,
                    req_ctrls=bind_server_ctrls,
                )
                self.sasl_mech = sasl_mech
                self.sasl_auth = sasl_auth
                # Don't store the password
                try:
                    del self.sasl_auth.cb_value_dict[ldap0.sasl.CB_PASS]
                except KeyError:
                    pass
            else:
                raise ldap0.LDAPError('SASL not supported by local installation.')

        else:
            # Simple bind
            #-------------------------------
            self.sasl_auth = None
            if not who or not cred:
                # Anonymous bind
                who = cred = None
            else:
                # Search bind DN by "user name" for simple bind
                who = self.get_bind_dn(who, loginSearchRoot, binddn_mapping)
            # Call simple bind
            try:
                self.l.simple_bind_s(
                    who or '',
                    (cred or '').encode(self.charset),
                    req_ctrls=bind_server_ctrls,
                )
            except ldap0.INVALID_DN_SYNTAX:
                self.who = None
                raise InvalidSimpleBindDN(who)
            except ldap0.LDAPError as ldap_err:
                # Explicitly fall back to anonymous bind before re-raising exception
                self.who = None
                raise ldap_err
            else:
                self.who = who

        # Determine identity by sending LDAPv3 Who Am I? extended operation
        try:
            whoami = self.l.whoami_s()
        except ldap0.LDAPError:
            if who:
                self.who = 'u:%s' % (who)
            else:
                self.who = None
        else:
            if whoami:
                if whoami.startswith('dn:'):
                    self.who = whoami[3:]
                else:
                    self.who = whoami
            else:
                self.who = None

        # Access to root DSE might have changed after binding
        # as another entity
        self.init_rootdse()

        # Try to look up the user entry's DN in case self.who is still not a DN
        if whoami_filtertemplate and \
           (self.who is None or not ldap0.dn.is_dn(self.who)):
            if self.sasl_auth and sasl_mech.encode('ascii') in ldap0.sasl.SASL_NONINTERACTIVE_MECHS:
                # For SASL mechs EXTERNAL and GSSAPI the user did not enter a SASL username
                # => try to determine it through OpenLDAP's libldap
                # Ask libldap for SASL username for later LDAP search
                who = self.l.get_option(ldap0.OPT_X_SASL_USERNAME).decode(self.charset)

            # Search for a user entry which matches the username known so far
            try:
                self.who = self.get_bind_dn(who, loginSearchRoot, whoami_filtertemplate)
            except (ldap0.LDAPError, UsernameNotFound, UsernameNotUnique):
                pass

        # Read the user's entry if self.who is a DN to get name and preferences
        if self.who and ldap0.dn.is_dn(self.who):
            try:
                user_res = self.l.read_s(
                    self.who,
                    attrlist=USER_ENTRY_ATTRIBUTES,
                    filterstr='(objectClass=*)',
                    cache_ttl=-1.0,
                )
            except (ldap0.LDAPError, IndexError):
                self.userEntry = {}
            else:
                if user_res is None:
                    self.userEntry = {}
                else:
                    self.userEntry = user_res.entry_as
        else:
            self.userEntry = {}
        # end of bind()

    def get_governing_structure_rule(self, dn, schema):
        """
        Determine the governing structure rule for the entry specified with dn
        in the subschema specified in argument schema
        """
        governing_structure_rule = None
        try:
            search_result = self.l.read_s(
                dn,
                attrlist=(
                    'objectClass',
                    'structuralObjectClass',
                    'governingStructureRule',
                    'subschemaSubentry',
                    'administrativeRole',
                )
            )
        except ldap0.NO_SUCH_OBJECT:
            # Probably we reached root of current naming context
            return None
        if not search_result:
            return None
        entry = ldap0.schema.models.Entry(schema, dn, search_result.entry_as)
        try:
            # Try to directly read the governing structure rule ID
            # from operational attribute in entry
            governing_structure_rule = entry['governingStructureRule'][0]
        except KeyError:
            pass
        else:
            return governing_structure_rule
        possible_dit_structure_rules = {}.fromkeys((
            entry.get_possible_dit_structure_rules(dn) or []
        ))
        parent_dn = str(DNObj.from_str(dn).parent())
        administrative_roles = entry.get('administrativeRole', [])
        if 'subschemaAdminSpecificArea' in administrative_roles or not parent_dn:
            # If the current entry is a subschema administrative point all
            # DIT structure rule with a SUP clause have to be sorted out
            for dit_structure_rule_id in possible_dit_structure_rules.keys():
                dit_structure_rule_obj = schema.get_obj(DITStructureRule, dit_structure_rule_id)
                if dit_structure_rule_obj.sup:
                    del possible_dit_structure_rules[dit_structure_rule_id]
        dit_structure_rules = list(possible_dit_structure_rules.keys())
        if not dit_structure_rules:
            governing_structure_rule = None
        elif len(dit_structure_rules) == 1:
            governing_structure_rule = dit_structure_rules[0]
        else:
            # More than one possible DIT structure rule found
            if parent_dn:
                parent_governing_structure_rule = self.get_governing_structure_rule(parent_dn, schema)
                if not parent_governing_structure_rule is None:
                    subord_structural_rules, _ = schema.get_subord_structural_oc_names(
                        parent_governing_structure_rule
                    )
                    dit_structure_rules = list(
                        set(subord_structural_rules).intersection(dit_structure_rules)
                    )
                    if len(dit_structure_rules) == 1:
                        governing_structure_rule = dit_structure_rules[0]
                    else:
                        # FIX ME! This seems a bit blurry...
                        governing_structure_rule = None
        return governing_structure_rule # get_governing_structure_rule()

    def ldapUrl(self, dn, add_login=True):
        if not self.uri:
            return None
        lu = ExtendedLDAPUrl(ldapUrl=self.uri)
        lu.dn = dn
        if self.startTLSOption:
            lu.x_startTLS = str(START_TLS_REQUIRED * (self.startTLSOption > 0))
        if add_login:
            if self.sasl_auth:
                lu.saslMech = self.sasl_mech
                if self.sasl_mech in ldap0.sasl.SASL_PASSWORD_MECHS:
                    lu.who = self.sasl_auth.cb_value_dict.get(
                        ldap0.sasl.CB_AUTHNAME,
                        '',
                    ) or None
            else:
                lu.who = (self.who or '') or None
        return lu
        # end of ldapUrl()

    def __repr__(self):
        try:
            connection_str = (' LDAPv%d' % (self.l.protocol_version))
        except AttributeError:
            connection_str = ''
        return '<LDAPSession%s:%s>' % (
            connection_str,
            ','.join([
                '%s:%r' % (a, getattr(self, a))
                for a in ('uri', 'who', 'dn', 'onBehalf', 'startedTLS')
                if hasattr(self, a)
            ]),
        )
