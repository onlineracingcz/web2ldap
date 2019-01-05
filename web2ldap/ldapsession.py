# -*- coding: utf-8 -*-
"""
ldapsession.py - higher-level class for handling LDAP connections

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import sys
import socket
import time
import types
import codecs

import ldap0
import ldap0.ldif
import ldap0.sasl
import ldap0.cidict
import ldap0.filter
import ldap0.schema
from ldap0.ldapobject import ReconnectLDAPObject
from ldap0.schema.models import DITStructureRule
from ldap0.schema.subentry import SubschemaError
from ldap0.controls.openldap import SearchNoOpControl
from ldap0.controls.libldap import AssertionControl
from ldap0.controls.readentry import PreReadControl, PostReadControl
from ldap0.controls import AuthorizationIdentityRequestControl, AuthorizationIdentityResponseControl
from ldap0.controls.ppolicy import PasswordPolicyControl
from ldap0.controls.sessiontrack import SessionTrackingControl, SESSION_TRACKING_FORMAT_OID_USERNAME

import web2ldap.ldaputil.base
from web2ldap.ldaputil.base import escape_ldap_filter_chars
from web2ldap.ldaputil.extldapurl import ExtendedLDAPUrl

START_TLS_NO = 0
START_TLS_TRY = 1
START_TLS_REQUIRED = 2

CONTROL_DONOTREPLICATE = '1.3.18.0.2.10.23' # IBM Directory Server
CONTROL_DONTUSECOPY = '1.3.6.1.1.22' # RFC 6171
CONTROL_DONTUSECOPY_OPENLDAP = '1.3.6.1.4.1.4203.666.5.15' # OpenLDAP experimental
CONTROL_LDUP_SUBENTRIES = '1.3.6.1.4.1.7628.5.101.1' # draft-ietf-ldup-subentry-07.txt
CONTROL_SUBENTRIES = '1.3.6.1.4.1.4203.1.10.1' # RFC 3672
CONTROL_MANAGEDSAIT = '2.16.840.1.113730.3.4.2' # RFC 3296
CONTROL_RELAXRULES = '1.3.6.1.4.1.4203.666.5.12' # draft-zeilenga-ldap-relax
CONTROL_SERVERADMINISTRATION = '1.3.18.0.2.10.15' # IBM Directory Server
CONTROL_TREEDELETE = '1.2.840.113556.1.4.805' # draft-armijo-ldap-treedelete

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
    'supportedAuthPasswordSchemes', # RFC 3112
    'vendorName',
    'vendorVersion',
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


READ_CACHE_EXPIRE = 120

LDAPLimitErrors = (
    ldap0.TIMEOUT,
    ldap0.TIMELIMIT_EXCEEDED,
    ldap0.SIZELIMIT_EXCEEDED,
    ldap0.ADMINLIMIT_EXCEEDED,
)

COUNT_TIMEOUT = 5.0

PYLDAP_RETRY_MAX = 8
PYLDAP_RETRY_DELAY = 1.5


class MyLDAPObject(ReconnectLDAPObject):

    def __init__(
            self,
            uri,
            trace_level=0,
            retry_max=PYLDAP_RETRY_MAX,
            retry_delay=PYLDAP_RETRY_DELAY,
            cache_ttl=5.0,
        ):
        self._serverctrls = {
            '**all**':[],      # all LDAP operations
            '**bind**':[],     # all bind operations
            '**read**':[],     # compare,search
            '**write**':[],    # add,delete,modify,rename
            'abandon':[],
            'add':[],
            'compare':[],
            'delete':[],
            'modify':[],
            'passwd':[],
            'rename':[],
            'search':[],
            'unbind':[],
            'sasl_interactive_bind_s':[],
            'simple_bind':[],
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

    def _get_server_ctrls(self, method):
        all_s_ctrls = {}
        for c in self._serverctrls[method]:
            all_s_ctrls[c.controlType] = c
        return all_s_ctrls

    def add_server_control(self, method, lc):
        _s_ctrls = self._get_server_ctrls(method)
        _s_ctrls[lc.controlType] = lc
        self._serverctrls[method] = _s_ctrls.values()

    def del_server_control(self, method, control_type):
        _s_ctrls = self._get_server_ctrls(method)
        try:
            del _s_ctrls[control_type]
        except KeyError:
            pass
        self._serverctrls[method] = _s_ctrls.values()

    def abandon(self, msgid, serverctrls=None):
        return ReconnectLDAPObject.abandon(
            self,
            msgid,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['abandon'],
        )

    def simple_bind(self, who='', cred='', serverctrls=None):
        assert isinstance(who, bytes), TypeError("Type of argument 'who' must be str but was %r" % (who))
        assert isinstance(cred, bytes), TypeError("Type of argument 'cred' must be str but was %r" % (cred))
        self.flush_cache()
        return ReconnectLDAPObject.simple_bind(
            self,
            who,
            cred,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['**bind**']+self._serverctrls['simple_bind'],
        )

    def sasl_interactive_bind_s(self, who, auth, serverctrls=None, sasl_flags=ldap0.SASL_QUIET):
        assert isinstance(who, bytes), TypeError("Type of argument 'who' must be str but was %r" % (who))
        self.flush_cache()
        return ReconnectLDAPObject.sasl_interactive_bind_s(
            self,
            who,
            auth,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['**bind**']+self._serverctrls['sasl_interactive_bind_s'],
            sasl_flags
        )

    def add(self, dn, modlist, serverctrls=None):
        assert isinstance(dn, bytes), TypeError("Type of argument 'dn' must be str but was %r" % dn)
        return ReconnectLDAPObject.add(
            self,
            dn,
            modlist,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['**write**']+self._serverctrls['add'],
        )

    def compare(self, dn, attr, value, serverctrls=None):
        assert isinstance(dn, bytes), TypeError("Type of argument 'dn' must be str but was %r" % dn)
        assert isinstance(attr, bytes), TypeError("Type of argument 'attr' must be str but was %r" % attr)
        assert isinstance(value, bytes), TypeError("Type of argument 'value' must be str but was %r" % value)
        return ReconnectLDAPObject.compare(
            self,
            dn,
            attr,
            value,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['**read**']+self._serverctrls['compare'],
        )

    def delete(self, dn, serverctrls=None):
        assert isinstance(dn, bytes), TypeError("Type of argument 'dn' must be str but was %r" % dn)
        return ReconnectLDAPObject.delete(
            self,
            dn,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['**write**']+self._serverctrls['delete'],
        )

    def modify(self, dn, modlist, serverctrls=None):
        assert isinstance(dn, bytes), TypeError("Type of argument 'dn' must be str but was %r" % dn)
        return ReconnectLDAPObject.modify(
            self,
            dn,
            modlist,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['**write**']+self._serverctrls['modify'],
        )

    def passwd(self, user, oldpw, newpw, serverctrls=None):
        assert isinstance(user, bytes), TypeError("Type of argument 'user' must be str but was %r" % user)
        assert oldpw is None or isinstance(oldpw, bytes), TypeError("Type of argument 'oldpw' must be None or str but was %r" % oldpw)
        assert isinstance(newpw, bytes), TypeError("Type of argument 'newpw' must be str but was %r" % newpw)
        return ReconnectLDAPObject.passwd(
            self,
            user,
            oldpw,
            newpw,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['**write**']+self._serverctrls['passwd'],
        )

    def rename(self, dn, newrdn, newsuperior=None, delold=1, serverctrls=None):
        assert isinstance(dn, bytes), TypeError("Type of argument 'dn' must be str but was %r" % dn)
        assert isinstance(newrdn, bytes), TypeError("Type of argument 'newrdn' must be str but was %r" % newrdn)
        return ReconnectLDAPObject.rename(
            self,
            dn,
            newrdn,
            newsuperior,
            delold,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['**write**']+self._serverctrls['rename'],
        )

    def search(
            self,
            base,
            scope,
            filterstr='(objectClass=*)',
            attrlist=None,
            attrsonly=0,
            serverctrls=None,
            timeout=-1,
            sizelimit=0,
        ):
        assert isinstance(base, bytes), TypeError("Type of argument 'base' must be str but was %r" % base)
        assert isinstance(filterstr, bytes), TypeError("Type of argument 'filterstr' must be str but was %r" % (filterstr))
        return ReconnectLDAPObject.search(
            self,
            base,
            scope,
            filterstr,
            attrlist,
            attrsonly,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['**read**']+self._serverctrls['search'],
            timeout,
            sizelimit,
        )

    def unbind(self, serverctrls=None):
        return ReconnectLDAPObject.unbind(
            self,
            (serverctrls or [])+self._serverctrls['**all**']+self._serverctrls['unbind'],
        )


class LDAPSessionException(ldap0.LDAPError):
    """
    Base exception class raised within this module
    """
    def __str__(self):
        return self.args[0]['desc']


class PasswordPolicyException(LDAPSessionException):

    def __init__(self, who=None, desc=None):
        self.who = who
        self.desc = desc

    def __str__(self):
        return self.desc


class PWD_CHANGE_AFTER_RESET(PasswordPolicyException):
    pass


class INVALID_SIMPLE_BIND_DN(ldap0.INVALID_DN_SYNTAX):

    def __init__(self, who=None, desc=None):
        self.who = who
        self.desc = desc or 'Invalid bind DN'

    def __str__(self):
        return ': '.join((self.desc, self.who))


class PWD_EXPIRATION_WARNING(PasswordPolicyException):

    def __init__(self, who=None, desc=None, timeBeforeExpiration=None):
        PasswordPolicyException.__init__(self, who, desc)
        self.timeBeforeExpiration = timeBeforeExpiration


class PWD_EXPIRED(PasswordPolicyException):

    def __init__(self, who=None, desc=None, graceAuthNsRemaining=None):
        PasswordPolicyException.__init__(self, who, desc)
        self.graceAuthNsRemaining = graceAuthNsRemaining


class USERNAME_NOT_FOUND(LDAPSessionException):
    """
    Simple exception class raised when getBindDN() does not
    find any entry matching search
    """


class USERNAME_NOT_UNIQUE(LDAPSessionException):
    """
    Simple exception class raised when getBindDN() does not
    find more than one entry matching search
    """


class LDAPSession:
    """
    Class for handling LDAP connection objects
    """

    def __init__(self, onBehalf, traceLevel, cache_ttl):
        """Initialize a LDAPSession object"""
        # Set to not connected
        self.uri = None
        self.namingContexts = None
        self._auditContextCache = ldap0.cidict.cidict()
        self._traceLevel = traceLevel
        # Character set/encoding of data stored on this particular host
        self.charset = 'utf-8'
        conn_codec = codecs.lookup(self.charset)
        self.uc_encode, self.uc_decode = conn_codec[0], conn_codec[1]
        # This is a dictionary for storing arbitrary objects
        # tied to a LDAP session
        self.rootDSE = ldap0.cidict.cidict()
        self.secureConn = 0
        self.saslAuth = None
        self.startTLSOption = 0
        self.schema_dn_cache = {}
        self.schema_cache = {}
        # Default timeout 60 seconds
        self.timeout = 60
        # Supports feature described in draft-zeilenga-ldap-opattrs
        self.supportsAllOpAttr = 0
        # IP adress, host name or other free form information
        # of proxy client
        self.onBehalf = onBehalf
        self.sessionStartTime = time.time()
        self.connStartTime = None
        self.setDN(u'')
        self._cache_ttl = cache_ttl
        return # __init__()

    def setTLSOptions(self, tls_options=None):
        tls_options = tls_options or {}
        if not self.uri.lower().startswith('ldapi:') and ldap0.TLS_AVAIL:
            # Only set the options if ldap0 was built with TLS support
            for ldap_opt, ldap_opt_value in tls_options.items() + [
                    (ldap0.OPT_X_TLS_REQUIRE_CERT, ldap0.OPT_X_TLS_DEMAND),
                    (ldap0.OPT_X_TLS_NEWCTX, 0),
                ]:
                try:
                    self.l.set_option(ldap_opt, ldap_opt_value)
                except ValueError as value_error:
                    if sys.platform != 'darwin' and \
                       str(value_error) != 'ValueError: option error':
                        raise
        return # setTLSOptions()

    def startTLSExtOp(self, startTLSOption):
        """StartTLS if possible and requested"""
        self.secureConn = 0
        self.startTLSOption = 0
        if startTLSOption:
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
        return # startTLSExtOp()

    def _initialize(self, uri_list, tls_options=None):
        while uri_list:
            uri = uri_list[0].strip().encode('ascii')
            # Try connecting to LDAP host
            try:
                self.l = MyLDAPObject(
                    uri,
                    trace_level=self._traceLevel,
                    cache_ttl=self._cache_ttl,
                )
                self.uri = uri
                self.setTLSOptions(tls_options)
                self.l.set_option(ldap0.OPT_NETWORK_TIMEOUT, self.timeout)
                self.who = None
            except ldap0.SERVER_DOWN:
                # Remove current host from list
                self.unbind()
                uri_list.pop(0)
                if uri_list:
                    # Try next host
                    continue
                else:
                    raise
            else:
                break
        return # end of _initialize()

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
        elif isinstance(uri, bytes) or isinstance(uri, unicode):
            uri_list = [uri]
        elif type(uri) == types.ListType:
            uri_list = uri
        else:
            raise TypeError("Parameter uri must be either list of strings or single string.")
        self.timeout = timeout
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
            self.startTLSExtOp(startTLS)
        elif self.uri.lower().startswith('ldaps:') or self.uri.lower().startswith('ldapi:'):
            self.secureConn = 1
        self.connStartTime = time.time()
        return # open()

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
        self.flushCache()
        return # unbind()

    def _forgetRootDSEAttrs(self):
        """Forget all old RootDSE values"""
        self.rootDSE = ldap0.cidict.cidict()
        self.supportsAllOpAttr = 0
        self.namingContexts = None

    def _setRootDSEAttrs(self):
        """Derive some class attributes from rootDSE attributes"""
        self.namingContexts = set([])
        self.namingContexts.update([
            unicode({'\x00':''}.get(v, v), self.charset)
            for v in self.rootDSE.get('namingContexts', [])
        ])
        for rootdse_naming_attrtype in (
                'configContext',
                'monitorContext',
                'ds-private-naming-contexts',
            ):
            self.namingContexts.update([
                unicode(v, self.charset)
                for v in self.rootDSE.get(rootdse_naming_attrtype, [])
            ])
        for attr_type in (
                'supportedLDAPVersion',
                'supportedControl',
                'supportedExtension',
                'supportedFeatures',
                'supportedSASLMechanisms',
            ):
            setattr(self, attr_type, frozenset(self.rootDSE.get(attr_type, [])))
        for attr_type in ('vendorName', 'vendorVersion'):
            setattr(self, attr_type, self.rootDSE.get(attr_type, [None])[0])
        self.supportsAllOpAttr = \
            ('1.3.6.1.4.1.4203.1.5.1' in self.supportedFeatures) or \
            ('OpenLDAProotDSE' in self.rootDSE.get('objectClass', []))
        # Speed up sub schema sub entry retrieval by pre-filling cache
        # with what is likely the sub schema for whole DIT
        try:
            schema_dn = self.rootDSE['subschemaSubEntry'][0]
        except KeyError:
            self.schema_dn_cache[u''] = None
        else:
            self.schema_dn_cache[u''] = unicode(schema_dn, self.charset)
        return # _setRootDSEAttrs()

    def getRootDSE(self):
        """Retrieve attributes from Root DSE"""
        self._forgetRootDSEAttrs()
        self.rootDSE = ldap0.cidict.cidict()
        try:
            ldap_result = self.readEntry('', ROOTDSE_ATTRS)
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
            pass
        else:
            # Copy special rootDSE attributes to object attributes
            for attr_type, attr_values in (ldap_result or [('', {})])[0][1].items():
                self.rootDSE[attr_type] = attr_values
        self._setRootDSEAttrs()
        return # getRootDSE()

    def getSearchRoot(self, dn, naming_contexts=None):
        """
        Returns the namingContexts value matching best the
        distinguished name given in dn

        naming_contexts is used if not None and LDAPSession.namingContexts is empty
        """
        if self.namingContexts is None and hasattr(self, 'l'):
            self.getRootDSE()
        return web2ldap.ldaputil.base.match_dnlist(
            dn,
            self.namingContexts or naming_contexts or [],
        )

    def isLeafEntry(self, dn):
        """Returns 1 if the node is a leaf entry, 0 otherwise"""
        return not self.subOrdinates(dn)[0]

    def count(
            self,
            dn,
            search_scope=ldap0.SCOPE_SUBTREE,
            search_filter=u'(objectClass=*)',
            timeout=COUNT_TIMEOUT,
            sizelimit=0,
        ):
        if SearchNoOpControl.controlType in self.rootDSE.get('supportedControl', []):
            num_entries, num_referrals = self.l.noop_search(
                self.uc_encode(dn)[0],
                search_scope,
                self.uc_encode(search_filter)[0],
                timeout=timeout,
            )
        else:
            msg_id = self.l.search(
                self.uc_encode(dn)[0],
                search_scope,
                self.uc_encode(search_filter)[0],
                attrlist=['1.1'],
                timeout=timeout,
                sizelimit=sizelimit,
            )
            count_dict = {
                ldap0.RES_SEARCH_ENTRY:0,
                ldap0.RES_SEARCH_REFERENCE:0,
            }
            for res_type, res_data, _, _ in self.l.results(msg_id):
                count_dict[res_type] += len(res_data)
            num_entries = count_dict[ldap0.RES_SEARCH_ENTRY]
            num_referrals = count_dict[ldap0.RES_SEARCH_REFERENCE]
        return num_entries, num_referrals

    def subOrdinates(self, dn):
        """Returns tuple (hasSubordinates,numSubordinates,numAllSubordinates)"""
        # List of operational attributes suitable to determine non-leafs
        subordinate_attrs = (
            'hasSubordinates',
            'subordinateCount',
            'numSubordinates',
            'numAllSubordinates',
            'msDS-Approx-Immed-Subordinates',
        )
        # First try to read operational attributes from entry itself
        # which might indicate whether there are subordinate entries
        entry = self.l.read_s(
            self.uc_encode(dn)[0],
            '(objectClass=*)',
            subordinate_attrs,
            timeout=self.timeout
        )
        hasSubordinates = numSubordinates = numAllSubordinates = numSubordinates_attr = None
        if entry:
            for a in (
                    'subordinateCount',
                    'numSubordinates',
                    'msDS-Approx-Immed-Subordinates',
                ):
                try:
                    numSubordinates = int(entry[a][0])
                except KeyError:
                    pass
                else:
                    numSubordinates_attr = a
                    break
            try:
                numAllSubordinates = int(entry['numAllSubordinates'][0])
            except KeyError:
                if numSubordinates is not None:
                    ldap_result = self.l.search_s(
                        self.uc_encode(dn)[0],
                        ldap0.SCOPE_SUBTREE,
                        '(objectClass=*)',
                        attrlist=[numSubordinates_attr],
                        timeout=COUNT_TIMEOUT
                    )
                    numAllSubordinates = 0
                    for _, ldap_entry in ldap_result:
                        numAllSubordinates += int(ldap_entry[numSubordinates_attr][0])
            try:
                hasSubordinates = (entry['hasSubordinates'][0].upper() == 'TRUE')
            except KeyError:
                if numSubordinates is not None or numAllSubordinates is not None:
                    hasSubordinates = (numSubordinates or numAllSubordinates or 0) > 0
                else:
                    hasSubordinates = None
        if hasSubordinates is None:
            # Explicitly search for subordinate entries
            ldap_msgid = self.l.search(
                self.uc_encode(dn)[0],
                ldap0.SCOPE_ONELEVEL,
                '(objectClass=*)',
                ['1.1'],
                timeout=self.timeout,
                sizelimit=1
            )

            ldap_result = (None, None)
            while ldap_result == (None, None):
                ldap_result = self.l.result(ldap_msgid, 0, self.timeout)
            self.l.abandon(ldap_msgid)
            hasSubordinates = len(ldap_result) > 0
        if SearchNoOpControl.controlType in self.rootDSE.get('supportedControl', []):
            if not numSubordinates:
                try:
                    numSubordinates, _ = self.l.noop_search(
                        self.uc_encode(dn)[0],
                        ldap0.SCOPE_ONELEVEL,
                        timeout=COUNT_TIMEOUT,
                    )
                except LDAPLimitErrors:
                    pass
            if not numAllSubordinates:
                try:
                    numAllSubordinates, _ = self.l.noop_search(
                        self.uc_encode(dn)[0],
                        ldap0.SCOPE_SUBTREE,
                        timeout=COUNT_TIMEOUT,
                    )
                except LDAPLimitErrors:
                    pass
        return (hasSubordinates, numSubordinates, numAllSubordinates)

    def getObjectClasses(self, dn):
        """
        Returns a 2-tuple with the list of object classes associated with an entry
        and the structural object class
        """
        try:
            search_result = self.readEntry(
                dn,
                ['objectClass', 'structuralObjectClass']
            )
        except ldap0.NO_SUCH_ATTRIBUTE:
            search_result = self.readEntry(dn, ['objectClass'])
        except (
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.UNWILLING_TO_PERFORM,
            ):
            return [], None
        if not search_result:
            raise ldap0.NO_SUCH_OBJECT
        entry = ldap0.cidict.cidict(search_result[0][1])
        objectClass = entry.get('objectClass', [])
        structuralObjectClass_values = entry.get('structuralObjectClass', [None])
        # Attribute structuralObjectClass is supposed to be SINGLE-VALUE
        # but some broken LDAPv3 server implementations return all the sup classes
        if len(structuralObjectClass_values) == 1:
            structuralObjectClass = structuralObjectClass_values[0]
        else:
            structuralObjectClass = None
        return objectClass, structuralObjectClass # getObjectClasses()

    def retrieveSubSchema(self, dn, default, supplement_schema_ldif, strict_check=True):
        """Retrieve parsed sub schema sub entry for current part of DIT"""
        if dn is None:
            return default
        subschemasubentry_dn = self.l.search_subschemasubentry_s(self.uc_encode(dn)[0])
        if subschemasubentry_dn is None:
            # No sub schema sub entry found => return default schema
            return default
        elif subschemasubentry_dn in self.schema_cache:
            # Return parsed schema from cache
            return self.schema_cache[subschemasubentry_dn]
        # Read the sub schema sub entry
        try:
            subschemasubentry = self.l.read_subschemasubentry_s(
                self.uc_encode(subschemasubentry_dn)[0],
                ldap0.schema.SCHEMA_ATTRS
            )
        except ldap0.LDAPError:
            sub_schema = None
        else:
            if subschemasubentry is None:
                sub_schema = None
            else:
                # Parse the schema
                if supplement_schema_ldif:
                    try:
                        with open(supplement_schema_ldif, 'rb') as ldif_fileobj:
                            _, supplement_schema = list(
                                ldap0.ldif.LDIFParser(ldif_fileobj).parse_entry_records(
                                    max_entries=1
                                )
                            )[0]
                    except (IndexError, ValueError):
                        pass
                    else:
                        subschemasubentry.update(supplement_schema or {})
                try:
                    sub_schema = ldap0.schema.subentry.SubSchema(
                        subschemasubentry,
                        self.uc_encode(subschemasubentry_dn)[0],
                        check_uniqueness=strict_check,
                    )
                except SubschemaError:
                    sub_schema = None
        # Store parsed schema in schema cache
        self.schema_cache[subschemasubentry_dn] = sub_schema
        # Determine what to return
        return sub_schema or default

    def readEntry(
            self,
            dn,
            attrtype_list=None,
            only_attrtypes=0,
            search_filter='(objectClass=*)',
            no_cache=False,
            server_ctrls=None,
        ):
        """Read a single entry"""
        if attrtype_list == ['*']:
            attrtype_list = None
        # Read single entry from LDAP server
        search_result = self.l.search_s(
            self.uc_encode(dn)[0],
            ldap0.SCOPE_BASE,
            self.uc_encode(search_filter)[0],
            attrlist=attrtype_list,
            attrsonly=only_attrtypes,
            timeout=self.timeout,
            cache_ttl={True:0, False:None}[no_cache],
            serverctrls=server_ctrls,
        )
        return search_result

    def existingEntry(self, dn, suppress_referrals=0):
        """Returns 1 if entry exists, 0 if NO_SUCH_OBJECT was raised."""
        try:
            self.readEntry(dn, [])
        except ldap0.INSUFFICIENT_ACCESS:
            return True
        except ldap0.NO_SUCH_OBJECT:
            return False
        except ldap0.PARTIAL_RESULTS:
            if suppress_referrals:
                return False
            else:
                raise
        else:
            return True

    def flushCache(self):
        """Flushes all LDAP cache data"""
        self.schema_dn_cache = {}
        self.schema_cache = {}
        try:
            self.l.flush_cache()
        except AttributeError:
            pass

    def modifyEntry(self, dn, modlist, serverctrls=None, assertion_filter=None):
        """Modify single entry"""
        if not modlist:
            return
        serverctrls = serverctrls or []
        dn_str = dn.encode(self.charset)
        if AssertionControl.controlType in self.supportedControl and assertion_filter:
            if 'OpenLDAProotDSE' in self.rootDSE.get('objectClass', []):
                # work-around for OpenLDAP ITS#6916
                assertion_filter_tmpl = u'(|{filter_str}(!(entryDN={dn_str})))'
            else:
                assertion_filter_tmpl = u'{filter_str}'
            assertion_filter_str = assertion_filter_tmpl.format(
                filter_str=assertion_filter,
                dn_str=ldap0.filter.escape_filter_chars(dn),
            ).encode(self.charset)
            serverctrls.append(AssertionControl(False, assertion_filter_str))
        self.l.modify_s(dn_str, modlist, serverctrls=serverctrls)
        return # modifyEntry()

    def copyEntry(self, dn, new_rdn, new_superior):
        """Copy an entry"""
        new_dn = u','.join((new_rdn, new_superior))
        r = self.readEntry(dn)
        if r:
            _, entry = r[0]
            mod_list = ldap0.modlist.add_modlist(entry)
            self.l.add_s(
                self.uc_encode(new_dn)[0],
                mod_list,
                serverctrls=None
            )
        else:
            raise ldap0.NO_SUCH_OBJECT
        entry_uuid = None
        return new_dn, entry_uuid # renameEntry()

    def renameEntry(self, dn, new_rdn, new_superior=None, delold=1):
        """Rename an entry"""
        self.l.uncache(dn.encode(self.charset))
        if not new_superior is None:
            self.l.uncache(new_superior.encode(self.charset))
        old_superior_str = web2ldap.ldaputil.base.parent_dn(web2ldap.ldaputil.base.normalize_dn(dn))
        if new_superior is not None:
            if old_superior_str == web2ldap.ldaputil.base.normalize_dn(new_superior):
                new_superior_str = None
            else:
                new_superior_str = self.uc_encode(new_superior)[0]
        rename_serverctrls = []
        if PreReadControl.controlType in self.supportedControl:
            rename_serverctrls.append(PreReadControl(criticality=False, attrList=['entryUUID']))
        if PostReadControl.controlType in self.supportedControl:
            rename_serverctrls.append(PostReadControl(criticality=False, attrList=['entryUUID']))
        rename_serverctrls = rename_serverctrls or None
        # Send ModRDNRequest
        _, _, _, rename_resp_ctrls = self.l.rename_s(
            self.uc_encode(dn)[0],
            self.uc_encode(new_rdn)[0],
            new_superior_str,
            delold,
            serverctrls=rename_serverctrls
        )
        # Try to extract Read Entry controls from response
        prec_ctrls = dict([
            (c.controlType, c)
            for c in rename_resp_ctrls or []
            if c.controlType in (PreReadControl.controlType, PostReadControl.controlType)
        ])
        if prec_ctrls:
            new_dn = self.uc_decode(prec_ctrls[PostReadControl.controlType].dn)[0]
            try:
                entry_uuid = self.uc_decode(prec_ctrls[PreReadControl.controlType].entry['entryUUID'][0])[0]
            except (IndexError, KeyError):
                entry_uuid = None
        else:
            new_dn = u','.join([new_rdn, new_superior or old_superior_str])
            entry_uuid = None
        return new_dn, entry_uuid # renameEntry()

    def deleteEntry(self, dn, serverctrls=None):
        """Delete single entry"""
        self.l.delete_s(self.uc_encode(dn)[0], serverctrls=serverctrls)
        return # deleteEntry()

    def setDN(self, dn):
        """
        Set currently used DN.
        """
        if isinstance(dn, bytes):
            dn = dn.decode(self.charset)
        dn = web2ldap.ldaputil.base.normalize_dn(dn)
        self._dn = dn
        self.currentSearchRoot = self.getSearchRoot(dn)
        return # setDN()

    def getAuditContext(self, search_root_dn):
        try:
            audit_context_dn = self._auditContextCache[search_root_dn]
        except KeyError:
            try:
                result = self.readEntry(search_root_dn, ['auditContext'])
            except AttributeError:
                audit_context_dn = None
            except ldap0.LDAPError:
                audit_context_dn = None
            else:
                if result:
                    try:
                        audit_context_dn = ldap0.cidict.cidict(
                            result[0][1]
                        )['auditContext'][0].decode(self.charset)
                    except KeyError:
                        audit_context_dn = None
                else:
                    audit_context_dn = None
            self._auditContextCache[search_root_dn] = audit_context_dn
        return audit_context_dn # getAuditContext()

    def getBindDN(
            self,
            username,       # User name or complete bind DN (Unicode)
            searchroot,     # search root for user entry search
            filtertemplate, # template string for LDAP filter
        ):
        """
        Search for a bind DN.

        If username is a valid DN it's used as bind-DN without further action.
        Otherwise filtertemplate is used to construct a LDAP search filter
        containing username instead of %s.
        """
        if not username:
            return u''
        elif web2ldap.ldaputil.base.is_dn(username):
            return web2ldap.ldaputil.base.normalize_dn(username)
        searchroot = searchroot or self.rootDSE.get(
            'defaultNamingContext',
            [''],
        )[0].decode(self.charset) or u''
        username_filter_escaped = escape_ldap_filter_chars(username)
        searchfilter = filtertemplate.replace(u'%s', username_filter_escaped)
        # Try to find a unique entry with filtertemplate
        try:
            result = self.l.search_s(
                self.uc_encode(searchroot)[0],
                ldap0.SCOPE_SUBTREE,
                self.uc_encode(searchfilter)[0],
                attrlist=['1.1'],
                timeout=self.timeout,
                sizelimit=2
            )
        except ldap0.NO_SUCH_OBJECT:
            raise USERNAME_NOT_FOUND({'desc':'Smart login did not find a matching user entry.'})
        else:
            # Ignore search continuations in search result list
            result = [r for r in result if r[0] is not None]
            if not result:
                raise USERNAME_NOT_FOUND({'desc':'Smart login did not find a matching user entry.'})
            elif len(result) != 1:
                raise USERNAME_NOT_UNIQUE({'desc':'More than one matching user entries.'})
            else:
                return web2ldap.ldaputil.base.normalize_dn(unicode(result[0][0], self.charset))

    def whoami(self):
        wai = self.l.whoami_s()
        if wai is not None:
            wai = wai.decode(self.charset)
        return wai

    def bind(
            self,
            who,
            cred,
            sasl_mech,
            sasl_authzid,
            sasl_realm,
            binddn_filtertemplate=u'(uid=%s)',
            whoami_filtertemplate=u'(uid=%s)',
            loginSearchRoot=u''
        ):
        """
        Send BindRequest to LDAP server
        """
        # Flush old data from cache
        self.flushCache()
        uri = self.uri
        try:
            # Drop the bind call sent before stored in ReconnectLDAPObject's class attribute
            self.l._last_bind = None
            # Force reconnecting in ReconnectLDAPObject
            self.l.reconnect(uri)
        except ldap0.INAPPROPRIATE_AUTH as e:
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
                    ldap0.sasl.CB_AUTHNAME: (who or u'').encode(self.charset),
                    ldap0.sasl.CB_PASS: (cred or u'').encode(self.charset),
                    ldap0.sasl.CB_USER: (sasl_authzid or u'').encode(self.charset),
                    ldap0.sasl.CB_GETREALM: (sasl_realm or u'').encode(self.charset),
                },
                sasl_mech
            )
            if ldap0.SASL_AVAIL:
                self.l.sasl_interactive_bind_s('', sasl_auth, serverctrls=bind_server_ctrls)
                self.saslAuth = sasl_auth
                # Don't store the password
                try:
                    del self.saslAuth.cb_value_dict[ldap0.sasl.CB_PASS]
                except KeyError:
                    pass
            else:
                raise ldap0.LDAPError('SASL not supported by local installation.')
            bind_srv_ctrls = []

        else:
            # Simple bind
            #-------------------------------
            self.saslAuth = None
            if not who or not cred:
                # Anonymous bind
                who = None; cred = None
            else:
                # Search bind DN by "user name" for simple bind
                who = self.getBindDN(who, loginSearchRoot, binddn_filtertemplate)
            # Call simple bind
            try:
                _, _, _, bind_srv_ctrls = self.l.simple_bind_s(
                    self.uc_encode(who or u'')[0],
                    self.uc_encode(cred or u'')[0],
                    serverctrls=bind_server_ctrls,
                )
            except ldap0.INVALID_DN_SYNTAX:
                self.who = None
                raise INVALID_SIMPLE_BIND_DN(who)
            except ldap0.LDAPError as ldap_err:
                # Explicitly fall back to anonymous bind before re-raising exception
                self.who = None
                raise ldap_err
            else:
                self.who = who

        if bind_srv_ctrls:
            authz_identity_ctrls = [
                c
                for c in bind_srv_ctrls
                if c.controlType == AuthorizationIdentityResponseControl.controlType
            ]
            if authz_identity_ctrls:
                authz_id = authz_identity_ctrls[0].authzId.decode(self.charset)
                if authz_id.startswith('dn:'):
                    self.who = authz_id[3:]
                else:
                    self.who = authz_id

        # Determine identity by sending LDAPv3 Who Am I? extended operation
        try:
            whoami = self.whoami()
        except ldap0.LDAPError as e:
            if who:
                self.who = u'u:%s' % (who)
            else:
                self.who = None
        else:
            if whoami:
                if whoami.startswith(u'dn:'):
                    self.who = whoami[3:]
                else:
                    self.who = whoami
            else:
                self.who = None

        # Access to root DSE might have changed after binding
        # as another entity
        self.getRootDSE()

        # Try to look up the user entry's DN in case self.who is still not a DN
        if whoami_filtertemplate and \
           (self.who == None or not web2ldap.ldaputil.base.is_dn(self.who)):
            if self.saslAuth and self.saslAuth.mech in ldap0.sasl.SASL_NONINTERACTIVE_MECHS:
                # For SASL mechs EXTERNAL and GSSAPI the user did not enter a SASL username
                # => try to determine it through OpenLDAP's libldap
                # Ask libldap for SASL username for later LDAP search
                who = self.l.get_option(ldap0.OPT_X_SASL_USERNAME).decode(self.charset)

            # Search for a user entry which matches the username known so far
            try:
                self.who = self.getBindDN(who, loginSearchRoot, whoami_filtertemplate)
            except (ldap0.LDAPError, USERNAME_NOT_FOUND, USERNAME_NOT_UNIQUE):
                pass

        # Read the user's entry if self.who is a DN to get name and preferences
        if self.who and web2ldap.ldaputil.base.is_dn(self.who):
            try:
                userEntryDN, self.userEntry = self.readEntry(
                    self.who,
                    attrtype_list=USER_ENTRY_ATTRIBUTES,
                    search_filter='(objectClass=*)',
                    no_cache=True,
                )[0]
            except (ldap0.LDAPError, IndexError):
                self.userEntry = {}
            else:
                self.who = userEntryDN.decode(self.charset)
        else:
            self.userEntry = {}
        # Extract the password policy response control and raise exceptions
        if bind_srv_ctrls:
            ppolicy_ctrls = [
                c
                for c in bind_srv_ctrls
                if c.controlType == PasswordPolicyControl.controlType
            ]
            if ppolicy_ctrls and len(ppolicy_ctrls) == 1:
                ppolicy_ctrl = ppolicy_ctrls[0]
                if ppolicy_ctrl.error == 2:
                    raise PWD_CHANGE_AFTER_RESET(
                        who=self.who.encode(self.charset),
                        desc='Password change is needed after reset!',
                    )
                elif ppolicy_ctrl.timeBeforeExpiration is not None:
                    raise PWD_EXPIRATION_WARNING(
                        who=self.who.encode(self.charset),
                        desc='Password will expire in %d seconds!' % (
                            ppolicy_ctrl.timeBeforeExpiration
                        ),
                        timeBeforeExpiration=ppolicy_ctrl.timeBeforeExpiration,
                    )
                elif ppolicy_ctrl.graceAuthNsRemaining is not None:
                    raise PWD_EXPIRED(
                        who=self.who.encode(self.charset),
                        desc='Password expired! %d grace logins left.' % (
                            ppolicy_ctrl.graceAuthNsRemaining
                        ),
                        graceAuthNsRemaining=ppolicy_ctrl.graceAuthNsRemaining,
                    )
        return # bind()

    def getGoverningStructureRule(self, dn, schema):
        """
        Determine the governing structure rule for the entry specified with dn
        in the subschema specified in argument schema
        """
        governing_structure_rule = None
        try:
            search_result = self.readEntry(
                dn,
                (
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
        entry = ldap0.schema.models.Entry(schema, dn, search_result[0][1])
        try:
            # Try to directly read the governing structure rule ID
            # from operational attribute in entry
            governing_structure_rule = entry['governingStructureRule'][0]
        except KeyError:
            pass
        else:
            return governing_structure_rule
        possible_dit_structure_rules = {}.fromkeys((
            entry.get_possible_dit_structure_rules(self.uc_encode(dn)[0]) or []
        ))
        parent_dn = web2ldap.ldaputil.base.parent_dn(dn)
        administrative_roles = entry.get('administrativeRole', [])
        if 'subschemaAdminSpecificArea' in administrative_roles or not parent_dn:
            # If the current entry is a subschema administrative point all
            # DIT structure rule with a SUP clause have to be sorted out
            for dit_structure_rule_id in possible_dit_structure_rules.keys():
                dit_structure_rule_obj = schema.get_obj(DITStructureRule, dit_structure_rule_id)
                if dit_structure_rule_obj.sup:
                    del possible_dit_structure_rules[dit_structure_rule_id]
        dit_structure_rules = possible_dit_structure_rules.keys()
        if not dit_structure_rules:
            governing_structure_rule = None
        elif len(dit_structure_rules) == 1:
            governing_structure_rule = dit_structure_rules[0]
        else:
            # More than one possible DIT structure rule found
            if parent_dn:
                parent_governing_structure_rule = self.getGoverningStructureRule(parent_dn, schema)
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
        return governing_structure_rule # getGoverningStructureRule()

    def ldapUrl(self, dn, add_login=True):
        if self.uri:
            lu = ExtendedLDAPUrl(ldapUrl=self.uri.encode('ascii'))
            lu.dn = dn.encode(self.charset)
            if self.startTLSOption:
                lu.x_startTLS = str(START_TLS_REQUIRED * (self.startTLSOption > 0))
            if add_login:
                if self.saslAuth:
                    lu.saslMech = self.saslAuth.mech.encode('ascii')
                    if self.saslAuth.mech in ldap0.sasl.SASL_PASSWORD_MECHS:
                        lu.who = self.saslAuth.cb_value_dict.get(
                            ldap0.sasl.CB_AUTHNAME,
                            u'',
                        ).encode(self.charset) or None
                else:
                    lu.who = (self.who or u'').encode(self.charset) or None
            return lu # ldapUrl()
        else:
            return None

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
