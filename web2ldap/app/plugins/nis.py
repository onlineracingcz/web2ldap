# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for schema elements defined in RFC2307
"""

import re

import web2ldap.app.searchform
from web2ldap.app.schema.syntaxes import \
    DaysSinceEpoch, \
    DNSDomain, \
    DynamicValueSelectList, \
    IA5String, \
    Integer, \
    IPHostAddress, \
    IPServicePortNumber, \
    MacAddress, \
    SelectList, \
    syntax_registry


class RFC2307BootParameter(IA5String):
    oid: str = '1.3.6.1.1.1.0.1'
    desc: str = 'RFC2307 Boot Parameter'
    reObj = None # just a stub, should be made stricter


class GidNumber(DynamicValueSelectList, Integer):
    oid: str = 'GidNumber-oid'
    desc: str = 'RFC2307: An integer uniquely identifying a group in an administrative domain'
    minValue = 0
    maxValue = 4294967295
    ldap_url = 'ldap:///_?gidNumber,cn?sub?(objectClass=posixGroup)'

    def _validate(self, attrValue: bytes) -> bool:
        return Integer._validate(self, attrValue)

    def display(self, valueindex=0, commandbutton=False) -> str:
        # Possibly display a link
        ocs = self._entry.object_class_oid_set()
        if 'posixAccount' in ocs or 'shadowAccount' in ocs:
            return DynamicValueSelectList.display(self, valueindex, commandbutton)
        r = [Integer.display(self, valueindex, commandbutton=False)]
        if not commandbutton:
            return r[0]
        if 'posixGroup' in ocs:
            title = u'Search primary group members'
            searchform_params = [
                ('dn', self._dn),
                ('searchform_mode', u'adv'),
                ('search_attr', u'objectClass'),
                ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                ('search_string', u'posixAccount'),
                ('search_attr', u'gidNumber'),
                ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                ('search_string', self.av_u),
            ]
        else:
            title = None
            searchform_params = None
        if title and searchform_params:
            r.append(self._app.anchor(
                'searchform', '&raquo;',
                searchform_params,
                title=title,
            ))
        return ' '.join(r)

    def formField(self) -> str:
        ocs = self._entry.object_class_oid_set()
        if 'posixAccount' in ocs or 'shadowAccount' in ocs:
            return DynamicValueSelectList.formField(self)
        return Integer.formField(self)

syntax_registry.reg_at(
    GidNumber.oid, [
        '1.3.6.1.1.1.1.1', # gidNumber
    ]
)


class MemberUID(IA5String, DynamicValueSelectList):
    oid: str = 'MemberUID-oid'
    desc: str = 'RFC2307 numerical UID of group member(s)'
    ldap_url = None
    #ldap_url = 'ldap:///_?uid,cn?sub?(objectClass=posixAccount)'

    def __init__(self, app, dn: str, schema, attrType: str, attrValue: bytes, entry=None):
        IA5String.__init__(self, app, dn, schema, attrType, attrValue, entry)
        if self.ldap_url:
            DynamicValueSelectList.__init__(self, app, dn, schema, attrType, attrValue, entry)

    def _validate(self, attrValue: bytes) -> bool:
        if self.ldap_url:
            return DynamicValueSelectList._validate(self, attrValue)
        return IA5String._validate(self, attrValue)

    def formField(self) -> str:
        if self.ldap_url:
            return DynamicValueSelectList.formField(self)
        return IA5String.formField(self)

    def display(self, valueindex=0, commandbutton=False) -> str:
        r = [IA5String.display(self, valueindex, commandbutton=False)]
        if commandbutton:
            r.append(self._app.anchor(
                'searchform', '&raquo;',
                [
                    ('dn', self._dn),
                    (
                        'filterstr', '(&(objectClass=posixAccount)(uid=%s))' % (
                            self._app.form.utf2display(self.av_u)
                        )
                    ),
                    ('searchform_mode', u'exp'),
                ],
                title=u'Search for user entry',
            ))
        return ' '.join(r)

syntax_registry.reg_at(
    MemberUID.oid, [
        '1.3.6.1.1.1.1.12', # memberUid
    ]
)


class RFC2307NISNetgroupTriple(IA5String):
    oid: str = '1.3.6.1.1.1.0.0'
    desc: str = 'RFC2307 NIS Netgroup Triple'
    reObj = re.compile(r'^\([a-z0-9.-]*,[a-z0-9.-]*,[a-z0-9.-]*\)$')


class UidNumber(Integer):
    oid: str = 'UidNumber-oid'
    desc: str = 'Numerical user ID for Posix systems'
    minValue = 0
    maxValue = 4294967295

syntax_registry.reg_at(
    UidNumber.oid, [
        '1.3.6.1.1.1.1.0', # uidNumber
    ]
)


class Shell(SelectList):
    oid: str = 'Shell-oid'
    desc: str = 'Shell for user of Posix systems'
    attr_value_dict = {
        u'/bin/sh': u'Standard shell /bin/sh',
        u'/bin/bash': u'Bourne-Again SHell /bin/bash',
        u'/bin/csh': u'/bin/csh',
        u'/bin/tcsh': u'/bin/tcsh',
        u'/bin/ksh': u'Korn shell /bin/ksh',
        u'/bin/passwd': u'Password change /bin/passwd',
        u'/bin/true': u'/bin/true',
        u'/bin/false': u'/bin/false',
        u'/bin/zsh': u'Zsh /bin/zsh',
        u'/usr/bin/bash': u'Bourne-Again SHell /usr/bin/bash',
        u'/usr/bin/csh': u'/usr/bin/csh',
        u'/usr/bin/tcsh': u'/usr/bin/csh',
        u'/usr/bin/ksh': u'Korn shell /usr/bin/ksh',
        u'/usr/bin/zsh': u'Zsh /usr/bin/zsh',
        u'/usr/sbin/nologin': u'Login denied /usr/sbin/nologin',
    }

syntax_registry.reg_at(
    Shell.oid, [
        '1.3.6.1.1.1.1.4', # loginShell
    ]
)


class IpServiceProtocol(SelectList):
    oid: str = 'IpServiceProtocol-oid'
    desc: str = 'RFC 2307: IP service protocol'

    attr_value_dict = {
        u'tcp': u'tcp',
        u'udp': u'udp',
    }

syntax_registry.reg_at(
    IpServiceProtocol.oid, [
        '1.3.6.1.1.1.1.16', # ipServiceProtocol
    ]
)


syntax_registry.reg_at(
    IPHostAddress.oid, [
        '1.3.6.1.1.1.1.19', # ipHostNumber
        '1.3.6.1.1.1.1.20', # ipNetworkNumber
    ]
)


syntax_registry.reg_at(
    DNSDomain.oid, [
        '1.3.6.1.1.1.1.30', # nisDomain
    ]
)


syntax_registry.reg_at(
    DaysSinceEpoch.oid, [
        '1.3.6.1.1.1.1.10', # shadowExpire
        '1.3.6.1.1.1.1.5', # shadowLastChange
    ]
)


syntax_registry.reg_at(
    IPServicePortNumber.oid, [
        '1.3.6.1.1.1.1.15', # ipServicePort
    ]
)


syntax_registry.reg_at(
    MacAddress.oid, [
        '1.3.6.1.1.1.1.22', # macAddress
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
