# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for Kerberos (see krb5-kdc.schema)
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import \
    BitArrayInteger, \
    DirectoryString, \
    OctetString, \
    SelectList, \
    DynamicDNSelectList, \
    Timespan, \
    syntax_registry


#-----------------------------------------------------------------
# Schema specific for heimdal
#-----------------------------------------------------------------

syntax_registry.registerAttrType(
    DirectoryString.oid, [
        '1.3.6.1.4.1.5322.10.1.1',  # krb5PrincipalName
        '1.3.6.1.4.1.5322.10.1.12', # krb5RealmName
    ]
)

syntax_registry.registerAttrType(
    OctetString.oid, [
        '1.3.6.1.4.1.5322.10.1.10', # krb5Key
    ]
)


class Krb5KDCFlagsSyntax(BitArrayInteger):
    """
       WITH SYNTAX            INTEGER
    --        initial(0),             -- require as-req
    --        forwardable(1),         -- may issue forwardable
    --        proxiable(2),           -- may issue proxiable
    --        renewable(3),           -- may issue renewable
    --        postdate(4),            -- may issue postdatable
    --        server(5),              -- may be server
    --        client(6),              -- may be client
    --        invalid(7),             -- entry is invalid
    --        require-preauth(8),     -- must use preauth
    --        change-pw(9),           -- change password service
    --        require-hwauth(10),     -- must use hwauth
    --        ok-as-delegate(11),     -- as in TicketFlags
    --        user-to-user(12),       -- may use user-to-user auth
    --        immutable(13)           -- may not be deleted
    """
    oid = '1.3.6.1.4.1.5322.10.0.1'
    flag_desc_table = (
        (u'initial', 0x0001),
        (u'forwardable', 0x0002),
        (u'proxiable', 0x0004),
        (u'renewable', 0x0008),
        (u'postdate', 0x0010),
        (u'server', 0x0020),
        (u'client', 0x0040),
        (u'invalid', 0x0080),
        (u'require-preauth', 0x0100),
        (u'change-pw', 0x0200),
        (u'require-hwauth', 0x0800),
        (u'ok-as-delegate', 0x1000),
        (u'user-to-user', 0x2000),
        (u'immutable', 0x4000),
    )

syntax_registry.registerAttrType(
    Krb5KDCFlagsSyntax.oid, [
        '1.3.6.1.4.1.5322.10.1.5', # krb5KDCFlags
    ]
)


syntax_registry.registerAttrType(
    Timespan.oid, [
        '1.3.6.1.4.1.5322.10.1.3', # krb5MaxLife
    ]
)


#-----------------------------------------------------------------
# Schema specific for MIT Kerberos
# see draft-rajasekaran-kerberos-schema (Beware! It's errornous!)
#-----------------------------------------------------------------


class KrbTicketFlags(BitArrayInteger):
    oid = 'KrbTicketFlags-oid'
    flag_desc_table = (
        (u'DISALLOW_POSTDATED', 0x00000001),
        (u'DISALLOW_FORWARDABLE', 0x00000002),
        (u'DISALLOW_TGT_BASED', 0x00000004),
        (u'DISALLOW_RENEWABLE', 0x00000008),
        (u'DISALLOW_PROXIABLE', 0x00000010),
        (u'DISALLOW_DUP_SKEY', 0x00000020),
        (u'DISALLOW_ALL_TIX', 0x00000040),
        (u'REQUIRES_PRE_AUTH', 0x00000080),
        (u'REQUIRES_HW_AUTH', 0x00000100),
        (u'REQUIRES_PWCHANGE', 0x00000200),
        (u'DISALLOW_SVR', 0x00001000),
        (u'PWCHANGE_SERVICE', 0x00002000),
    )

syntax_registry.registerAttrType(
    KrbTicketFlags.oid, [
        '2.16.840.1.113719.1.301.4.8.1', # krbTicketFlags
    ]
)

class KrbSearchScope(SelectList):
    oid = 'KrbSearchScope-oid'
    desc = 'Kerberos search scope'
    attr_value_dict = {
        u'1': u'ONE_LEVEL',
        u'2': u'SUB_TREE',
    }

syntax_registry.registerAttrType(
    KrbSearchScope.oid, [
        '2.16.840.1.113719.1.301.4.25.1', # krbSearchScope
    ]
)


class KrbPrincipalType(SelectList):
    oid = 'KrbPrincipalType-oid'
    desc = 'Kerberos V Principal Type (see RFC 4120, section 6.2)'
    attr_value_dict = {
        u'0': u'NT-UNKNOWN',        # Name type not known
        u'1': u'NT-PRINCIPAL',      # Just the name of the principal as in DCE, or for users
        u'2': u'NT-SRV-INST',       # Service and other unique instance (krbtgt)
        u'3': u'NT-SRV-HST',        # Service with host name as instance (telnet, rcommands)
        u'4': u'NT-SRV-XHST',       # Service with host as remaining components
        u'5': u'NT-UID',            # Unique ID
        u'6': u'NT-X500-PRINCIPAL', # Encoded X.509 Distinguished name [RFC2253]
        u'7': u'NT-SMTP-NAME',      # Name in form of SMTP email name (e.g., user@example.com)
        u'10': u'NT-ENTERPRISE',     # Enterprise name - may be mapped to principal name
    }

syntax_registry.registerAttrType(
    KrbPrincipalType.oid, [
        '2.16.840.1.113719.1.301.4.3.1', # krbPrincipalType
    ]
)


class KrbTicketPolicyReference(DynamicDNSelectList):
    oid = 'KrbTicketPolicyReference-oid'
    desc = 'DN of a Kerberos V ticket policy entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=krbTicketPolicy)'

syntax_registry.registerAttrType(
    KrbTicketPolicyReference.oid, [
        '2.16.840.1.113719.1.301.4.40.1', # krbTicketPolicyReference
    ]
)


class KrbPwdPolicyReference(DynamicDNSelectList):
    oid = 'KrbPwdPolicyReference-oid'
    desc = 'DN of a Kerberos V password policy entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=krbPwdPolicy)'

syntax_registry.registerAttrType(
    KrbPwdPolicyReference.oid, [
        '2.16.840.1.113719.1.301.4.36.1', # krbPwdPolicyReference
    ]
)


syntax_registry.registerAttrType(
    Timespan.oid, [
        '1.2.840.113554.1.4.1.6.3',       # krbPwdMaxLife
        '1.2.840.113554.1.4.1.6.4',       # krbPwdMaxRenewableLife
        '1.3.6.1.4.1.5322.21.2.3',        # krbPwdLockoutDuration
        '2.16.840.1.113719.1.301.4.10.1', # krbMaxRenewableAge
        '2.16.840.1.113719.1.301.4.30.1', # krbMaxPwdLife
        '2.16.840.1.113719.1.301.4.31.1', # krbMinPwdLife
        '2.16.840.1.113719.1.301.4.9.1',  # krbMaxTicketLife
    ]
)


# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
