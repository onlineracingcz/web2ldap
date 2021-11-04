# -*- coding: ascii -*-
"""
web2ldap plugin classes for Kerberos (see krb5-kdc.schema)
"""

from typing import Dict

from ..schema.syntaxes import (
    BitArrayInteger,
    DirectoryString,
    OctetString,
    SelectList,
    DynamicDNSelectList,
    Timespan,
    syntax_registry,
)


#-----------------------------------------------------------------
# Schema specific for heimdal
#-----------------------------------------------------------------

syntax_registry.reg_at(
    DirectoryString.oid, [
        '1.3.6.1.4.1.5322.10.1.1',  # krb5PrincipalName
        '1.3.6.1.4.1.5322.10.1.12', # krb5RealmName
    ]
)

syntax_registry.reg_at(
    OctetString.oid, [
        '1.3.6.1.4.1.5322.10.1.10', # krb5Key
        '1.3.6.1.4.1.5322.10.1.13', # krb5ExtendedAttributes
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
    oid: str = '1.3.6.1.4.1.5322.10.0.1'
    flag_desc_table = (
        ('initial', 0x0001),
        ('forwardable', 0x0002),
        ('proxiable', 0x0004),
        ('renewable', 0x0008),
        ('postdate', 0x0010),
        ('server', 0x0020),
        ('client', 0x0040),
        ('invalid', 0x0080),
        ('require-preauth', 0x0100),
        ('change-pw', 0x0200),
        ('require-hwauth', 0x0800),
        ('ok-as-delegate', 0x1000),
        ('user-to-user', 0x2000),
        ('immutable', 0x4000),
    )

syntax_registry.reg_at(
    Krb5KDCFlagsSyntax.oid, [
        '1.3.6.1.4.1.5322.10.1.5', # krb5KDCFlags
    ]
)


syntax_registry.reg_at(
    Timespan.oid, [
        '1.3.6.1.4.1.5322.10.1.3', # krb5MaxLife
    ]
)


#-----------------------------------------------------------------
# Schema specific for MIT Kerberos
# see draft-rajasekaran-kerberos-schema (Beware! It's erroneous!)
#-----------------------------------------------------------------


class KrbTicketFlags(BitArrayInteger):
    oid: str = 'KrbTicketFlags-oid'
    flag_desc_table = (
        ('DISALLOW_POSTDATED', 0x00000001),
        ('DISALLOW_FORWARDABLE', 0x00000002),
        ('DISALLOW_TGT_BASED', 0x00000004),
        ('DISALLOW_RENEWABLE', 0x00000008),
        ('DISALLOW_PROXIABLE', 0x00000010),
        ('DISALLOW_DUP_SKEY', 0x00000020),
        ('DISALLOW_ALL_TIX', 0x00000040),
        ('REQUIRES_PRE_AUTH', 0x00000080),
        ('REQUIRES_HW_AUTH', 0x00000100),
        ('REQUIRES_PWCHANGE', 0x00000200),
        ('DISALLOW_SVR', 0x00001000),
        ('PWCHANGE_SERVICE', 0x00002000),
    )

syntax_registry.reg_at(
    KrbTicketFlags.oid, [
        '2.16.840.1.113719.1.301.4.8.1', # krbTicketFlags
    ]
)

class KrbSearchScope(SelectList):
    oid: str = 'KrbSearchScope-oid'
    desc: str = 'Kerberos search scope'
    attr_value_dict: Dict[str, str] = {
        '1': 'ONE_LEVEL',
        '2': 'SUB_TREE',
    }

syntax_registry.reg_at(
    KrbSearchScope.oid, [
        '2.16.840.1.113719.1.301.4.25.1', # krbSearchScope
    ]
)


class KrbPrincipalType(SelectList):
    oid: str = 'KrbPrincipalType-oid'
    desc: str = 'Kerberos V Principal Type (see RFC 4120, section 6.2)'
    attr_value_dict: Dict[str, str] = {
        '0': 'NT-UNKNOWN',        # Name type not known
        '1': 'NT-PRINCIPAL',      # Just the name of the principal as in DCE, or for users
        '2': 'NT-SRV-INST',       # Service and other unique instance (krbtgt)
        '3': 'NT-SRV-HST',        # Service with host name as instance (telnet, rcommands)
        '4': 'NT-SRV-XHST',       # Service with host as remaining components
        '5': 'NT-UID',            # Unique ID
        '6': 'NT-X500-PRINCIPAL', # Encoded X.509 Distinguished name [RFC2253]
        '7': 'NT-SMTP-NAME',      # Name in form of SMTP email name (e.g., user@example.com)
        '10': 'NT-ENTERPRISE',     # Enterprise name - may be mapped to principal name
    }

syntax_registry.reg_at(
    KrbPrincipalType.oid, [
        '2.16.840.1.113719.1.301.4.3.1', # krbPrincipalType
    ]
)


class KrbTicketPolicyReference(DynamicDNSelectList):
    oid: str = 'KrbTicketPolicyReference-oid'
    desc: str = 'DN of a Kerberos V ticket policy entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=krbTicketPolicy)'

syntax_registry.reg_at(
    KrbTicketPolicyReference.oid, [
        '2.16.840.1.113719.1.301.4.40.1', # krbTicketPolicyReference
    ]
)


class KrbPwdPolicyReference(DynamicDNSelectList):
    oid: str = 'KrbPwdPolicyReference-oid'
    desc: str = 'DN of a Kerberos V password policy entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=krbPwdPolicy)'

syntax_registry.reg_at(
    KrbPwdPolicyReference.oid, [
        '2.16.840.1.113719.1.301.4.36.1', # krbPwdPolicyReference
    ]
)


syntax_registry.reg_at(
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
syntax_registry.reg_syntaxes(__name__)
