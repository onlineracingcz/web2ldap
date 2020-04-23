# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for Active Directory (for some information see draft-armijo-ldap-syntax)
"""

import os
import time
import uuid

from ldap0.dn import is_dn
from ldap0.msad import sid2sddl, sddl2sid

import web2ldapcnf

import web2ldap.web
import web2ldap.app.searchform
from web2ldap.utctime import strftimeiso8601
from web2ldap.app.plugins.groups import GroupEntryDN
from web2ldap.app.schema.syntaxes import (
    Binary,
    BitArrayInteger,
    Boolean,
    DirectoryString,
    DistinguishedName,
    DNSDomain,
    DynamicDNSelectList,
    DynamicValueSelectList,
    GeneralizedTime,
    IA5String,
    Integer,
    OctetString,
    OID,
    PropertiesSelectList,
    SelectList,
    Uri,
    XmlValue,
    syntax_registry,
)


class ObjectCategory(DynamicDNSelectList, DistinguishedName):
    oid: str = 'ObjectCategory-oid'
    desc: str = 'DN of the class entry'
    ldap_url = 'ldap:///CN=Schema,CN=Configuration,_?cn?one?(objectClass=classSchema)'
    ref_attrs = (
        (None, 'Same category', None, None),
    )

syntax_registry.reg_at(
    ObjectCategory.oid, [
        '1.2.840.113556.1.4.782', # objectCategory
        '1.2.840.113556.1.4.783', # defaultObjectCategory
    ]
)


class ObjectVersion(Integer, SelectList):
    oid: str = 'ObjectVersion-oid'
    desc: str = 'Object version in MS AD (see [MS-ADTS])'
    attr_value_dict = {
        '13': 'Windows 2000 Server operating system',
        '30': 'Windows Server 2003 operating system or Windows Server 2008 (AD LDS)',
        '31': 'Windows Server 2003 R2 operating system or Windows Server 2008 R2 (AD LDS)',
        '44': 'Windows Server 2008 operating system (AD DS)',
        '47': 'Windows Server 2008 R2 (AD DS)',
        '11221': 'Exchange 2007 SP1',
        '11222': 'Exchange 2007 SP2',
        '12639': 'Exchange 2010',
        '12640': 'Exchange 2010',
        '13040': 'Exchange 2010 SP1',
        '13214': 'Exchange 2010 SP1',
        '14247': 'Exchange 2010 SP2',
    }

    def display(self, valueindex=0, commandbutton=False) -> str:
        return SelectList.display(self, valueindex, commandbutton)

# Register certain attribute types for syntax classes
syntax_registry.reg_at(
    ObjectVersion.oid, [
        '1.2.840.113556.1.2.76', # objectVersion
    ]
)


class ObjectSID(OctetString, IA5String):
    oid: str = 'ObjectSID-oid'
    desc: str = 'Base class for Windows Security Identifiers'
    """
    SID anatomy:
    Byte Position
    0 : SID Structure Revision Level (SRL)
    1 : Number of Subauthority/Relative Identifier
    2-7 : Identifier Authority Value (IAV) [48 bits]
    8-x : Variable number of Subauthority or Relative Identifier (RID)
          [32 bits]
    """

    def _validate(self, attrValue: bytes) -> bool:
        return OctetString._validate(self, attrValue)

    def sanitize(self, attrValue: bytes) -> bytes:
        if not attrValue:
            return b''
        return sddl2sid(attrValue.decode('ascii'))

    def formValue(self) -> str:
        if not self._av:
            return u''
        return sid2sddl(self._av)

    def formField(self) -> str:
        return IA5String.formField(self)

    def display(self, valueindex=0, commandbutton=False) -> str:
        return '%s<br>%s' % (
            self._app.form.utf2display(sid2sddl(self._av)),
            OctetString.display(self, valueindex, commandbutton),
        )

syntax_registry.reg_at(
    ObjectSID.oid, [
        '1.2.840.113556.1.4.146', # objectSID
        '1.2.840.113556.1.4.609', # sIDHistory
    ]
)


class OtherSID(ObjectSID):
    oid: str = 'OtherSID-oid'
    desc: str = 'SID in MS AD which points to another object'
    editable: bool = False
    well_known_sids = {
        # see also http://msdn.microsoft.com/en-us/library/aa379649(VS.85).aspx
        'S-1-0-0': 'NULL',
        'S-1-1': 'WORLD_DOMAIN',
        'S-1-1-0': 'WORLD',
        'S-1-3': 'CREATOR_OWNER_DOMAIN',
        'S-1-3-0': 'CREATOR_OWNER',
        'S-1-3-1': 'CREATOR_GROUP',
        'S-1-3-4': 'OWNER_RIGHTS',
        'S-1-5': 'NT_AUTHORITY',
        'S-1-5-1': 'NT_DIALUP',
        'S-1-5-2': 'NT_NETWORK',
        'S-1-5-3': 'NT_BATCH',
        'S-1-5-4': 'NT_INTERACTIVE',
        'S-1-5-6': 'NT_SERVICE',
        'S-1-5-7': 'NT_ANONYMOUS',
        'S-1-5-8': 'NT_PROXY',
        'S-1-5-9': 'NT_ENTERPRISE_DCS',
        'S-1-5-10': 'NT_SELF',
        'S-1-5-11': 'NT_AUTHENTICATED_USERS',
        'S-1-5-12': 'NT_RESTRICTED',
        'S-1-5-13': 'NT_TERMINAL_SERVER_USERS',
        'S-1-5-14': 'NT_REMOTE_INTERACTIVE',
        'S-1-5-15': 'NT_THIS_ORGANISATION',
        'S-1-5-17': 'NT_IUSR',
        'S-1-5-18': 'NT_SYSTEM',
        'S-1-5-19': 'NT_LOCAL_SERVICE',
        'S-1-5-20': 'NT_NETWORK_SERVICE',
        'S-1-5-64-21': 'NT_DIGEST_AUTHENTICATION',
        'S-1-5-64-10': 'NT_NTLM_AUTHENTICATION',
        'S-1-5-64-14': 'NT_SCHANNEL_AUTHENTICATION',
        'S-1-5-1000': 'NT_OTHER_ORGANISATION',
        'S-1-5-32': 'BUILTIN',
        'S-1-5-32-544': 'BUILTIN_ADMINISTRATORS',
        'S-1-5-32-545': 'BUILTIN_USERS',
        'S-1-5-32-546': 'BUILTIN_GUESTS',
        'S-1-5-32-547': 'BUILTIN_POWER_USERS',
        'S-1-5-32-548': 'BUILTIN_ACCOUNT_OPERATORS',
        'S-1-5-32-549': 'BUILTIN_SERVER_OPERATORS',
        'S-1-5-32-550': 'BUILTIN_PRINT_OPERATORS',
        'S-1-5-32-551': 'BUILTIN_BACKUP_OPERATORS',
        'S-1-5-32-552': 'BUILTIN_REPLICATOR',
        'S-1-5-32-553': 'BUILTIN_RAS_SERVERS',
        'S-1-5-32-554': 'BUILTIN_PREW2K',
        'S-1-5-32-555': 'BUILTIN_REMOTE_DESKTOP_USERS',
        'S-1-5-32-556': 'BUILTIN_NETWORK_CONF_OPERATORS',
    }

    def display(self, valueindex=0, commandbutton=False) -> str:
        sddl_str = sid2sddl(self._av)
        search_anchor = self.well_known_sids.get(sddl_str, '')
        if commandbutton and sddl_str not in self.well_known_sids:
            search_anchor = self._app.anchor(
                'searchform', '&raquo;',
                [
                    ('dn', self._dn),
                    ('searchform_mode', u'adv'),
                    ('search_attr', u'objectSid'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', sddl_str),
                ],
                title=u'Search by SID',
            )
        return '%s %s<br>%s' % (
            self._app.form.utf2display(sddl_str),
            search_anchor,
            OctetString.display(self, valueindex, commandbutton),
        )

syntax_registry.reg_at(
    OtherSID.oid, [
        '1.2.840.113556.1.4.1301', # tokenGroups
        '1.2.840.113556.1.4.1418', # tokenGroupsGlobalAndUniversal
        '1.2.840.113556.1.4.1303', # tokenGroupsNoGCAcceptable
        '1.2.840.113556.1.4.667',  # syncWithSID
        '1.2.840.113556.1.4.1410', # mS-DS-CreatorSID
    ]
)


class SAMAccountName(DirectoryString):
    oid: str = 'SAMAccountName-oid'
    desc: str = 'SAM-Account-Name in MS AD'
    maxLen: int = 20

# Register certain attribute types for syntax classes
syntax_registry.reg_at(
    SAMAccountName.oid, [
        '1.2.840.113556.1.4.221', # sAMAccountName
    ]
)


class SAMAccountType(SelectList):
    """
    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/adschema/adschema/a_samaccounttype.asp
    """
    oid: str = 'SAMAccountType-oid'
    desc: str = 'SAM-Account-Type in MS AD'
    attr_value_dict = {
        '268435456': 'SAM_GROUP_OBJECT',
        '268435457': 'SAM_NON_SECURITY_GROUP_OBJECT',
        '536870912': 'SAM_ALIAS_OBJECT',
        '536870913': 'SAM_NON_SECURITY_ALIAS_OBJECT',
        '805306368': 'SAM_NORMAL_USER_ACCOUNT',
        '805306369': 'SAM_MACHINE_ACCOUNT',
        '805306370': 'SAM_TRUST_ACCOUNT',
        '1073741824': 'SAM_APP_BASIC_GROUP',
        '1073741825': 'SAM_APP_QUERY_GROUP',
        '2147483647': 'SAM_ACCOUNT_TYPE_MAX',
    }

# Register certain attribute types for syntax classes
syntax_registry.reg_at(
    SAMAccountType.oid, [
        '1.2.840.113556.1.4.302', # sAMAccountType
    ]
)


class GroupType(BitArrayInteger):
    """
    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/adschema/adschema/a_samaccounttype.asp
    """
    oid: str = 'GroupType-oid'
    desc: str = 'Group-Type in MS AD'
    flag_desc_table = (
        ('Group created by system', 0x00000001),
        ('Group with global scope', 0x00000002),
        ('Group with domain local scope', 0x00000004),
        ('Group with universal scope', 0x00000008),
        ('APP_BASIC group Authz Mgr', 0x00000010),
        ('APP_QUERY group Authz Mgr.', 0x00000020),
        ('Security group', 0x80000000),
    )

syntax_registry.reg_at(
    GroupType.oid, [
        '1.2.840.113556.1.4.750', # groupType
    ]
)


class DomainRID(SelectList):
    oid: str = 'DomainRID-oid'
    desc: str = 'Domain RID in MS AD'
    attr_value_dict = {
        '9': 'DOMAIN_RID_LOGON',
        '500': 'DOMAIN_RID_ADMINISTRATOR',
        '501': 'DOMAIN_RID_GUEST',
        '502': 'DOMAIN_RID_KRBTGT',
        '512': 'DOMAIN_RID_ADMINS',
        '513': 'DOMAIN_RID_USERS',
        '514': 'DOMAIN_RID_GUESTS',
        '515': 'DOMAIN_RID_DOMAIN_MEMBERS',
        '516': 'DOMAIN_RID_DCS',
        '517': 'DOMAIN_RID_CERT_ADMINS',
        '518': 'DOMAIN_RID_SCHEMA_ADMINS',
        '519': 'DOMAIN_RID_ENTERPRISE_ADMINS',
        '520': 'DOMAIN_RID_POLICY_ADMINS',
    }

syntax_registry.reg_at(
    DomainRID.oid, [
        '1.2.840.113556.1.4.98', # primaryGroupID
    ]
)


class UserAccountControl(BitArrayInteger):
    """
    See knowledge base article 305144:
    http://support.microsoft.com/default.aspx?scid=kb;en-us;Q305144
    """
    oid: str = 'UserAccountControl-oid'
    flag_desc_table = (
        ('SCRIPT', 0x0001),
        ('ACCOUNTDISABLE', 0x0002),
        ('HOMEDIR_REQUIRED', 0x0008),
        ('LOCKOUT', 0x0010),
        ('PASSWD_NOTREQD', 0x0020),
        ('PASSWD_CANT_CHANGE', 0x0040),
        ('ENCRYPTED_TEXT_PWD_ALLOWED', 0x0080),
        ('TEMP_DUPLICATE_ACCOUNT', 0x0100),
        ('NORMAL_ACCOUNT', 0x0200),
        ('INTERDOMAIN_TRUST_ACCOUNT', 0x0800),
        ('WORKSTATION_TRUST_ACCOUNT', 0x1000),
        ('SERVER_TRUST_ACCOUNT', 0x2000),
        ('DONT_EXPIRE_PASSWORD', 0x10000),
        ('MNS_LOGON_ACCOUNT', 0x20000),
        ('SMARTCARD_REQUIRED', 0x40000),
        ('TRUSTED_FOR_DELEGATION', 0x80000),
        ('NOT_DELEGATED', 0x100000),
        ('USE_DES_KEY_ONLY', 0x200000),
        ('DONT_REQ_PREAUTH', 0x400000),
        ('PASSWORD_EXPIRED', 0x800000),
        ('TRUSTED_TO_AUTH_FOR_DELEGATION', 0x1000000),
        ('NO_AUTH_DATA_REQUIRED', 0x2000000),
        ('PARTIAL_SECRETS_ACCOUNT', 0x4000000),
    )

syntax_registry.reg_at(
    UserAccountControl.oid, [
        '1.2.840.113556.1.4.8', # userAccountControl
    ]
)


class SystemFlags(BitArrayInteger):
    """
    See
    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/adschema/adschema/a_systemflags.asp
    and
    http://msdn2.microsoft.com/en-us/library/aa772297.aspx
    """
    oid: str = 'SystemFlags-oid'
    flag_desc_table = (
        ('ADS_SYSTEMFLAG_DISALLOW_DELETE', 0x80000000),
        ('ADS_SYSTEMFLAG_CONFIG_ALLOW_RENAME', 0x40000000),
        ('ADS_SYSTEMFLAG_CONFIG_ALLOW_MOVE', 0x20000000),
        ('ADS_SYSTEMFLAG_CONFIG_ALLOW_LIMITED_MOVE', 0x10000000),
        ('ADS_SYSTEMFLAG_DOMAIN_DISALLOW_RENAME', 0x08000000),
        ('ADS_SYSTEMFLAG_DOMAIN_DISALLOW_MOVE', 0x04000000),
        ('ADS_SYSTEMFLAG_CR_NTDS_NC', 0x00000001),
        ('ADS_SYSTEMFLAG_CR_NTDS_DOMAIN', 0x00000002),
        ('ADS_SYSTEMFLAG_ATTR_NOT_REPLICATED', 0x00000001),
        ('ADS_SYSTEMFLAG_ATTR_IS_CONSTRUCTED', 0x00000004),
        ('IS_CATEGORY_1_OBJECT', 0x00000010),
        ('IS_NOT_MOVED_TO_THE_DELETED_OBJECTS', 0x02000000),
    )

syntax_registry.reg_at(
    SystemFlags.oid, [
        '1.2.840.113556.1.4.375', # systemFlags
    ]
)


class SearchFlags(BitArrayInteger):
    """
    http://msdn.microsoft.com/en-us/library/ms679765(VS.85).aspx

     1 (0x00000001) Create an index for the attribute.
     2 (0x00000002) Create an index for the attribute in each container.
     4 (0x00000004) Add this attribute to the Ambiguous Name Resolution (ANR) set.
     8 (0x00000008) Preserve this attribute in the tombstone object for deleted objects.
    16 (0x00000010) Copy the value for this attribute when the object is copied.
    32 (0x00000020) Create a tuple index for the attribute (since Windows Server 2003).
    64 (0x00000040) Creates an index to greatly help VLV performance on arbitrary attributes (ADAM).
    """
    oid: str = 'SearchFlags-oid'
    flag_desc_table = (
        ('Indexed', 0x0001),
        ('Indexed in each container', 0x0002),
        ('Ambiguous Name Resolution (ANR)', 0x0004),
        ('Preserve in tombstone object', 0x0008),
        ('Copy value when object copied', 0x0010),
        ('tuple index', 0x0020),
        ('VLV index (Subtree Index in ADAM)', 0x0040),
        ('CONFIDENTIAL', 0x0080),
        ('NEVER_AUDIT_VALUE', 0x0100),
        ('RODC_FILTERED', 0x0200),
        ('', 0x0400),
        ('', 0x0800),
    )

syntax_registry.reg_at(
    SearchFlags.oid, [
        '1.2.840.113556.1.2.334', # searchFlags
    ]
)


class LogonHours(OctetString):
    oid: str = 'LogonHours-oid'
    desc: str = 'Logon hours'
    dayofweek = ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat')

    @staticmethod
    def _extract_hours(value):
        if not value or len(value) != 21:
            return []
        hour_flags = []
        for eight_hours in value:
            for i in range(8):
                hour_flags.append({0:'-', 1:'X'}[(eight_hours>>i)&1])
        return hour_flags

    def sanitize(self, attrValue: bytes) -> bytes:
        if not attrValue:
            return b''
        attrValue = attrValue.replace(b'\r', b'').replace(b'\n', b'')
        hour_flags = [
            int(attrValue[i:i+1] == b'X')<<i%8
            for i in range(len(attrValue))
        ]
        res = [
            sum(hour_flags[i*8:(i+1)*8])
            for i in range(21)
        ]
        return bytes(res)

    def _validate(self, attrValue: bytes) -> bool:
        return len(attrValue) == 21

    def formValue(self) -> str:
        hour_flags = self._extract_hours(self._av)
        if hour_flags:
            day_bits = [
                ''.join(hour_flags[24*day:24*day+24])
                for day in range(7)
            ]
        else:
            day_bits = []
        return '\r\n'.join(day_bits)

    def formField(self) -> str:
        return web2ldap.web.forms.Textarea(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen,
            1,
            None,
            default=self.formValue(),
            rows=7,
            cols=24,
        )

    def display(self, valueindex=0, commandbutton=False) -> str:
        hour_flags = self._extract_hours(self._av)
        result_lines = [
            """<tr>
            <th width="10%%">Day</th>
            <th colspan="3" width="8%%">0</th>
            <th colspan="3" width="8%%">3</th>
            <th colspan="3" width="8%%">6</th>
            <th colspan="3" width="8%%">9</th>
            <th colspan="3" width="8%%">12</th>
            <th colspan="3" width="8%%">15</th>
            <th colspan="3" width="8%%">18</th>
            <th colspan="3" width="8%%">21</th>
            </tr>""",
        ]
        for day in range(7):
            day_bits = hour_flags[24*day:24*day+24]
            result_lines.append(
                '<tr><td>%s</td><td>%s</td></tr>' % (
                    self.dayofweek[day],
                    '</td><td>'.join(day_bits)
                )
            )
        return '<p>%s</p><table>%s</table>' % (
            OctetString.display(self, valueindex, commandbutton),
            '\n'.join(result_lines)
        )


syntax_registry.reg_at(
    LogonHours.oid, [
        '1.2.840.113556.1.4.64', # logonHours
    ]
)


class CountryCode(PropertiesSelectList):
    oid: str = 'CountryCode-oid'
    desc: str = 'Numerical country code'
    properties_pathname = os.path.join(
        web2ldapcnf.etc_dir, 'properties', 'attribute_select_countryCode.properties'
    )
    simpleSanitizers = (
        bytes.strip,
    )

    def _get_attr_value_dict(self):
        # Enable empty value in any case
        attr_value_dict = {'0': '-/-'}
        attr_value_dict.update(PropertiesSelectList._get_attr_value_dict(self))
        del attr_value_dict['']
        return attr_value_dict


syntax_registry.reg_at(
    CountryCode.oid, [
        '1.2.840.113556.1.4.25', # countryCode
    ]
)


class InstanceType(BitArrayInteger):
    """
    http://msdn.microsoft.com/library/en-us/adschema/adschema/a_instancetype.asp
    """
    oid: str = 'InstanceType-oid'
    flag_desc_table = (
        ('The head of naming context.', 0x00000001),
        ('This replica is not instantiated.', 0x00000002),
        ('The object is writable on this directory.', 0x00000004),
        ('The naming context above this one on this directory is held.', 0x00000008),
        ('The naming context is in the process of being constructed for the first time via replication.', 0x00000010),
        ('The naming context is in the process of being removed from the local DSA.', 0x00000020),
    )

syntax_registry.reg_at(
    InstanceType.oid, [
        '1.2.840.113556.1.2.1', # instanceType
    ]
)


class DNWithOctetString(DistinguishedName):
    oid: str = '1.2.840.113556.1.4.903'
    desc: str = 'DNWithOctetString'
    octetTag = 'B'

    def _validate(self, attrValue: bytes) -> bool:
        try:
            octet_tag, count, octet_string, dn = self._app.ls.uc_decode(attrValue)[0].split(':')
        except ValueError:
            return False
        try:
            count = int(count)
        except ValueError:
            return False
        return len(octet_string) == count and octet_tag.upper() == self.octetTag and is_dn(dn)

    def display(self, valueindex=0, commandbutton=False) -> str:
        try:
            octet_tag, count, octet_string, dn = self.av_u.split(':')
        except ValueError:
            return self._app.form.utf2display(self.av_u)
        return ':'.join([
            self._app.form.utf2display(octet_tag),
            self._app.form.utf2display(count),
            self._app.form.utf2display(octet_string),
            self._app.display_dn(
                dn,
                commandbutton=commandbutton,
            )
        ])


class DNWithString(DNWithOctetString):
    oid: str = '1.2.840.113556.1.4.904'
    desc: str = 'DNWithString'
    octetTag = 'S'


class MicrosoftLargeInteger(Integer):
    oid: str = '1.2.840.113556.1.4.906'
    desc: str = 'Integer guaranteed to support 64 bit numbers'


class ObjectSecurityDescriptor(OctetString):
    oid: str = '1.2.840.113556.1.4.907'
    desc: str = 'Object-Security-Descriptor'


class MsAdGUID(OctetString):
    oid: str = 'MsAdGUID-oid'
    desc: str = 'GUID in Active Directory'

    def sanitize(self, attrValue: bytes) -> bytes:
        try:
            object_guid_uuid = uuid.UUID(attrValue.decode('ascii').replace(':', ''))
        except ValueError:
            return OctetString.sanitize(self, attrValue)
        return object_guid_uuid.bytes

    def display(self, valueindex=0, commandbutton=False) -> str:
        object_guid_uuid = uuid.UUID(bytes=self._av)
        return '{%s}<br>%s' % (
            str(object_guid_uuid),
            OctetString.display(self, valueindex=0, commandbutton=False),
        )

syntax_registry.reg_at(
    MsAdGUID.oid, [
        '1.2.840.113556.1.4.2',    # objectGUID
        '1.2.840.113556.1.4.1224', # parentGUID
        '1.2.840.113556.1.4.340',  # rightsGuid
        '1.2.840.113556.1.4.362',  # siteGUID
    ]
)


class Interval(MicrosoftLargeInteger):
    oid: str = 'Interval-oid'
    desc: str = 'Large integer with timestamp expressed as 100 nanoseconds since 1601-01-01 00:00'

    @staticmethod
    def _delta(attrValue):
        return (int(attrValue)-116444736000000000)/10000000

    def display(self, valueindex=0, commandbutton=False) -> str:
        if self.av_u == '9223372036854775807':
            return '-1: unlimited/off'
        delta = self._delta(self.av_u)
        if delta >= 0:
            return '%s (%s)' % (
                MicrosoftLargeInteger.display(self, valueindex, commandbutton),
                self._app.form.utf2display(str(strftimeiso8601(time.gmtime(delta)))),
            )
        return self.av_u


class LockoutTime(Interval):
    oid: str = 'LockoutTime-oid'
    desc: str = 'Timestamp of password failure lockout'

    def display(self, valueindex=0, commandbutton=False) -> str:
        delta = self._delta(self._av)
        if delta == 0:
            return '%s (not locked)' % (MicrosoftLargeInteger.display(self, valueindex, commandbutton))
        if delta < 0:
            return MicrosoftLargeInteger.display(self, valueindex, commandbutton)
        return '%s (locked since %s)' % (
            MicrosoftLargeInteger.display(self, valueindex, commandbutton),
            self._app.form.utf2display(str(strftimeiso8601(time.gmtime(delta)))),
        )

syntax_registry.reg_at(
    LockoutTime.oid, [
        '1.2.840.113556.1.4.662', # lockoutTime
    ]
)


class DomainFunctionality(SelectList):
    oid: str = 'DomainFunctionality-oid'
    desc: str = 'Functional level of domain/forest'

    attr_value_dict = {
        '': '',
        '0': 'Windows 2000',
        '1': 'Windows 2003 Mixed',
        '2': 'Windows 2003',
        '3': 'Windows 2008',
        '4': 'Windows 2008R2',
        '5': 'Windows 2012',
    }

syntax_registry.reg_at(
    DomainFunctionality.oid, [
        'domainFunctionality', # no schema information available
        'forestFunctionality', # no schema information available
    ]
)


class DomainControllerFunctionality(SelectList):
    oid: str = 'DomainControllerFunctionality-oid'
    desc: str = 'Functional level of domain controller'

    attr_value_dict = {
        '': '',
        '0': 'Windows 2000',
        '2': 'Windows 2003',
        '3': 'Windows 2008',
        '4': 'Windows 2008R2',
        '5': 'Windows 2012',
        '6': 'Windows 2012R2',
    }

syntax_registry.reg_at(
    DomainFunctionality.oid, [
        'domainControllerFunctionality', # no schema information available
    ]
)


# Register certain attribute types for Interval
syntax_registry.reg_at(
    Interval.oid, [
        '1.2.840.113556.1.4.159',  # accountExpires
        '1.2.840.113556.1.4.49',   # badPasswordTime
        '1.2.840.113556.1.4.52',   # lastLogon
        '1.2.840.113556.1.4.1696', # lastLogonTimestamp
        '1.2.840.113556.1.4.51',   # lastLogoff
        '1.2.840.113556.1.4.96',   # pwdLastSet
    ]
)


class ServerStatus(SelectList):
    oid: str = 'ServerStatus-oid'
    desc: str = 'Specifies whether the server is enabled or disabled.'
    attr_value_dict = {
        '': '',
        '1': 'enabled',
        '2': 'disabled',
    }

syntax_registry.reg_at(
    ServerStatus.oid, [
        '1.2.840.113556.1.4.154', # serverStatus
    ]
)


class ObjectClassCategory(SelectList):
    oid: str = 'ObjectClassCategory-oid'
    desc: str = 'Category for object class'
    attr_value_dict = {
        '1': 'STRUCTURAL',
        '2': 'ABSTRACT',
        '3': 'AUXILIARY',
    }

syntax_registry.reg_at(
    ObjectClassCategory.oid, [
        '1.2.840.113556.1.2.370', # objectClassCategory
    ]
)


class ClassSchemaLDAPName(DynamicValueSelectList, OID):
    oid: str = 'ClassSchema-oid'
    desc: str = 'lDAPDisplayName of the classSchema entry'
    ldap_url = 'ldap:///_?lDAPDisplayName,lDAPDisplayName?one?(objectClass=classSchema)'

    def display(self, valueindex=0, commandbutton=False) -> str:
        return OID.display(self, valueindex, commandbutton)

syntax_registry.reg_at(
    ClassSchemaLDAPName.oid, [
        '1.2.840.113556.1.2.351', # auxiliaryClass
        '1.2.840.113556.1.4.198', # systemAuxiliaryClass
        '1.2.840.113556.1.2.8',   # possSuperiors
        '1.2.840.113556.1.4.195', # systemPossSuperiors
    ]
)


class AttributeSchemaLDAPName(DynamicValueSelectList, OID):
    oid: str = 'AttributeSchema-oid'
    desc: str = 'lDAPDisplayName of the classSchema entry'
    ldap_url = 'ldap:///_?lDAPDisplayName,lDAPDisplayName?one?(objectClass=attributeSchema)'

    def display(self, valueindex=0, commandbutton=False) -> str:
        return OID.display(self, valueindex, commandbutton)

syntax_registry.reg_at(
    AttributeSchemaLDAPName.oid, [
        '1.2.840.113556.1.2.25', # mayContain
        '1.2.840.113556.1.4.196', # systemMayContain
        '1.2.840.113556.1.2.24', # mustContain
        '1.2.840.113556.1.4.197', # systemMustContain
    ]
)


class PwdProperties(BitArrayInteger):
    """
    http://msdn.microsoft.com/en-us/library/ms679431(VS.85).aspx
    """
    oid: str = 'PwdProperties-oid'
    flag_desc_table = (
        ('DOMAIN_PASSWORD_COMPLEX', 1),
        ('DOMAIN_PASSWORD_NO_ANON_CHANGE', 2),
        ('DOMAIN_PASSWORD_NO_CLEAR_CHANGE', 4),
        ('DOMAIN_LOCKOUT_ADMINS', 8),
        ('DOMAIN_PASSWORD_STORE_CLEARTEXT', 16),
        ('DOMAIN_REFUSE_PASSWORD_CHANGE', 32)
    )

syntax_registry.reg_at(
    PwdProperties.oid, [
        '1.2.840.113556.1.4.93', # pwdProperties
    ]
)


class MsDSSupportedEncryptionTypes(BitArrayInteger):
    oid: str = 'MsDSSupportedEncryptionTypes-oid'
    flag_desc_table = (
        ('KERB_ENCTYPE_DES_CBC_CRC', 0x00000001),
        ('KERB_ENCTYPE_DES_CBC_MD5', 0x00000002),
        ('KERB_ENCTYPE_RC4_HMAC_MD5', 0x00000004),
        ('KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96', 0x00000008),
        ('KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96', 0x00000010),
    )

syntax_registry.reg_at(
    MsDSSupportedEncryptionTypes.oid, [
        '1.2.840.113556.1.4.1963', # msDS-SupportedEncryptionTypes
    ]
)


class ShowInAddressBook(DynamicDNSelectList):
    oid: str = 'ShowInAddressBook-oid'
    desc: str = 'DN of the addressbook container entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=addressBookContainer)'

syntax_registry.reg_at(
    ShowInAddressBook.oid, [
        '1.2.840.113556.1.4.644', # showInAddressBook
    ]
)


class MsDSReplAttributeMetaData(XmlValue):
    oid: str = 'MsDSReplAttributeMetaData-oid'
    editable: bool = False

    def _validate(self, attrValue: bytes) -> bool:
        return attrValue.endswith(b'\n\x00') and XmlValue._validate(self, attrValue[:-1])

syntax_registry.reg_at(
    MsDSReplAttributeMetaData.oid, [
        '1.2.840.113556.1.4.1707',   # msDS-ReplAttributeMetaData
    ]
)


class MsSFU30NisDomain(DynamicValueSelectList):
    oid: str = 'MsSFU30NisDomain-oid'
    desc: str = 'Name of NIS domain controlled by MS SFU'
    ldap_url = 'ldap:///_?cn,cn?sub?(objectClass=msSFU30DomainInfo)'

syntax_registry.reg_at(
    MsSFU30NisDomain.oid, [
        '1.2.840.113556.1.6.18.1.339', # msSFU30NisDomain
    ]
)


syntax_registry.reg_at(
    GroupEntryDN.oid, [
        '2.5.4.49', # distinguishedName
    ],
    structural_oc_oids=[
        '1.2.840.113556.1.5.8', # group
    ],
)


# Work around for Active Directory of Windows 2000:
# Register syntaxes by odd names
syntax_registry.oid2syntax['Boolean'] = Boolean
syntax_registry.oid2syntax['DN'] = DistinguishedName
syntax_registry.oid2syntax['Integer'] = Integer
syntax_registry.oid2syntax['DirectoryString'] = DirectoryString
syntax_registry.oid2syntax['GeneralizedTime'] = GeneralizedTime

syntax_registry.reg_at(
    DistinguishedName.oid, [
        'configurationNamingContext',
        'defaultNamingContext',
        'dsServiceName',
        'rootDomainNamingContext',
        'schemaNamingContext',
        '1.2.840.113556.1.4.223', # serverName
    ]
)

# MS AD declares these attributes with OctetString
# syntax but Binary syntax is more suitable
syntax_registry.reg_at(
    Binary.oid, [
        '1.2.840.113556.1.4.645', # userCert
        '1.2.840.113556.1.4.4',   # replUpToDateVector
        '1.2.840.113556.1.2.91',  # repsFrom
        '1.2.840.113556.1.2.83',  # repsTo
        '1.2.840.113556.1.2.281', # nTSecurityDescriptor
    ]
)

# MS AD declares these attributes with DirectoryString
# syntax but OctetString syntax is more suitable
syntax_registry.reg_at(
    OctetString.oid, [
        '1.2.840.113556.1.4.138', # userParameters
    ]
)

syntax_registry.reg_at(
    Uri.oid, [
        '1.2.840.113556.1.4.583', # meetingURL
        '1.2.840.113556.1.2.464', # wWWHomePage
        '1.2.840.113556.1.4.749', # url
    ]
)

syntax_registry.reg_at(
    DNSDomain.oid, [
        '1.2.840.113556.1.4.619',   # dNSHostName
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
