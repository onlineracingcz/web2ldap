# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for Active Directory (for some information see draft-armijo-ldap-syntax)
"""

from __future__ import absolute_import

import os
import time
import struct
import uuid

import web2ldapcnf

import web2ldap.web
import web2ldap.app.searchform
from web2ldap.utctime import strftimeiso8601
from web2ldap.ldaputil import is_dn
from web2ldap.app.plugins.groups import GroupEntryDN
from web2ldap.app.schema.syntaxes import \
    Binary, \
    BitArrayInteger, \
    Boolean, \
    DirectoryString, \
    DistinguishedName, \
    DNSDomain, \
    DynamicDNSelectList, \
    DynamicValueSelectList, \
    GeneralizedTime, \
    IA5String, \
    Integer, \
    OctetString, \
    OID, \
    PropertiesSelectList, \
    SelectList, \
    Uri, \
    XmlValue, \
    syntax_registry


class ObjectCategory(DynamicDNSelectList, DistinguishedName):
    oid = 'ObjectCategory-oid'
    desc = 'DN of the class entry'
    ldap_url = 'ldap:///CN=Schema,CN=Configuration,_?cn?one?(objectClass=classSchema)'
    ref_attrs = (
        (None, u'Same category', None, None),
    )

syntax_registry.reg_at(
    ObjectCategory.oid, [
        '1.2.840.113556.1.4.782', # objectCategory
        '1.2.840.113556.1.4.783', # defaultObjectCategory
    ]
)


class ObjectVersion(Integer, SelectList):
    oid = 'ObjectVersion-oid'
    desc = 'Object version in MS AD (see [MS-ADTS])'
    attr_value_dict = {
        u'13': u'Windows 2000 Server operating system',
        u'30': u'Windows Server 2003 operating system or Windows Server 2008 (AD LDS)',
        u'31': u'Windows Server 2003 R2 operating system or Windows Server 2008 R2 (AD LDS)',
        u'44': u'Windows Server 2008 operating system (AD DS)',
        u'47': u'Windows Server 2008 R2 (AD DS)',
        u'11221': u'Exchange 2007 SP1',
        u'11222': u'Exchange 2007 SP2',
        u'12639': u'Exchange 2010',
        u'12640': u'Exchange 2010',
        u'13040': u'Exchange 2010 SP1',
        u'13214': u'Exchange 2010 SP1',
        u'14247': u'Exchange 2010 SP2',
    }

    def displayValue(self, valueindex=0, commandbutton=False):
        return SelectList.displayValue(self, valueindex, commandbutton)

# Register certain attribute types for syntax classes
syntax_registry.reg_at(
    ObjectVersion.oid, [
        '1.2.840.113556.1.2.76', # objectVersion
    ]
)


class ObjectSID(OctetString, IA5String):
    oid = 'ObjectSID-oid'
    desc = 'Base class for Windows Security Identifiers'
    """
    SID anatomy:
    Byte Position
    0 : SID Structure Revision Level (SRL)
    1 : Number of Subauthority/Relative Identifier
    2-7 : Identifier Authority Value (IAV) [48 bits]
    8-x : Variable number of Subauthority or Relative Identifier (RID)
          [32 bits]
    """

    @staticmethod
    def _sid2sddl(sid):
        srl = ord(sid[0])
        number_sub_id = ord(sid[1])
        iav = struct.unpack('!Q', '\x00\x00'+sid[2:8])[0]
        sub_ids = [
            struct.unpack('<I', sid[8+4*i:12+4*i])[0]
            for i in range(number_sub_id)
        ]
        return 'S-%d-%d-%s' % (
            srl,
            iav,
            '-'.join([str(s) for s in sub_ids]),
        )

    @staticmethod
    def _sddl2sid(sddl):
        sid_components = sddl.split('-')
        srl_byte = chr(int(sid_components[1]))
        number_sub_id_byte = chr(len(sid_components)-3)
        iav_buf = struct.pack('!Q', int(sid_components[2]))[2:]
        result_list = [srl_byte, number_sub_id_byte, iav_buf]
        result_list.extend([
            struct.pack('<I', int(s))
            for s in sid_components[3:]
        ])
        return ''.join(result_list)

    def sanitize(self, attrValue):
        if attrValue:
            return self._sddl2sid(attrValue)
        return ''

    def formValue(self):
        if self._av:
            return unicode(self._sid2sddl(self._av), 'ascii')
        return u''

    def formField(self):
        return IA5String.formField(self)

    def displayValue(self, valueindex=0, commandbutton=False):
        sddl_str = unicode(self._sid2sddl(self._av), 'ascii')
        return '%s<br>%s' % (
            self._app.form.utf2display(sddl_str),
            OctetString.displayValue(self, valueindex, commandbutton),
        )

syntax_registry.reg_at(
    ObjectSID.oid, [
        '1.2.840.113556.1.4.146', # objectSID
        '1.2.840.113556.1.4.609', # sIDHistory
    ]
)


class OtherSID(ObjectSID):
    oid = 'OtherSID-oid'
    desc = 'SID in MS AD which points to another object'
    editable = 0
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

    def displayValue(self, valueindex=0, commandbutton=False):
        sddl_str = unicode(self._sid2sddl(self._av), 'ascii')
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
            OctetString.displayValue(self, valueindex, commandbutton),
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
    oid = 'SAMAccountName-oid'
    desc = 'SAM-Account-Name in MS AD'
    maxLen = 20

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
    oid = 'SAMAccountType-oid'
    desc = 'SAM-Account-Type in MS AD'
    attr_value_dict = {
        u'268435456': u'SAM_GROUP_OBJECT',
        u'268435457': u'SAM_NON_SECURITY_GROUP_OBJECT',
        u'536870912': u'SAM_ALIAS_OBJECT',
        u'536870913': u'SAM_NON_SECURITY_ALIAS_OBJECT',
        u'805306368': u'SAM_NORMAL_USER_ACCOUNT',
        u'805306369': u'SAM_MACHINE_ACCOUNT',
        u'805306370': u'SAM_TRUST_ACCOUNT',
        u'1073741824': u'SAM_APP_BASIC_GROUP',
        u'1073741825': u'SAM_APP_QUERY_GROUP',
        u'2147483647': u'SAM_ACCOUNT_TYPE_MAX',
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
    oid = 'GroupType-oid'
    desc = 'Group-Type in MS AD'
    flag_desc_table = (
        (u'Group created by system', 0x00000001),
        (u'Group with global scope', 0x00000002),
        (u'Group with domain local scope', 0x00000004),
        (u'Group with universal scope', 0x00000008),
        (u'APP_BASIC group Authz Mgr', 0x00000010),
        (u'APP_QUERY group Authz Mgr.', 0x00000020),
        (u'Security group', 0x80000000),
    )

syntax_registry.reg_at(
    GroupType.oid, [
        '1.2.840.113556.1.4.750', # groupType
    ]
)


class DomainRID(SelectList):
    oid = 'DomainRID-oid'
    desc = 'Domain RID in MS AD'
    attr_value_dict = {
        u'9': u'DOMAIN_RID_LOGON',
        u'500': u'DOMAIN_RID_ADMINISTRATOR',
        u'501': u'DOMAIN_RID_GUEST',
        u'502': u'DOMAIN_RID_KRBTGT',
        u'512': u'DOMAIN_RID_ADMINS',
        u'513': u'DOMAIN_RID_USERS',
        u'514': u'DOMAIN_RID_GUESTS',
        u'515': u'DOMAIN_RID_DOMAIN_MEMBERS',
        u'516': u'DOMAIN_RID_DCS',
        u'517': u'DOMAIN_RID_CERT_ADMINS',
        u'518': u'DOMAIN_RID_SCHEMA_ADMINS',
        u'519': u'DOMAIN_RID_ENTERPRISE_ADMINS',
        u'520': u'DOMAIN_RID_POLICY_ADMINS',
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
    oid = 'UserAccountControl-oid'
    flag_desc_table = (
        (u'SCRIPT', 0x0001),
        (u'ACCOUNTDISABLE', 0x0002),
        (u'HOMEDIR_REQUIRED', 0x0008),
        (u'LOCKOUT', 0x0010),
        (u'PASSWD_NOTREQD', 0x0020),
        (u'PASSWD_CANT_CHANGE', 0x0040),
        (u'ENCRYPTED_TEXT_PWD_ALLOWED', 0x0080),
        (u'TEMP_DUPLICATE_ACCOUNT', 0x0100),
        (u'NORMAL_ACCOUNT', 0x0200),
        (u'INTERDOMAIN_TRUST_ACCOUNT', 0x0800),
        (u'WORKSTATION_TRUST_ACCOUNT', 0x1000),
        (u'SERVER_TRUST_ACCOUNT', 0x2000),
        (u'DONT_EXPIRE_PASSWORD', 0x10000),
        (u'MNS_LOGON_ACCOUNT', 0x20000),
        (u'SMARTCARD_REQUIRED', 0x40000),
        (u'TRUSTED_FOR_DELEGATION', 0x80000),
        (u'NOT_DELEGATED', 0x100000),
        (u'USE_DES_KEY_ONLY', 0x200000),
        (u'DONT_REQ_PREAUTH', 0x400000),
        (u'PASSWORD_EXPIRED', 0x800000),
        (u'TRUSTED_TO_AUTH_FOR_DELEGATION', 0x1000000),
        (u'NO_AUTH_DATA_REQUIRED', 0x2000000),
        (u'PARTIAL_SECRETS_ACCOUNT', 0x4000000),
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
    oid = 'SystemFlags-oid'
    flag_desc_table = (
        (u'ADS_SYSTEMFLAG_DISALLOW_DELETE', 0x80000000),
        (u'ADS_SYSTEMFLAG_CONFIG_ALLOW_RENAME', 0x40000000),
        (u'ADS_SYSTEMFLAG_CONFIG_ALLOW_MOVE', 0x20000000),
        (u'ADS_SYSTEMFLAG_CONFIG_ALLOW_LIMITED_MOVE', 0x10000000),
        (u'ADS_SYSTEMFLAG_DOMAIN_DISALLOW_RENAME', 0x08000000),
        (u'ADS_SYSTEMFLAG_DOMAIN_DISALLOW_MOVE', 0x04000000),
        (u'ADS_SYSTEMFLAG_CR_NTDS_NC', 0x00000001),
        (u'ADS_SYSTEMFLAG_CR_NTDS_DOMAIN', 0x00000002),
        (u'ADS_SYSTEMFLAG_ATTR_NOT_REPLICATED', 0x00000001),
        (u'ADS_SYSTEMFLAG_ATTR_IS_CONSTRUCTED', 0x00000004),
        (u'IS_CATEGORY_1_OBJECT', 0x00000010),
        (u'IS_NOT_MOVED_TO_THE_DELETED_OBJECTS', 0x02000000),
    )

syntax_registry.reg_at(
    SystemFlags.oid, [
        '1.2.840.113556.1.4.375', # systemFlags
    ]
)


class SearchFlags(BitArrayInteger):
    """
    http://msdn.microsoft.com/en-us/library/ms679765(VS.85).aspx

     1 (0x00000001)   Create an index for the attribute.
     2 (0x00000002)   Create an index for the attribute in each container.
     4 (0x00000004)   Add this attribute to the Ambiguous Name Resolution (ANR) set. This is used to assist in finding an object when only partial information is given. For example, if the LDAP filter is (ANR=JEFF), the search will find each object where the first name, last name, e-mail address, or other ANR attribute is equal to JEFF. Bit 0 must be set for this index take affect.
     8 (0x00000008)   Preserve this attribute in the tombstone object for deleted objects.
    16 (0x00000010)   Copy the value for this attribute when the object is copied.
    32 (0x00000020)   Supported beginning with Windows Server 2003. Create a tuple index for the attribute. This will improve searches where the wildcard appears at the front of the search string. For example, (sn=*mith).
    64 (0x00000040)   Supported beginning with ADAM. Creates an index to greatly help VLV performance on arbitrary attributes.
    """
    oid = 'SearchFlags-oid'
    flag_desc_table = (
        (u'Indexed', 0x0001),
        (u'Indexed in each container', 0x0002),
        (u'Ambiguous Name Resolution (ANR)', 0x0004),
        (u'Preserve in tombstone object', 0x0008),
        (u'Copy value when object copied', 0x0010),
        (u'tuple index', 0x0020),
        (u'VLV index (Subtree Index in ADAM)', 0x0040),
        (u'CONFIDENTIAL', 0x0080),
        (u'NEVER_AUDIT_VALUE', 0x0100),
        (u'RODC_FILTERED', 0x0200),
        (u'', 0x0400),
        (u'', 0x0800),
    )

syntax_registry.reg_at(
    SearchFlags.oid, [
        '1.2.840.113556.1.2.334', # searchFlags
    ]
)


class LogonHours(OctetString):
    oid = 'LogonHours-oid'
    desc = 'Logon hours'
    dayofweek = ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat')

    @staticmethod
    def _extract_hours(value):
        if not value or len(value) != 21:
            return []
        hour_flags = []
        for eight_hours in value:
            eight_hours_int = ord(eight_hours)
            for i in range(8):
                hour_flags.append({0:'-', 1:'X'}[(eight_hours_int>>i)&1])
        # For whatever reason the list has to be shifted one hour
        return hour_flags

    def sanitize(self, attrValue):
        if not attrValue:
            return ''
        attrValue = attrValue.replace('\r', '').replace('\n', '')
        hour_flags = [
            int(attrValue[i] == 'X')<<i%8
            for i in xrange(len(attrValue))
        ]
        r = [
            chr(sum(hour_flags[i*8:(i+1)*8]))
            for i in xrange(21)
        ]
        return ''.join(r)

    def _validate(self, attrValue):
        return len(attrValue) == 21

    def formValue(self):
        hour_flags = self._extract_hours(self._av)
        if hour_flags:
            day_bits = [
                ''.join(hour_flags[24*day:24*day+24])
                for day in range(7)
            ]
        else:
            day_bits = []
        return u'\r\n'.join(day_bits)

    def formField(self):
        form_value = self.formValue()
        return web2ldap.web.forms.Textarea(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen,
            1,
            None,
            default=form_value,
            rows=7,
            cols=24,
        )

    def displayValue(self, valueindex=0, commandbutton=False):
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
            OctetString.displayValue(self, valueindex, commandbutton),
            '\n'.join(result_lines)
        )


syntax_registry.reg_at(
    LogonHours.oid, [
        '1.2.840.113556.1.4.64', # logonHours
    ]
)


class CountryCode(PropertiesSelectList):
    oid = 'CountryCode-oid'
    desc = 'Numerical country code'
    properties_pathname = os.path.join(
        web2ldapcnf.etc_dir, 'properties', 'attribute_select_countryCode.properties'
    )
    simpleSanitizers = (
        str.strip,
    )

    def __init__(self, app, dn, schema, attrType, attrValue, entry=None):
        self.attr_value_dict[u'0'] = u'-/-'
        SelectList.__init__(self, app, dn, schema, attrType, attrValue, entry)


syntax_registry.reg_at(
    CountryCode.oid, [
        '1.2.840.113556.1.4.25', # countryCode
    ]
)


class InstanceType(BitArrayInteger):
    """
    http://msdn.microsoft.com/library/en-us/adschema/adschema/a_instancetype.asp
    """
    oid = 'InstanceType-oid'
    flag_desc_table = (
        (u'The head of naming context.', 0x00000001),
        (u'This replica is not instantiated.', 0x00000002),
        (u'The object is writable on this directory.', 0x00000004),
        (u'The naming context above this one on this directory is held.', 0x00000008),
        (u'The naming context is in the process of being constructed for the first time via replication.', 0x00000010),
        (u'The naming context is in the process of being removed from the local DSA.', 0x00000020),
    )

syntax_registry.reg_at(
    InstanceType.oid, [
        '1.2.840.113556.1.2.1', # instanceType
    ]
)


class DNWithOctetString(DistinguishedName):
    oid = '1.2.840.113556.1.4.903'
    desc = 'DNWithOctetString'
    octetTag = 'B'
    stringCharset = 'ascii'

    def _validate(self, attrValue):
        try:
            octet_tag, count, octet_string, dn = self._av.split(':')
        except ValueError:
            return False
        try:
            count = int(count)
        except ValueError:
            return False
        try:
            octet_string.decode(self.stringCharset)
        except UnicodeError:
            return False
        dn_u = self._app.ls.uc_decode(dn)[0]
        return len(octet_string) == count and octet_tag.upper() == self.octetTag and is_dn(dn_u)

    def displayValue(self, valueindex=0, commandbutton=False):
        try:
            octet_tag, count, octet_string, dn = self._av.split(':', 3)
        except ValueError:
            return self._app.form.utf2display(self._app.ls.uc_decode(self._av)[0])
        return ':'.join([
            octet_tag,
            count,
            self._app.form.utf2display(self._app.ls.uc_decode(octet_string)[0]),
            self._app.display_dn(
                self._app.ls.uc_decode(dn)[0],
                commandbutton=commandbutton,
            )
        ])


class DNWithString(DNWithOctetString):
    oid = '1.2.840.113556.1.4.904'
    desc = 'DNWithString'
    octetTag = 'S'
    stringCharset = 'utf-8'


class MicrosoftLargeInteger(Integer):
    oid = '1.2.840.113556.1.4.906'
    desc = 'Integer guaranteed to support 64 bit numbers'


class ObjectSecurityDescriptor(OctetString):
    oid = '1.2.840.113556.1.4.907'
    desc = 'Object-Security-Descriptor'


class MsAdGUID(OctetString):
    oid = 'MsAdGUID-oid'
    desc = 'GUID in Active Directory'

    def sanitize(self, attrValue):
        try:
            object_guid_uuid = uuid.UUID(attrValue.replace(':', ''))
        except ValueError:
            return OctetString.sanitize(self, attrValue)
        return object_guid_uuid.bytes

    def displayValue(self, valueindex=0, commandbutton=False):
        object_guid_uuid = uuid.UUID(bytes=self._av)
        return '{%s}<br>%s' % (
            str(object_guid_uuid),
            OctetString.displayValue(self, valueindex=0, commandbutton=False),
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
    oid = 'Interval-oid'
    desc = 'Large integer with timestamp expressed as 100 nanoseconds since 1601-01-01 00:00'

    @staticmethod
    def _delta(attrValue):
        return (long(attrValue)-116444736000000000L)/10000000

    def displayValue(self, valueindex=0, commandbutton=False):
        if self._av == '9223372036854775807':
            return '-1: unlimited/off'
        delta = self._delta(self._av)
        if delta >= 0:
            return '%s (%s)' % (
                MicrosoftLargeInteger.displayValue(self, valueindex, commandbutton),
                self._app.form.utf2display(unicode(strftimeiso8601(time.gmtime(delta)))),
            )
        return self._av


class LockoutTime(Interval):
    oid = 'LockoutTime-oid'
    desc = 'Timestamp of password failure lockout'

    def displayValue(self, valueindex=0, commandbutton=False):
        delta = self._delta(self._av)
        if delta == 0:
            return '%s (not locked)' % (MicrosoftLargeInteger.displayValue(self, valueindex, commandbutton))
        elif delta < 0:
            return MicrosoftLargeInteger.displayValue(self, valueindex, commandbutton)
        return '%s (locked since %s)' % (
            MicrosoftLargeInteger.displayValue(self, valueindex, commandbutton),
            self._app.form.utf2display(unicode(strftimeiso8601(time.gmtime(delta)))),
        )

syntax_registry.reg_at(
    LockoutTime.oid, [
        '1.2.840.113556.1.4.662', # lockoutTime
    ]
)


class DomainFunctionality(SelectList):
    oid = 'DomainFunctionality-oid'
    desc = 'Functional level of domain/forest'

    attr_value_dict = {
        u'': u'',
        u'0': u'Windows 2000',
        u'1': u'Windows 2003 Mixed',
        u'2': u'Windows 2003',
        u'3': u'Windows 2008',
        u'4': u'Windows 2008R2',
        u'5': u'Windows 2012',
    }

syntax_registry.reg_at(
    DomainFunctionality.oid, [
        'domainFunctionality', # no schema information available
        'forestFunctionality', # no schema information available
    ]
)


class DomainControllerFunctionality(SelectList):
    oid = 'DomainControllerFunctionality-oid'
    desc = 'Functional level of domain controller'

    attr_value_dict = {
        u'': u'',
        u'0': u'Windows 2000',
        u'2': u'Windows 2003',
        u'3': u'Windows 2008',
        u'4': u'Windows 2008R2',
        u'5': u'Windows 2012',
        u'6': u'Windows 2012R2',
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
    oid = 'ServerStatus-oid'
    desc = 'Specifies whether the server is enabled or disabled.'
    attr_value_dict = {
        u'': u'',
        u'1': u'enabled',
        u'2': u'disabled',
    }

syntax_registry.reg_at(
    ServerStatus.oid, [
        '1.2.840.113556.1.4.154', # serverStatus
    ]
)


class ObjectClassCategory(SelectList):
    oid = 'ObjectClassCategory-oid'
    desc = 'Category for object class'
    attr_value_dict = {
        u'1': u'STRUCTURAL',
        u'2': u'ABSTRACT',
        u'3': u'AUXILIARY',
    }

syntax_registry.reg_at(
    ObjectClassCategory.oid, [
        '1.2.840.113556.1.2.370', # objectClassCategory
    ]
)


class ClassSchemaLDAPName(DynamicValueSelectList, OID):
    oid = 'ClassSchema-oid'
    desc = 'lDAPDisplayName of the classSchema entry'
    ldap_url = 'ldap:///_?lDAPDisplayName,lDAPDisplayName?one?(objectClass=classSchema)'

    def displayValue(self, valueindex=0, commandbutton=False):
        return OID.displayValue(self, valueindex, commandbutton)

syntax_registry.reg_at(
    ClassSchemaLDAPName.oid, [
        '1.2.840.113556.1.2.351', # auxiliaryClass
        '1.2.840.113556.1.4.198', # systemAuxiliaryClass
        '1.2.840.113556.1.2.8',   # possSuperiors
        '1.2.840.113556.1.4.195', # systemPossSuperiors
    ]
)


class AttributeSchemaLDAPName(DynamicValueSelectList, OID):
    oid = 'AttributeSchema-oid'
    desc = 'lDAPDisplayName of the classSchema entry'
    ldap_url = 'ldap:///_?lDAPDisplayName,lDAPDisplayName?one?(objectClass=attributeSchema)'

    def displayValue(self, valueindex=0, commandbutton=False):
        return OID.displayValue(self, valueindex, commandbutton)

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
    oid = 'PwdProperties-oid'
    flag_desc_table = (
        (u'DOMAIN_PASSWORD_COMPLEX', 1),
        (u'DOMAIN_PASSWORD_NO_ANON_CHANGE', 2),
        (u'DOMAIN_PASSWORD_NO_CLEAR_CHANGE', 4),
        (u'DOMAIN_LOCKOUT_ADMINS', 8),
        (u'DOMAIN_PASSWORD_STORE_CLEARTEXT', 16),
        (u'DOMAIN_REFUSE_PASSWORD_CHANGE', 32)
    )

syntax_registry.reg_at(
    PwdProperties.oid, [
        '1.2.840.113556.1.4.93', # pwdProperties
    ]
)


class MsDSSupportedEncryptionTypes(BitArrayInteger):
    oid = 'MsDSSupportedEncryptionTypes-oid'
    flag_desc_table = (
        (u'KERB_ENCTYPE_DES_CBC_CRC', 0x00000001),
        (u'KERB_ENCTYPE_DES_CBC_MD5', 0x00000002),
        (u'KERB_ENCTYPE_RC4_HMAC_MD5', 0x00000004),
        (u'KERB_ENCTYPE_AES128_CTS_HMAC_SHA1_96', 0x00000008),
        (u'KERB_ENCTYPE_AES256_CTS_HMAC_SHA1_96', 0x00000010),
    )

syntax_registry.reg_at(
    MsDSSupportedEncryptionTypes.oid, [
        '1.2.840.113556.1.4.1963', # msDS-SupportedEncryptionTypes
    ]
)


class ShowInAddressBook(DynamicDNSelectList):
    oid = 'ShowInAddressBook-oid'
    desc = 'DN of the addressbook container entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=addressBookContainer)'

syntax_registry.reg_at(
    ShowInAddressBook.oid, [
        '1.2.840.113556.1.4.644', # showInAddressBook
    ]
)


class MsDSReplAttributeMetaData(XmlValue):
    oid = 'MsDSReplAttributeMetaData-oid'
    editable = 0

    def _validate(self, attrValue):
        return attrValue.endswith('\n\x00') and XmlValue._validate(self, attrValue[:-1])

syntax_registry.reg_at(
    MsDSReplAttributeMetaData.oid, [
        '1.2.840.113556.1.4.1707',   # msDS-ReplAttributeMetaData
    ]
)


class MsSFU30NisDomain(DynamicValueSelectList):
    oid = 'MsSFU30NisDomain-oid'
    desc = 'Name of NIS domain controlled by MS SFU'
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
