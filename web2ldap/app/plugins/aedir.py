# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for

Æ-DIR -- Yet another LDAP user and systems management
"""

# Python's standard lib
import re
import time
import socket
from typing import List

# from ldap0 package
import ldap0
import ldap0.filter
from ldap0.pw import random_string
from ldap0.controls.readentry import PreReadControl
from ldap0.controls.deref import DereferenceControl
from ldap0.filter import compose_filter, map_filter_parts
from ldap0.dn import DNObj

import web2ldapcnf

from web2ldap.web.forms import HiddenInput
import web2ldap.ldaputil
import web2ldap.app.searchform
import web2ldap.app.plugins.inetorgperson
import web2ldap.app.plugins.sudoers
import web2ldap.app.plugins.ppolicy
from web2ldap.app.plugins.nis import UidNumber, GidNumber, MemberUID, Shell
from web2ldap.app.plugins.inetorgperson import DisplayNameInetOrgPerson
from web2ldap.app.plugins.groups import GroupEntryDN
from web2ldap.app.plugins.oath import OathHOTPToken
from web2ldap.app.plugins.opensshlpk import SshPublicKey
from web2ldap.app.plugins.posixautogen import HomeDirectory
from web2ldap.app.schema.syntaxes import \
    ComposedAttribute, \
    DirectoryString, \
    DistinguishedName, \
    DNSDomain, \
    DerefDynamicDNSelectList, \
    DynamicValueSelectList, \
    IA5String, \
    Integer, \
    NotAfter, \
    NotBefore, \
    RFC822Address, \
    SelectList, \
    syntax_registry


# OID arc for AE-DIR, see stroeder.com-oid-macros.schema
AE_OID_PREFIX = '1.3.6.1.4.1.5427.1.389.100'

# OIDs of AE-DIR's structural object classes
AE_USER_OID = AE_OID_PREFIX+'.6.2'
AE_GROUP_OID = AE_OID_PREFIX+'.6.1'
AE_MAILGROUP_OID = AE_OID_PREFIX+'.6.27'
AE_SRVGROUP_OID = AE_OID_PREFIX+'.6.13'
AE_SUDORULE_OID = AE_OID_PREFIX+'.6.7'
AE_HOST_OID = AE_OID_PREFIX+'.6.6.1'
AE_SERVICE_OID = AE_OID_PREFIX+'.6.4'
AE_ZONE_OID = AE_OID_PREFIX+'.6.20'
AE_PERSON_OID = AE_OID_PREFIX+'.6.8'
AE_TAG_OID = AE_OID_PREFIX+'.6.24'
AE_POLICY_OID = AE_OID_PREFIX+'.6.26'
AE_AUTHCTOKEN_OID = AE_OID_PREFIX+'.6.25'
AE_DEPT_OID = AE_OID_PREFIX+'.6.29'
AE_CONTACT_OID = AE_OID_PREFIX+'.6.5'
AE_LOCATION_OID = AE_OID_PREFIX+'.6.35'
AE_NWDEVICE_OID = AE_OID_PREFIX+'.6.6.2'


syntax_registry.reg_at(
    DNSDomain.oid, [
        AE_OID_PREFIX+'.4.10', # aeFqdn
    ]
)


def ae_validity_filter(secs=None):
    if secs is None:
        secs = time.time()
    return (
        '(&'
          '(|'
            '(!(aeNotBefore=*))'
            '(aeNotBefore<={0})'
          ')'
          '(|'
            '(!(aeNotAfter=*))'
            '(aeNotAfter>={0})'
          ')'
        ')'
    ).format(
        time.strftime('%Y%m%d%H%M%SZ', time.gmtime(secs))
    )


class AEObjectUtil:

    def _zone_entry(self, attrlist=None):
        zone_dn = 'cn={0},{1}'.format(
            self._get_zone_name(),
            self._app.naming_context,
        )
        try:
            zone = self._app.ls.l.read_s(
                zone_dn,
                attrlist=attrlist,
                filterstr='(objectClass=aeZone)',
            ) or {}
        except ldap0.LDAPError:
            zone = {}
        return zone.entry_s

    def _get_zone_dn(self) -> str:
        return str(self.dn.slice(None, -len(DNObj.from_str(self._app.naming_context))-1))

    def _get_zone_name(self) -> str:
        return self.dn[-len(DNObj.from_str(self._app.naming_context))-1][0][1]


class AEHomeDirectory(HomeDirectory):
    oid: str = 'AEHomeDirectory-oid'
    # all valid directory prefixes for attribute 'homeDirectory'
    # but without trailing slash
    homeDirectoryPrefixes = (
        '/home',
    )
    homeDirectoryHidden = '-/-'

    def _validate(self, attrValue: bytes) -> bool:
        av_u = self._app.ls.uc_decode(attrValue)[0]
        if attrValue == self.homeDirectoryHidden:
            return True
        for prefix in self.homeDirectoryPrefixes:
            if av_u.startswith(prefix):
                uid = self._app.ls.uc_decode(self._entry.get('uid', [b''])[0])[0]
                return av_u.endswith(uid)
        return False

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if attrValues == [self.homeDirectoryHidden]:
            return attrValues
        if 'uid' in self._entry:
            uid = self._app.ls.uc_decode(self._entry['uid'][0])[0]
        else:
            uid = ''
        if attrValues:
            av_u = self._app.ls.uc_decode(attrValues[0])[0]
            for prefix in self.homeDirectoryPrefixes:
                if av_u.startswith(prefix):
                    break
            else:
                prefix = self.homeDirectoryPrefixes[0]
        else:
            prefix = self.homeDirectoryPrefixes[0]
        return [self._app.ls.uc_encode('/'.join((prefix, uid)))[0]]

    def formField(self) -> str:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen,
            self.maxValues,
            None,
            default=self.formValue()
        )
        input_field.charset = self._app.form.accept_charset
        return input_field

syntax_registry.reg_at(
    AEHomeDirectory.oid, [
        '1.3.6.1.1.1.1.3', # homeDirectory
    ],
    structural_oc_oids=[AE_USER_OID, AE_SERVICE_OID], # aeUser and aeService
)


class AEUIDNumber(UidNumber):
    oid: str = 'AEUIDNumber-oid'
    desc: str = 'numeric Unix-UID'

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        return self._entry.get('gidNumber', [''])

    def formField(self) -> str:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues, None,
            default=self.formValue()
        )
        input_field.charset = self._app.form.accept_charset
        return input_field

syntax_registry.reg_at(
    AEUIDNumber.oid, [
        '1.3.6.1.1.1.1.0', # uidNumber
    ],
    structural_oc_oids=[
        AE_USER_OID,    # aeUser
        AE_SERVICE_OID, # aeService
    ],
)


class AEGIDNumber(GidNumber):
    oid: str = 'AEGIDNumber-oid'
    desc: str = 'numeric Unix-GID'
    minNewValue = 30000
    maxNewValue = 49999
    id_pool_dn = None

    def _get_id_pool_dn(self) -> str:
        """
        determine which ID pool entry to use
        """
        return self.id_pool_dn or str(self._app.naming_context)

    def _get_next_gid(self) -> int:
        """
        consumes next ID by sending MOD_INCREMENT modify operation with
        pre-read entry control
        """
        prc = PreReadControl(criticality=True, attrList=[self._at])
        ldap_result = self._app.ls.l.modify_s(
            self._get_id_pool_dn(),
            [(ldap0.MOD_INCREMENT, self.at_b, [b'1'])],
            req_ctrls=[prc],
        )
        return int(ldap_result.ctrls[0].res.entry_s[self._at][0])

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if attrValues and attrValues[0]:
            return attrValues
        # first try to re-read gidNumber from existing entry
        try:
            ldap_result = self._app.ls.l.read_s(
                self._dn,
                attrlist=[self._at],
                filterstr='({0}=*)'.format(self._at),
            )
        except (
                ldap0.NO_SUCH_OBJECT,
                ldap0.INSUFFICIENT_ACCESS,
            ):
            # search failed => ignore
            pass
        else:
            if ldap_result:
                return ldap_result.entry_s[self._at]
        # return next ID from pool entry
        return [str(self._get_next_gid()).encode('ascii')]

    def formValue(self) -> str:
        return Integer.formValue(self)

    def formField(self) -> str:
        return Integer.formField(self)

syntax_registry.reg_at(
    AEGIDNumber.oid, [
        '1.3.6.1.1.1.1.1', # gidNumber
    ],
    structural_oc_oids=[
        AE_USER_OID,    # aeUser
        AE_GROUP_OID,   # aeGroup
        AE_SERVICE_OID, # aeService
    ],
)


class AEUid(IA5String):
    oid: str = 'AEUid-oid'
    simpleSanitizers = (
        bytes.strip,
        bytes.lower,
    )


class AEUserUid(AEUid):
    """
    Class for auto-generating values for aeUser -> uid
    """
    oid: str = 'AEUserUid-oid'
    desc: str = 'AE-DIR: User name'
    maxValues = 1
    minLen: int = 4
    maxLen: int = 4
    maxCollisionChecks: int = 15
    UID_LETTERS = 'abcdefghijklmnopqrstuvwxyz'
    reobj = re.compile('^%s$' % (UID_LETTERS))
    genLen = 4
    simpleSanitizers = (
        bytes.strip,
        bytes.lower,
    )

    def __init__(self, app, dn: str, schema, attrType: str, attrValue: bytes, entry=None):
        IA5String.__init__(self, app, dn, schema, attrType, attrValue, entry=entry)

    def _gen_uid(self):
        gen_collisions = 0
        while gen_collisions < self.maxCollisionChecks:
            # generate new random UID candidate
            uid_candidate = random_string(alphabet=self.UID_LETTERS, length=self.genLen)
            # check whether UID candidate already exists
            uid_result = self._app.ls.l.search_s(
                str(self._app.naming_context),
                ldap0.SCOPE_SUBTREE,
                '(uid=%s)' % (ldap0.filter.escape_str(uid_candidate)),
                attrlist=['1.1'],
            )
            if not uid_result:
                return uid_candidate
            gen_collisions += 1
        raise web2ldap.app.core.ErrorExit(
            u'Gave up generating new unique <em>uid</em> after %d attempts.' % (gen_collisions)
        )
        # end of _gen_uid()

    def formValue(self) -> str:
        form_value = IA5String.formValue(self)
        if not self._av:
            form_value = self._gen_uid()
        return form_value

    def formField(self) -> str:
        return HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues, None,
            default=self.formValue()
        )

    def sanitize(self, attrValue: bytes) -> bytes:
        return attrValue.strip().lower()

syntax_registry.reg_at(
    AEUserUid.oid, [
        '0.9.2342.19200300.100.1.1', # uid
    ],
    structural_oc_oids=[
        AE_USER_OID, # aeUser
    ],
)


class AEServiceUid(AEUid):
    oid: str = 'AEServiceUid-oid'

syntax_registry.reg_at(
    AEServiceUid.oid, [
        '0.9.2342.19200300.100.1.1', # uid
    ],
    structural_oc_oids=[
        AE_SERVICE_OID, # aeService
    ],
)


class AETicketId(IA5String):
    oid: str = 'AETicketId-oid'
    desc: str = 'AE-DIR: Ticket no. related to last change of entry'
    simpleSanitizers = (
        bytes.upper,
        bytes.strip,
    )

syntax_registry.reg_at(
    AETicketId.oid, [
        AE_OID_PREFIX+'.4.3', # aeTicketId
    ]
)


class AEZoneDN(DerefDynamicDNSelectList):
    oid: str = 'AEZoneDN-oid'
    desc: str = 'AE-DIR: Zone'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeZone)(aeStatus=0))'
    ref_attrs = (
        (None, u'Same zone', None, u'Search all groups constrained to same zone'),
    )

syntax_registry.reg_at(
    AEZoneDN.oid, [
        AE_OID_PREFIX+'.4.36', # aeMemberZone
    ]
)


class AEHost(DerefDynamicDNSelectList):
    oid: str = 'AEHost-oid'
    desc: str = 'AE-DIR: Host'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///_?host?sub?(&(objectClass=aeHost)(aeStatus=0))'
    ref_attrs = (
        (None, u'Same host', None, u'Search all services running on same host'),
    )

syntax_registry.reg_at(
    AEHost.oid, [
        AE_OID_PREFIX+'.4.28', # aeHost
    ]
)


class AENwDevice(DerefDynamicDNSelectList):
    oid: str = 'AENwDevice-oid'
    desc: str = 'AE-DIR: network interface'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///..?cn?sub?(&(objectClass=aeNwDevice)(aeStatus=0))'
    ref_attrs = (
        (None, u'Siblings', None, u'Search sibling network devices'),
    )

    def _search_root(self) -> str:
        if self._dn.startswith('host='):
            return self._dn
        return DerefDynamicDNSelectList._search_root(self)

    def _filterstr(self):
        orig_filter = DerefDynamicDNSelectList._filterstr(self)
        try:
            dev_name = self._app.ls.uc_decode(self._entry['cn'][0])[0]
        except (KeyError, IndexError):
            result_filter = orig_filter
        else:
            result_filter = '(&{0}(!(cn={1})))'.format(orig_filter, dev_name)
        return result_filter

syntax_registry.reg_at(
    AENwDevice.oid, [
        AE_OID_PREFIX+'.4.34', # aeNwDevice
    ]
)


class AEGroupMember(DerefDynamicDNSelectList, AEObjectUtil):
    oid: str = 'AEGroupMember-oid'
    desc: str = 'AE-DIR: Member of a group'
    input_fallback = False # no fallback to normal input field
    ldap_url = (
        'ldap:///_?displayName?sub?'
        '(&(|(objectClass=aeUser)(objectClass=aeService))(aeStatus=0))'
    )
    deref_person_attrs = ('aeDept', 'aeLocation')

    def _zone_filter(self):
        member_zones = [
            self._app.ls.uc_decode(mezo)[0]
            for mezo in self._entry.get('aeMemberZone', [])
            if mezo
        ]
        if member_zones:
            member_zone_filter = compose_filter(
                '|',
                map_filter_parts('entryDN:dnSubordinateMatch:', member_zones),
            )
        else:
            member_zone_filter = ''
        return member_zone_filter

    def _deref_person_attrset(self):
        result = {}
        for attr_type in self.deref_person_attrs:
            if attr_type in self._entry and list(filter(None, self._entry[attr_type])):
                result[attr_type] = set(self._entry[attr_type])
        return result

    def _filterstr(self):
        return '(&{0}{1})'.format(
            DerefDynamicDNSelectList._filterstr(self),
            self._zone_filter(),
        )

    def _get_attr_value_dict(self):
        deref_person_attrset = self._deref_person_attrset()
        if not deref_person_attrset:
            return DerefDynamicDNSelectList._get_attr_value_dict(self)
        if deref_person_attrset:
            srv_ctrls = [DereferenceControl(True, {'aePerson': deref_person_attrset.keys()})]
        else:
            srv_ctrls = None
        # Use the existing LDAP connection as current user
        attr_value_dict = SelectList._get_attr_value_dict(self)
        try:
            ldap_result = self._app.ls.l.search_s(
                self._search_root(),
                self.lu_obj.scope or ldap0.SCOPE_SUBTREE,
                filterstr=self._filterstr(),
                attrlist=self.lu_obj.attrs+['description'],
                req_ctrls=srv_ctrls,
            )
            for dn, entry, controls in ldap_result:
                if dn is None:
                    # ignore search continuations
                    continue
                # process dn and entry
                if controls:
                    deref_control = controls[0]
                    _, deref_entry = deref_control.derefRes['aePerson'][0]
                elif deref_person_attrset:
                    # if we have constrained attributes, no deref response control
                    # means constraint not valid
                    continue
                # check constrained values here
                valid = True
                for attr_type, attr_values in deref_person_attrset.items():
                    if attr_type not in deref_entry or \
                       deref_entry[attr_type][0] not in attr_values:
                        valid = False
                if valid:
                    option_value = self._app.ls.uc_decode(dn)[0]
                    try:
                        option_text = self._app.ls.uc_decode(entry['displayName'][0])[0]
                    except KeyError:
                        option_text = option_value
                    try:
                        entry_desc = entry['description'][0]
                    except KeyError:
                        option_title = option_value
                    else:
                        option_title = self._app.ls.uc_decode(entry_desc)[0]
                    attr_value_dict[option_value] = (option_text, option_title)
        except (
                ldap0.NO_SUCH_OBJECT,
                ldap0.SIZELIMIT_EXCEEDED,
                ldap0.TIMELIMIT_EXCEEDED,
                ldap0.PARTIAL_RESULTS,
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.CONSTRAINT_VIOLATION,
                ldap0.REFERRAL,
            ):
            pass
        return attr_value_dict # _get_attr_value_dict()

    def _validate(self, attrValue: bytes) -> bool:
        if 'memberURL' in self._entry:
            # reduce to simple DN syntax check for dynamic groups
            return DistinguishedName._validate(self, attrValue)
        return SelectList._validate(self, attrValue)

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if int(self._entry['aeStatus'][0]) == 2:
            return []
        return DerefDynamicDNSelectList.transmute(self, attrValues)

syntax_registry.reg_at(
    AEGroupMember.oid, [
        '2.5.4.31', # member
    ],
    structural_oc_oids=[
        AE_GROUP_OID, # aeGroup
    ],
)


class AEMailGroupMember(AEGroupMember):
    oid: str = 'AEMailGroupMember-oid'
    desc: str = 'AE-DIR: Member of a mail group'
    input_fallback = False # no fallback to normal input field
    ldap_url = (
        'ldap:///_?displayName?sub?'
        '(&(|(objectClass=inetLocalMailRecipient)(objectClass=aeContact))(mail=*)(aeStatus=0))'
    )

syntax_registry.reg_at(
    AEMailGroupMember.oid, [
        '2.5.4.31', # member
    ],
    structural_oc_oids=[
        AE_MAILGROUP_OID, # aeMailGroup
    ],
)


class AEMemberUid(MemberUID):
    oid: str = 'AEMemberUid-oid'
    desc: str = 'AE-DIR: username (uid) of member of a group'
    ldap_url = None
    showValueButton = False
    reobj = AEUserUid.reobj

    def _member_uids_from_member(self):
        return [
            dn[4:].split(b',')[0]
            for dn in self._entry.get('member', [])
        ]

    def _validate(self, attrValue: bytes) -> bool:
        """
        Because AEMemberUid.transmute() always resets all attribute values it's
        ok to not validate values thoroughly
        """
        return IA5String._validate(self, attrValue)

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if 'member' not in self._entry:
            return []
        if int(self._entry['aeStatus'][0]) == 2:
            return []
        return list(filter(None, self._member_uids_from_member()))

    def formValue(self) -> str:
        return u''

    def formField(self) -> str:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues, None,
        )
        input_field.charset = self._app.form.accept_charset
        input_field.set_default(self.formValue())
        return input_field

syntax_registry.reg_at(
    AEMemberUid.oid, [
        '1.3.6.1.1.1.1.12', # memberUid
    ],
    structural_oc_oids=[
        AE_GROUP_OID, # aeGroup
    ],
)


class AEGroupDN(DerefDynamicDNSelectList):
    oid: str = 'AEGroupDN-oid'
    desc: str = 'AE-DIR: DN of user group entry'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///_??sub?(&(|(objectClass=aeGroup)(objectClass=aeMailGroup))(aeStatus=0))'
    ref_attrs = (
        ('memberOf', u'Members', None, u'Search all member entries of this user group'),
    )

    def display(self, valueindex=0, commandbutton=False) -> str:
        group_dn = DNObj.from_str(self.av_u)
        group_cn = group_dn[0][0][1]
        r = [
            'cn=<strong>{0}</strong>,{1}'.format(
                self._app.form.utf2display(group_cn),
                self._app.form.utf2display(str(group_dn.parent())),
            )
        ]
        if commandbutton:
            r.extend(self._additional_links())
        return web2ldapcnf.command_link_separator.join(r)

syntax_registry.reg_at(
    AEGroupDN.oid, [
        '1.2.840.113556.1.2.102', # memberOf
    ],
    structural_oc_oids=[
        AE_USER_OID,    # aeUser
        AE_SERVICE_OID, # aeService
        AE_CONTACT_OID, # aeContact
    ],
)


class AEZoneAdminGroupDN(AEGroupDN):
    oid: str = 'AEZoneAdminGroupDN-oid'
    desc: str = 'AE-DIR: DN of zone admin group entry'
    ldap_url = (
      'ldap:///_??sub?'
      '(&'
        '(objectClass=aeGroup)'
        '(aeStatus=0)'
        '(cn=*-zone-admins)'
        '(!'
          '(|'
            '(cn:dn:=pub)'
            '(cn:dn:=ae)'
          ')'
        ')'
      ')'
    )

syntax_registry.reg_at(
    AEZoneAdminGroupDN.oid, [
        AE_OID_PREFIX+'.4.31', # aeZoneAdmins
        AE_OID_PREFIX+'.4.33', # aePasswordAdmins
    ]
)


class AEZoneAuditorGroupDN(AEGroupDN):
    oid: str = 'AEZoneAuditorGroupDN-oid'
    desc: str = 'AE-DIR: DN of zone auditor group entry'
    ldap_url = (
      'ldap:///_??sub?'
      '(&'
        '(objectClass=aeGroup)'
        '(aeStatus=0)'
        '(|'
          '(cn=*-zone-admins)'
          '(cn=*-zone-auditors)'
        ')'
        '(!'
          '(|'
            '(cn:dn:=pub)'
            '(cn:dn:=ae)'
          ')'
        ')'
      ')'
    )

syntax_registry.reg_at(
    AEZoneAuditorGroupDN.oid, [
        AE_OID_PREFIX+'.4.32',  # aeZoneAuditors
    ]
)


class AESrvGroupRightsGroupDN(AEGroupDN):
    oid: str = 'AESrvGroupRightsGroupDN-oid'
    desc: str = 'AE-DIR: DN of user group entry'
    ldap_url = (
      'ldap:///_??sub?'
      '(&'
        '(objectClass=aeGroup)'
        '(aeStatus=0)'
        '(!'
          '(|'
            '(cn:dn:=pub)'
            '(cn=*-zone-admins)'
            '(cn=*-zone-auditors)'
          ')'
        ')'
      ')'
    )

syntax_registry.reg_at(
    AESrvGroupRightsGroupDN.oid, [
        AE_OID_PREFIX+'.4.4',  # aeLoginGroups
        AE_OID_PREFIX+'.4.6',  # aeSetupGroups
        AE_OID_PREFIX+'.4.7',  # aeLogStoreGroups
        AE_OID_PREFIX+'.4.37', # aeABAccessGroups
    ]
)


class AEDisplayNameGroups(AESrvGroupRightsGroupDN):
    oid: str = 'AEDisplayNameGroups-oid'
    desc: str = 'AE-DIR: DN of visible user group entry'
    ldap_url = (
      'ldap:///_??sub?'
      '(&'
        '(|'
          '(objectClass=aeGroup)'
          '(objectClass=aeMailGroup)'
        ')'
        '(aeStatus=0)'
        '(!'
          '(|'
            '(cn:dn:=pub)'
            '(cn=*-zone-admins)'
            '(cn=*-zone-auditors)'
          ')'
        ')'
      ')'
    )

syntax_registry.reg_at(
    AEDisplayNameGroups.oid, [
        AE_OID_PREFIX+'.4.30', # aeDisplayNameGroups
    ]
)


class AEVisibleGroups(AEDisplayNameGroups):
    oid: str = 'AEVisibleGroups-oid'
    desc: str = 'AE-DIR: DN of visible user group entry'
    always_add_groups = (
        'aeLoginGroups',
        'aeDisplayNameGroups',
    )

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        attrValues = set(attrValues)
        for attr_type in self.always_add_groups:
            attrValues.update(self._entry.get(attr_type, []))
        return list(attrValues)

syntax_registry.reg_at(
    AEVisibleGroups.oid, [
        AE_OID_PREFIX+'.4.20', # aeVisibleGroups
    ]
)


class AESameZoneObject(DerefDynamicDNSelectList, AEObjectUtil):
    oid: str = 'AESameZoneObject-oid'
    desc: str = 'AE-DIR: DN of referenced aeSrvGroup entry this is proxy for'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeObject)(aeStatus=0))'

    def _search_root(self):
        return self._get_zone_dn()


class AESrvGroup(AESameZoneObject):
    oid: str = 'AESrvGroup-oid'
    desc: str = 'AE-DIR: DN of referenced aeSrvGroup entry'
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0)(!(aeProxyFor=*)))'

    def _filterstr(self):
        filter_str = self.lu_obj.filterstr or '(objectClass=*)'
        return '(&%s(!(entryDN=%s)))' % (
            filter_str,
            ldap0.filter.escape_str(str(self.dn.parent())),
        )

syntax_registry.reg_at(
    AESrvGroup.oid, [
        AE_OID_PREFIX+'.4.27', # aeSrvGroup
    ]
)


class AERequires(DerefDynamicDNSelectList):
    oid: str = 'AERequires-oid'
    desc: str = 'AE-DIR: DN of required aeSrvGroup'
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0))'
    ref_attrs = (
        (
            'aeRequires', u'Same require', None, 'aeSrvGroup',
            u'Search all service groups depending on this service group.'
        ),
    )


syntax_registry.reg_at(
    AERequires.oid, [
        AE_OID_PREFIX+'.4.48', # aeSrvGroup
    ]
)


class AEProxyFor(AESameZoneObject, AEObjectUtil):
    oid: str = 'AEProxyFor-oid'
    desc: str = 'AE-DIR: DN of referenced aeSrvGroup entry this is proxy for'
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0)(!(aeProxyFor=*)))'

    def _filterstr(self):
        filter_str = self.lu_obj.filterstr or '(objectClass=*)'
        return '(&%s(!(entryDN=%s)))' % (
            filter_str,
            self._dn,
        )

syntax_registry.reg_at(
    AEProxyFor.oid, [
        AE_OID_PREFIX+'.4.25', # aeProxyFor
    ]
)


class AETag(DynamicValueSelectList):
    oid: str = 'AETag-oid'
    desc: str = 'AE-DIR: cn of referenced aeTag entry'
    ldap_url = 'ldap:///_?cn,cn?sub?(&(objectClass=aeTag)(aeStatus=0))'

syntax_registry.reg_at(
    AETag.oid, [
        AE_OID_PREFIX+'.4.24', # aeTag
    ]
)


class AEEntryDNAEPerson(DistinguishedName):
    oid: str = 'AEEntryDNAEPerson-oid'
    desc: str = 'AE-DIR: entryDN of aePerson entry'
    ref_attrs = (
        ('manager', u'Manages', None, u'Search all entries managed by this person'),
        (
            'aePerson', u'Users', None, 'aeUser',
            u'Search all personal AE-DIR user accounts (aeUser entries) of this person.'
        ),
        (
            'aeOwner', u'Devices', None, 'aeDevice',
            u'Search all devices (aeDevice entries) assigned to this person.'
        ),
    )

syntax_registry.reg_at(
    AEEntryDNAEPerson.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_PERSON_OID, # aePerson
    ],
)


class AEEntryDNAEUser(DistinguishedName):
    oid: str = 'AEEntryDNAEUser-oid'
    desc: str = 'AE-DIR: entryDN of aeUser entry'

    def _additional_links(self):
        r = DistinguishedName._additional_links(self)
        if self._app.audit_context:
            r.append(self._app.anchor(
                'search', 'Activity',
                (
                    ('dn', self._app.audit_context),
                    ('searchform_mode', u'adv'),
                    ('search_attr', u'objectClass'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', u'auditObject'),
                    ('search_attr', u'reqAuthzID'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', self.av_u),
                ),
                title=u'Search modifications made by %s in accesslog DB' % (self.av_u),
            ))
        return r

syntax_registry.reg_at(
    AEEntryDNAEUser.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_USER_OID, # aeUser
    ],
)


class AEEntryDNAEHost(DistinguishedName):
    oid: str = 'AEEntryDNAEHost-oid'
    desc: str = 'AE-DIR: entryDN of aeUser entry'
    ref_attrs = (
        ('aeHost', u'Services', None, u'Search all services running on this host'),
    )

    def _additional_links(self):
        aesrvgroup_filter = u''.join([
            u'(aeSrvGroup=%s)' % av.decode(self._app.ls.charset)
            for av in self._entry.get('aeSrvGroup', [])
        ])
        r = DistinguishedName._additional_links(self)
        r.extend([
            self._app.anchor(
                'search', 'Siblings',
                (
                    ('dn', self._dn),
                    ('search_root', self._app.naming_context),
                    ('searchform_mode', u'exp'),
                    (
                        'filterstr',
                        (
                            u'(&(|(objectClass=aeHost)(objectClass=aeService))'
                            u'(|(entryDN:dnSubordinateMatch:=%s)%s))'
                        ) % (
                            ldap0.filter.escape_str(str(self.dn.parent())),
                            aesrvgroup_filter,
                        )
                    ),
                ),
                title=(
                    u'Search all host entries which are member in '
                    u'at least one common server group(s) with this host'
                ),
            ),
        ])
        return r

syntax_registry.reg_at(
    AEEntryDNAEHost.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_HOST_OID, # aeHost
    ],
)


class AEEntryDNAEZone(DistinguishedName):
    oid: str = 'AEEntryDNAEZone-oid'
    desc: str = 'AE-DIR: entryDN of aeZone entry'

    def _additional_links(self):
        r = DistinguishedName._additional_links(self)
        if self._app.audit_context:
            r.append(self._app.anchor(
                'search', 'Audit all',
                (
                    ('dn', self._app.audit_context),
                    ('searchform_mode', u'adv'),
                    ('search_attr', u'objectClass'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', u'auditObject'),
                    ('search_attr', u'reqDN'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_DN_SUBTREE),
                    ('search_string', self.av_u),
                ),
                title=u'Search all audit log entries for sub-tree %s' % (self.av_u),
            ))
            r.append(self._app.anchor(
                'search', 'Audit writes',
                (
                    ('dn', self._app.audit_context),
                    ('searchform_mode', u'adv'),
                    ('search_attr', u'objectClass'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', u'auditObject'),
                    ('search_attr', u'reqDN'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_DN_SUBTREE),
                    ('search_string', self.av_u),
                ),
                title=u'Search audit log entries for write operation within sub-tree %s' % (
                    self.av_u
                ),
            ))
        return r

syntax_registry.reg_at(
    AEEntryDNAEZone.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_ZONE_OID, # aeZone
    ],
)


class AEEntryDNAEMailGroup(GroupEntryDN):
    oid: str = 'AEEntryDNAEMailGroup-oid'
    desc: str = 'AE-DIR: entryDN of aeGroup entry'
    ref_attrs = (
        ('memberOf', u'Members', None, u'Search all member entries of this mail group'),
        ('aeVisibleGroups', u'Visible', None, u'Search all server/service groups (aeSrvGroup)\non which this mail group is visible'),
    )

syntax_registry.reg_at(
    AEEntryDNAEMailGroup.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_MAILGROUP_OID, # aeMailGroup
    ],
)


class AEEntryDNAEGroup(GroupEntryDN):
    oid: str = 'AEEntryDNAEGroup-oid'
    desc: str = 'AE-DIR: entryDN of aeGroup entry'
    ref_attrs = (
        ('memberOf', u'Members', None, u'Search all member entries of this user group'),
        ('aeLoginGroups', u'Login', None, u'Search all server/service groups (aeSrvGroup)\non which this user group has login right'),
        ('aeLogStoreGroups', u'View Logs', None, u'Search all server/service groups (aeSrvGroup)\non which this user group has log view right'),
        ('aeSetupGroups', u'Setup', None, u'Search all server/service groups (aeSrvGroup)\non which this user group has setup/installation rights'),
        ('aeVisibleGroups', u'Visible', None, u'Search all server/service groups (aeSrvGroup)\non which this user group is at least visible'),
    )

    def _additional_links(self):
        aegroup_cn = self._entry['cn'][0].decode(self._app.ls.charset)
        ref_attrs = list(AEEntryDNAEGroup.ref_attrs)
        if aegroup_cn.endswith('zone-admins'):
            ref_attrs.extend([
                (
                    'aeZoneAdmins', u'Zone Admins', None,
                    u'Search all zones (aeZone)\nfor which members of this user group act as zone admins'
                ),
                (
                    'aePasswordAdmins', u'Password Admins', None,
                    u'Search all zones (aeZone)\nfor which members of this user group act as password admins'
                ),
            ])
        if aegroup_cn.endswith('zone-auditors') or aegroup_cn.endswith('zone-admins'):
            ref_attrs.append(
                (
                    'aeZoneAuditors', u'Zone Auditors', None,
                    u'Search all zones (aeZone)\nfor which members of this user group act as zone auditors'
                ),
            )
        self.ref_attrs = tuple(ref_attrs)
        r = DistinguishedName._additional_links(self)
        r.append(self._app.anchor(
            'search', 'SUDO rules',
            (
                ('dn', self._dn),
                ('search_root', self._app.naming_context),
                ('searchform_mode', u'adv'),
                ('search_attr', u'sudoUser'),
                ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                ('search_string', u'%'+self._entry['cn'][0].decode(self._app.ls.charset)),
            ),
            title=u'Search for SUDO rules\napplicable with this user group',
        ))
        return r

syntax_registry.reg_at(
    AEEntryDNAEGroup.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_GROUP_OID, # aeGroup
    ],
)


class AEEntryDNAESrvGroup(DistinguishedName):
    oid: str = 'AEEntryDNAESrvGroup-oid'
    desc: str = 'AE-DIR: entryDN'
    ref_attrs = (
        ('aeProxyFor', u'Proxy', None, u'Search access gateway/proxy group for this server group'),
        (
            'aeRequires', u'Required by', None, 'aeSrvGroup',
            u'Search all service groups depending on this service group.'
        ),
    )

    def _additional_links(self):
        r = DistinguishedName._additional_links(self)
        r.append(
            self._app.anchor(
                'search', 'All members',
                (
                    ('dn', self._dn),
                    ('search_root', self._app.naming_context),
                    ('searchform_mode', u'exp'),
                    (
                        'filterstr',
                        (
                            u'(&'
                            u'(|(objectClass=aeHost)(objectClass=aeService))'
                            u'(|(entryDN:dnSubordinateMatch:={0})(aeSrvGroup={0}))'
                            u')'
                        ).format(self.av_u)
                    ),
                ),
                title=u'Search all service and host entries which are member in this service/host group {0}'.format(self.av_u),
            )
        )
        return r

syntax_registry.reg_at(
    AEEntryDNAESrvGroup.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_SRVGROUP_OID, # aeSrvGroup
    ],
)


class AEEntryDNSudoRule(DistinguishedName):
    oid: str = 'AEEntryDNSudoRule-oid'
    desc: str = 'AE-DIR: entryDN'
    ref_attrs = (
        ('aeVisibleSudoers', u'Used on', None, u'Search all server groups (aeSrvGroup entries) referencing this SUDO rule'),
    )

syntax_registry.reg_at(
    AEEntryDNSudoRule.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_SUDORULE_OID, # aeSudoRule
    ],
)


class AEEntryDNAELocation(DistinguishedName):
    oid: str = 'AEEntryDNAELocation-oid'
    desc: str = 'AE-DIR: entryDN of aeLocation entry'
    ref_attrs = (
        ('aeLocation', u'Persons', None, 'aePerson', u'Search all persons assigned to this location.'),
        ('aeLocation', u'Zones', None, 'aeZone', u'Search all location-based zones associated with this location.'),
        ('aeLocation', u'Groups', None, 'groupOfEntries', u'Search all location-based zones associated with this location.'),
    )

syntax_registry.reg_at(
    AEEntryDNAELocation.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_LOCATION_OID, # aeLocation
    ],
)


class AELocation(DerefDynamicDNSelectList):
    oid: str = 'AELocation-oid'
    desc: str = 'AE-DIR: DN of location entry'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aeLocation)(aeStatus=0))'
    ref_attrs = AEEntryDNAELocation.ref_attrs

syntax_registry.reg_at(
    AELocation.oid, [
        AE_OID_PREFIX+'.4.35', # aeLocation
    ]
)


class AEEntryDNAEDept(DistinguishedName):
    oid: str = 'AEEntryDNAEDept-oid'
    desc: str = 'AE-DIR: entryDN of aePerson entry'
    ref_attrs = (
        ('aeDept', u'Persons', None, 'aePerson', u'Search all persons assigned to this department.'),
        ('aeDept', u'Zones', None, 'aeZone', u'Search all team-related zones associated with this department.'),
        ('aeDept', u'Groups', None, 'groupOfEntries', u'Search all team-related groups associated with this department.'),
    )

syntax_registry.reg_at(
    AEEntryDNAEDept.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_DEPT_OID, # aeDept
    ],
)


class AEDept(DerefDynamicDNSelectList):
    oid: str = 'AEDept-oid'
    desc: str = 'AE-DIR: DN of department entry'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aeDept)(aeStatus=0))'
    ref_attrs = AEEntryDNAEDept.ref_attrs

syntax_registry.reg_at(
    AEDept.oid, [
        AE_OID_PREFIX+'.4.29', # aeDept
    ]
)


class AEOwner(DerefDynamicDNSelectList):
    oid: str = 'AEOwner-oid'
    desc: str = 'AE-DIR: DN of owner entry'
    ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aePerson)(aeStatus=0))'
    ref_attrs = (
        ('aeOwner', u'Devices', None, 'aeDevice', u'Search all devices (aeDevice entries) assigned to same owner.'),
    )

syntax_registry.reg_at(
    AEOwner.oid, [
        AE_OID_PREFIX+'.4.2', # aeOwner
    ]
)


class AEPerson(DerefDynamicDNSelectList, AEObjectUtil):
    oid: str = 'AEPerson-oid'
    desc: str = 'AE-DIR: DN of person entry'
    ldap_url = 'ldap:///_?displayName?sub?(objectClass=aePerson)'
    ref_attrs = (
        ('aePerson', u'Users', None, 'aeUser', u'Search all personal AE-DIR user accounts (aeUser entries) of this person.'),
    )
    ae_status_map = {
        -1: (0,),
        0: (0,),
        1: (0, 1, 2),
        2: (0, 1, 2),
    }
    deref_attrs = ('aeDept', 'aeLocation')

    def _status_filter(self):
        try:
            ae_status = int(self._entry['aeStatus'][0])
        except (KeyError, ValueError, IndexError):
            ae_status = 0
        return compose_filter(
            '|',
            map_filter_parts(
                'aeStatus',
                map(str, self.ae_status_map.get(ae_status, [])),
            ),
        )

    def _filterstr(self):
        filter_components = [
            DerefDynamicDNSelectList._filterstr(self),
            self._status_filter(),
            #ae_validity_filter(),
        ]
        zone_entry = self._zone_entry(attrlist=self.deref_attrs) or {}
        for deref_attr_type in self.deref_attrs:
            deref_attr_values = [
                z
                for z in zone_entry.get(deref_attr_type, [])
                if z
            ]
            if deref_attr_values:
                filter_components.append(
                    compose_filter(
                        '|',
                        map_filter_parts(deref_attr_type, deref_attr_values),
                    )
                )
        ocs = self._entry.object_class_oid_set()
        if 'inetLocalMailRecipient' not in ocs:
            filter_components.append('(mail=*)')
        filter_str = '(&{})'.format(''.join(filter_components))
        return filter_str


class AEPerson2(AEPerson):
    oid: str = 'AEPerson2-oid'
    sanitize_filter_tmpl = '(|(cn={av}*)(uniqueIdentifier={av})(employeeNumber={av})(displayName={av})(mail={av}))'

    def formValue(self) -> str:
        form_value = DistinguishedName.formValue(self)
        if self._av:
            person_entry = self._get_ref_entry(self.av_u)
            if person_entry:
                form_value = person_entry.get(
                    'displayName',
                    [form_value],
                )[0].decode(self._app.form.accept_charset)
        return form_value

    def formField(self) -> str:
        return DistinguishedName.formField(self)

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if not attrValues or not attrValues[0]:
            return attrValues
        sanitize_filter = '(&{0}{1})'.format(
            self._filterstr(),
            self.sanitize_filter_tmpl.format(av=ldap0.filter.escape_str(attrValues[0])),
        )
        try:
            ldap_result = self._app.ls.l.search_s(
                self._search_root(),
                ldap0.SCOPE_SUBTREE,
                sanitize_filter,
                attrlist=self.lu_obj.attrs,
            )
        except (
                ldap0.NO_SUCH_OBJECT,
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.SIZELIMIT_EXCEEDED,
                ldap0.TIMELIMIT_EXCEEDED,
            ):
            return attrValues
        if ldap_result and len(ldap_result) == 1:
            return [ldap_result[0][0]]
        return attrValues

syntax_registry.reg_at(
    AEPerson.oid, [
        AE_OID_PREFIX+'.4.16', # aePerson
    ]
)


class AEManager(DerefDynamicDNSelectList):
    oid: str = 'AEManager-oid'
    desc: str = 'AE-DIR: Manager responsible for a person/department'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aePerson)(aeStatus=0))'

syntax_registry.reg_at(
    AEManager.oid, [
        '0.9.2342.19200300.100.1.10', # manager
    ],
    structural_oc_oids=[
        AE_PERSON_OID, # aePerson
        AE_DEPT_OID, # aeDept
    ]
)


class AEDerefAttribute(DirectoryString):
    oid: str = 'AEDerefAttribute-oid'
    maxValues = 1
    deref_object_class = None
    deref_attribute_type = None
    deref_filter_tmpl = '(&(objectClass={deref_object_class})(aeStatus=0)({attribute_type}=*))'

    def _read_person_attr(self):
        try:
            sre = self._app.ls.l.read_s(
                self._entry[self.deref_attribute_type][0].decode(self._app.ls.charset),
                attrlist=[self._at],
                filterstr=self.deref_filter_tmpl.format(
                    deref_object_class=self.deref_object_class,
                    attribute_type=self._at,
                ),
            )
        except ldap0.LDAPError:
            return None
        if sre is None:
            return None
        return sre.entry_s[self._at][0]

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if self.deref_attribute_type in self._entry:
            ae_person_attribute = self._read_person_attr()
            if ae_person_attribute is not None:
                result = [ae_person_attribute.encode(self._app.ls.charset)]
            else:
                raise KeyError
        else:
            result = attrValues
        return result

    def formValue(self) -> str:
        return u''

    def formField(self) -> str:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues, None,
        )
        input_field.charset = self._app.form.accept_charset
        input_field.set_default(self.formValue())
        return input_field


class AEPersonAttribute(AEDerefAttribute):
    oid: str = 'AEPersonAttribute-oid'
    maxValues = 1
    deref_object_class = 'aePerson'
    deref_attribute_type = 'aePerson'


class AEUserNames(AEPersonAttribute, DirectoryString):
    oid: str = 'AEUserNames-oid'

syntax_registry.reg_at(
    AEUserNames.oid, [
        '2.5.4.4', # sn
        '2.5.4.42', # givenName
    ],
    structural_oc_oids=[
        AE_USER_OID, # aeUser
    ],
)


class AEMailLocalAddress(RFC822Address):
    oid: str = 'AEMailLocalAddress-oid'
    simpleSanitizers = (
        bytes.strip,
        bytes.lower,
    )

syntax_registry.reg_at(
    AEMailLocalAddress.oid, [
        '2.16.840.1.113730.3.1.13', # mailLocalAddress
    ],
    structural_oc_oids=[
        AE_USER_OID,    # aeUser
        AE_SERVICE_OID, # aeService
    ],
)


class AEUserMailaddress(AEPersonAttribute, SelectList):
    oid: str = 'AEUserMailaddress-oid'
    html_tmpl = RFC822Address.html_tmpl
    maxValues = 1
    input_fallback = False
    simpleSanitizers = AEMailLocalAddress.simpleSanitizers

    def _get_attr_value_dict(self):
        attr_value_dict = {
            u'': u'-/-',
        }
        attr_value_dict.update([
            (addr.decode(self._app.ls.charset), addr.decode(self._app.ls.charset))
            for addr in self._entry.get('mailLocalAddress', [])
        ])
        return attr_value_dict

    def _is_mail_account(self):
        return 'inetLocalMailRecipient' in self._entry['objectClass']

    def _validate(self, attrValue: bytes) -> bool:
        if self._is_mail_account():
            return SelectList._validate(self, attrValue)
        return AEPersonAttribute._validate(self, attrValue)

    def formValue(self) -> str:
        if self._is_mail_account():
            return SelectList.formValue(self)
        return AEPersonAttribute.formValue(self)

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if self._is_mail_account():
            # make sure only non-empty strings are in attribute value list
            if not list(filter(None, map(str.strip, attrValues))):
                try:
                    attrValues = [self._entry['mailLocalAddress'][0]]
                except KeyError:
                    attrValues = []
        else:
            attrValues = AEPersonAttribute.transmute(self, attrValues)
        return attrValues

    def formField(self) -> str:
        if self._is_mail_account():
            return SelectList.formField(self)
        return AEPersonAttribute.formField(self)

syntax_registry.reg_at(
    AEUserMailaddress.oid, [
        '0.9.2342.19200300.100.1.3', # mail
    ],
    structural_oc_oids=[
        AE_USER_OID, # aeUser
    ],
)


class AEPersonMailaddress(DynamicValueSelectList, RFC822Address):
    oid: str = 'AEPersonMailaddress-oid'
    maxValues = 1
    ldap_url = 'ldap:///_?mail,mail?sub?'
    input_fallback = True
    html_tmpl = RFC822Address.html_tmpl

    def _validate(self, attrValue: bytes) -> bool:
        if not RFC822Address._validate(self, attrValue):
            return False
        attr_value_dict = self._get_attr_value_dict()
        if not attr_value_dict or attr_value_dict.keys() == [u'']:
            return True
        return DynamicValueSelectList._validate(self, attrValue)

    def _filterstr(self):
        return (
          '(&'
            '(objectClass=aeUser)'
            '(objectClass=inetLocalMailRecipient)'
            '(aeStatus=0)'
            '(aePerson=%s)'
            '(mailLocalAddress=*)'
          ')'
        ) % self._app.ls.uc_encode(self._dn)[0]

syntax_registry.reg_at(
    AEPersonMailaddress.oid, [
        '0.9.2342.19200300.100.1.3', # mail
    ],
    structural_oc_oids=[
        AE_PERSON_OID, # aePerson
    ],
)


class AEDeptAttribute(AEDerefAttribute, DirectoryString):
    oid: str = 'AEDeptAttribute-oid'
    maxValues = 1
    deref_object_class = 'aeDept'
    deref_attribute_type = 'aeDept'

syntax_registry.reg_at(
    AEDeptAttribute.oid, [
        '2.16.840.1.113730.3.1.2', # departmentNumber
        '2.5.4.11',                # ou, organizationalUnitName
    ],
    structural_oc_oids=[
        AE_PERSON_OID, # aePerson
    ],
)


class AEHostname(DNSDomain):
    oid: str = 'AEHostname-oid'
    desc: str = 'Canonical hostname / FQDN'
    host_lookup = 0

    def _validate(self, attrValue: bytes) -> bool:
        if not DNSDomain._validate(self, attrValue):
            return False
        if self.host_lookup:
            try:
                ip_addr = socket.gethostbyname(attrValue)
            except (socket.gaierror, socket.herror):
                return False
            if self.host_lookup >= 2:
                try:
                    reverse_hostname = socket.gethostbyaddr(ip_addr)[0]
                except (socket.gaierror, socket.herror):
                    return False
                else:
                    return reverse_hostname == attrValue
        return True

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        result = []
        for attr_value in attrValues:
            attr_value.lower().strip()
            if self.host_lookup:
                try:
                    ip_addr = socket.gethostbyname(attr_value)
                    reverse_hostname = socket.gethostbyaddr(ip_addr)[0]
                except (socket.gaierror, socket.herror):
                    pass
                else:
                    attr_value = reverse_hostname
            result.append(attr_value)
        return attrValues

syntax_registry.reg_at(
    AEHostname.oid, [
        '0.9.2342.19200300.100.1.9', # host
    ],
    structural_oc_oids=[
        AE_HOST_OID, # aeHost
    ],
)


class AEDisplayNameUser(ComposedAttribute, DirectoryString):
    oid: str = 'AEDisplayNameUser-oid'
    desc: str = 'Attribute displayName in object class aeUser'
    compose_templates = (
        '{givenName} {sn} ({uid}/{uidNumber})',
        '{givenName} {sn} ({uid})',
    )

syntax_registry.reg_at(
    AEDisplayNameUser.oid, [
        '2.16.840.1.113730.3.1.241', # displayName
    ],
    structural_oc_oids=[AE_USER_OID], # aeUser
)


class AEDisplayNameContact(ComposedAttribute, DirectoryString):
    oid: str = 'AEDisplayNameContact-oid'
    desc: str = 'Attribute displayName in object class aeContact'
    compose_templates = (
        '{cn} <{mail}>',
        '{cn}',
    )

syntax_registry.reg_at(
    AEDisplayNameContact.oid, [
        '2.16.840.1.113730.3.1.241', # displayName
    ],
    structural_oc_oids=[AE_CONTACT_OID], # aeContact
)


class AEDisplayNameDept(ComposedAttribute, DirectoryString):
    oid: str = 'AEDisplayNameDept-oid'
    desc: str = 'Attribute displayName in object class aeDept'
    compose_templates = (
        '{ou} ({departmentNumber})',
        '{ou}',
        '#{departmentNumber}',
    )

syntax_registry.reg_at(
    AEDisplayNameDept.oid, [
        '2.16.840.1.113730.3.1.241', # displayName
    ],
    structural_oc_oids=[AE_DEPT_OID], # aeDept
)


class AEDisplayNameLocation(ComposedAttribute, DirectoryString):
    oid: str = 'AEDisplayNameLocation-oid'
    desc: str = 'Attribute displayName in object class aeLocation'
    compose_templates = (
        '{cn}: {l}, {street}',
        '{cn}: {l}',
        '{cn}: {street}',
        '{cn}: {st}',
        '{cn}',
    )

syntax_registry.reg_at(
    AEDisplayNameLocation.oid, [
        '2.16.840.1.113730.3.1.241', # displayName
    ],
    structural_oc_oids=[AE_LOCATION_OID], # aeLocation
)


class AEDisplayNamePerson(DisplayNameInetOrgPerson):
    oid: str = 'AEDisplayNamePerson-oid'
    desc: str = 'Attribute displayName in object class aePerson'
    # do not stuff confidential employeeNumber herein!
    compose_templates = (
        '{givenName} {sn} / {ou}',
        '{givenName} {sn} / #{departmentNumber}',
        '{givenName} {sn} ({uniqueIdentifier})',
        '{givenName} {sn}',
    )

syntax_registry.reg_at(
    AEDisplayNamePerson.oid, [
        '2.16.840.1.113730.3.1.241', # displayName
    ],
    structural_oc_oids=[AE_PERSON_OID], # aePerson
)


class AEUniqueIdentifier(DirectoryString):
    oid: str = 'AEUniqueIdentifier-oid'
    maxValues = 1
    gen_template = 'web2ldap-{timestamp}'

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if not attrValues or not attrValues[0].strip():
            return [self.gen_template.format(timestamp=time.time())]
        return attrValues

    def formField(self) -> str:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues, None,
            default=self.formValue(),
        )
        input_field.charset = self._app.form.accept_charset
        return input_field

syntax_registry.reg_at(
    AEUniqueIdentifier.oid, [
        '0.9.2342.19200300.100.1.44', # uniqueIdentifier
    ],
    structural_oc_oids=[
        AE_PERSON_OID, # aePerson
    ]
)


class AEDepartmentNumber(DirectoryString):
    oid: str = 'AEDepartmentNumber-oid'
    maxValues = 1

syntax_registry.reg_at(
    AEDepartmentNumber.oid, [
        '2.16.840.1.113730.3.1.2', # departmentNumber
    ],
    structural_oc_oids=[
        AE_DEPT_OID,   # aeDept
    ]
)


class AECommonName(DirectoryString):
    oid: str = 'AECommonName-oid'
    desc: str = 'AE-DIR: common name of aeObject'
    maxValues = 1
    simpleSanitizers = (
        bytes.strip,
    )


class AECommonNameAEZone(AECommonName):
    oid: str = 'AECommonNameAEZone-oid'
    desc: str = 'AE-DIR: common name of aeZone'
    simpleSanitizers = (
        bytes.strip,
        bytes.lower,
    )

syntax_registry.reg_at(
    AECommonNameAEZone.oid, [
        '2.5.4.3', # cn alias commonName
    ],
    structural_oc_oids=[
        AE_ZONE_OID, # aeZone
    ],
)


class AECommonNameAELocation(AECommonName):
    oid: str = 'AECommonNameAELocation-oid'
    desc: str = 'AE-DIR: common name of aeLocation'

syntax_registry.reg_at(
    AECommonNameAELocation.oid, [
        '2.5.4.3', # cn alias commonName
    ],
    structural_oc_oids=[
        AE_LOCATION_OID, # aeLocation
    ],
)


class AECommonNameAEHost(AECommonName):
    oid: str = 'AECommonNameAEHost-oid'
    desc: str = 'Canonical hostname'
    derive_from_host = True
    host_begin_item = 0
    host_end_item = None

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if self.derive_from_host:
            return list(set([
                '.'.join(av.strip().lower().split('.')[self.host_begin_item:self.host_end_item])
                for av in self._entry['host']
            ]))
        return attrValues

syntax_registry.reg_at(
    AECommonNameAEHost.oid, [
        '2.5.4.3', # cn alias commonName
    ],
    structural_oc_oids=[
        AE_HOST_OID, # aeHost
    ],
)


class AEZonePrefixCommonName(AECommonName, AEObjectUtil):
    oid: str = 'AEZonePrefixCommonName-oid'
    desc: str = 'AE-DIR: Attribute values have to be prefixed with zone name'
    reObj = re.compile(r'^[a-z0-9]+-[a-z0-9-]+$')
    special_names = ('zone-admins', 'zone-auditors')

    def sanitize(self, attrValue: bytes) -> bytes:
        return attrValue.strip()

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        attrValues = [attrValues[0].lower()]
        return attrValues

    def _validate(self, attrValue: bytes) -> bool:
        result = DirectoryString._validate(self, attrValue)
        if result and attrValue:
            zone_cn = self._get_zone_name()
            result = (
                zone_cn and
                (zone_cn == 'pub' or attrValue.decode(self._app.ls.charset).startswith(zone_cn+u'-'))
            )
        return result

    def formValue(self) -> str:
        result = DirectoryString.formValue(self)
        zone_cn = self._get_zone_name()
        if zone_cn:
            if not self._av:
                result = zone_cn+u'-'
            elif self._av in self.special_names:
                result = '-'.join((zone_cn, self.av_u))
        return result # formValue()


class AECommonNameAEGroup(AEZonePrefixCommonName):
    oid: str = 'AECommonNameAEGroup-oid'

syntax_registry.reg_at(
    AECommonNameAEGroup.oid, [
        '2.5.4.3', # cn alias commonName
    ],
    structural_oc_oids=[
        AE_GROUP_OID,     # aeGroup
        AE_MAILGROUP_OID, # aeMailGroup
    ]
)


class AECommonNameAESrvGroup(AEZonePrefixCommonName):
    oid: str = 'AECommonNameAESrvGroup-oid'

syntax_registry.reg_at(
    AECommonNameAESrvGroup.oid, [
        '2.5.4.3', # cn alias commonName
    ],
    structural_oc_oids=[
        AE_SRVGROUP_OID, # aeSrvGroup
    ]
)


class AECommonNameAETag(AEZonePrefixCommonName):
    oid: str = 'AECommonNameAETag-oid'

    def display(self, valueindex=0, commandbutton=False) -> str:
        display_value = AEZonePrefixCommonName.display(self, valueindex, commandbutton)
        if commandbutton:
            search_anchor = self._app.anchor(
                'searchform', '&raquo;',
                (
                    ('dn', self._dn),
                    ('search_root', self._app.naming_context),
                    ('searchform_mode', u'adv'),
                    ('search_attr', u'aeTag'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', self.av_u),
                ),
                title=u'Search all entries tagged with this tag',
            )
        else:
            search_anchor = ''
        return ''.join((display_value, search_anchor))

syntax_registry.reg_at(
    AECommonNameAETag.oid, [
        '2.5.4.3', # cn alias commonName
    ],
    structural_oc_oids=[
        AE_TAG_OID, # aeTag
    ]
)


class AECommonNameAESudoRule(AEZonePrefixCommonName):
    oid: str = 'AECommonNameAESudoRule-oid'

syntax_registry.reg_at(
    AECommonNameAESudoRule.oid, [
        '2.5.4.3', # cn alias commonName
    ],
    structural_oc_oids=[
        AE_SUDORULE_OID, # aeSudoRule
    ]
)

syntax_registry.reg_at(
    web2ldap.app.plugins.inetorgperson.CNInetOrgPerson.oid, [
        '2.5.4.3', # commonName
    ],
    structural_oc_oids=[
        AE_PERSON_OID, # aePerson
        AE_USER_OID,   # aeUser
    ]
)


class AESudoRuleDN(DerefDynamicDNSelectList):
    oid: str = 'AESudoRuleDN-oid'
    desc: str = 'AE-DIR: DN(s) of visible SUDO rules'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSudoRule)(aeStatus=0))'

syntax_registry.reg_at(
    AESudoRuleDN.oid, [
        AE_OID_PREFIX+'.4.21', # aeVisibleSudoers
    ]
)


class AENotBefore(NotBefore):
    oid: str = 'AENotBefore-oid'
    desc: str = 'AE-DIR: begin of validity period'

syntax_registry.reg_at(
    AENotBefore.oid, [
        AE_OID_PREFIX+'.4.22', # aeNotBefore
    ]
)


class AENotAfter(NotAfter):
    oid: str = 'AENotAfter-oid'
    desc: str = 'AE-DIR: begin of validity period'

    def _validate(self, attrValue: bytes) -> bool:
        result = NotAfter._validate(self, attrValue)
        if result:
            ae_not_after = time.strptime(attrValue.decode('ascii'), '%Y%m%d%H%M%SZ')
            try:
                ae_not_before = time.strptime(
                    self._entry['aeNotBefore'][0].decode('ascii'),
                    '%Y%m%d%H%M%SZ',
                )
            except KeyError:
                result = True
            except (UnicodeDecodeError, ValueError):
                result = False
            else:
                result = (ae_not_before <= ae_not_after)
        return result

syntax_registry.reg_at(
    AENotAfter.oid, [
        AE_OID_PREFIX+'.4.23', # aeNotAfter
    ]
)


class AEStatus(SelectList, Integer):
    oid: str = 'AEStatus-oid'
    desc: str = 'AE-DIR: Status of object'
    attr_value_dict = {
        u'-1': u'requested',
        u'0': u'active',
        u'1': u'deactivated',
        u'2': u'archived',
    }

    def _validate(self, attrValue: bytes) -> bool:
        result = SelectList._validate(self, attrValue)
        if not result or not attrValue:
            return result
        ae_status = int(attrValue)
        current_time = time.gmtime(time.time())
        try:
            ae_not_before = time.strptime(self._entry['aeNotBefore'][0].decode('ascii'), '%Y%m%d%H%M%SZ')
        except (KeyError, IndexError, ValueError, UnicodeDecodeError):
            ae_not_before = time.strptime('19700101000000Z', '%Y%m%d%H%M%SZ')
        try:
            ae_not_after = time.strptime(self._entry['aeNotAfter'][0].decode('ascii'), '%Y%m%d%H%M%SZ')
        except (KeyError, IndexError, ValueError, UnicodeDecodeError):
            ae_not_after = current_time
        # see https://www.ae-dir.com/docs.html#schema-validity-period
        if current_time > ae_not_after:
            result = ae_status >= 1
        elif current_time < ae_not_before:
            result = ae_status == -1
        else:
            result = ae_not_before <= current_time <= ae_not_after
        return result

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if not attrValues or not attrValues[0]:
            return attrValues
        ae_status = int(attrValues[0].decode('ascii'))
        current_time = time.gmtime(time.time())
        try:
            ae_not_before = time.strptime(self._entry['aeNotBefore'][0].decode('ascii'), '%Y%m%d%H%M%SZ')
        except (KeyError, IndexError, ValueError):
            ae_not_before = None
        else:
            if ae_status == 0 and current_time < ae_not_before:
                ae_status = -1
        try:
            ae_not_after = time.strptime(self._entry['aeNotAfter'][0].decode('ascii'), '%Y%m%d%H%M%SZ')
        except (KeyError, IndexError, ValueError):
            ae_not_after = None
        else:
            if current_time > ae_not_after:
                try:
                    ae_expiry_status = int(self._entry.get('aeExpiryStatus', ['1'])[0].decode('ascii'))
                except (KeyError, IndexError, ValueError):
                    pass
                else:
                    if ae_status <= ae_expiry_status:
                        ae_status = ae_expiry_status
        return [str(ae_status).encode('ascii')]

    def display(self, valueindex=0, commandbutton=False) -> str:
        if not commandbutton:
            return Integer.display(self, valueindex)
        return SelectList.display(self, valueindex, commandbutton)

syntax_registry.reg_at(
    AEStatus.oid, [
        AE_OID_PREFIX+'.4.5', # aeStatus
    ]
)


class AEExpiryStatus(SelectList):
    oid: str = 'AEExpiryStatus-oid'
    desc: str = 'AE-DIR: Expiry status of object'
    attr_value_dict = {
        u'-/-': u'',
        u'1': u'deactivated',
        u'2': u'archived',
    }

syntax_registry.reg_at(
    AEStatus.oid, [
        AE_OID_PREFIX+'.4.46', # aeExpiryStatus
    ]
)


class AESudoUser(web2ldap.app.plugins.sudoers.SudoUserGroup):
    oid: str = 'AESudoUser-oid'
    desc: str = 'AE-DIR: sudoUser'
    ldap_url = (
        'ldap:///_?cn,cn?sub?'
        '(&'
          '(objectClass=aeGroup)'
          '(aeStatus=0)'
          '(!(|'
            '(cn=ae-admins)'
            '(cn=ae-auditors)'
            '(cn=ae-providers)'
            '(cn=ae-replicas)'
            '(cn=ae-login-proxies)'
            '(cn=*-zone-admins)'
            '(cn=*-zone-auditors)'
          '))'
        ')'
    )

syntax_registry.reg_at(
    AESudoUser.oid, [
        '1.3.6.1.4.1.15953.9.1.1', # sudoUser
    ],
    structural_oc_oids=[
        AE_SUDORULE_OID, # aeSudoRule
    ]
)


class AEServiceSshPublicKey(SshPublicKey):
    oid: str = 'AEServiceSshPublicKey-oid'
    desc: str = 'AE-DIR: aeService:sshPublicKey'

syntax_registry.reg_at(
    AEServiceSshPublicKey.oid, [
        '1.3.6.1.4.1.24552.500.1.1.1.13', # sshPublicKey
    ],
    structural_oc_oids=[
        AE_SERVICE_OID, # aeService
    ]
)


class AEEntryDNAEAuthcToken(DistinguishedName):
    oid: str = 'AEEntryDNAEAuthcToken-oid'
    desc: str = 'AE-DIR: entryDN of aeAuthcToken entry'
    ref_attrs = (
        ('oathToken', u'Users', None, 'aeUser', u'Search all personal user accounts using this OATH token.'),
    )

syntax_registry.reg_at(
    AEEntryDNAEAuthcToken.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_AUTHCTOKEN_OID, # aeAuthcToken
    ],
)


class AEEntryDNAEPolicy(DistinguishedName):
    oid: str = 'AEEntryDNAEPolicy-oid'
    desc: str = 'AE-DIR: entryDN of aePolicy entry'
    ref_attrs = (
        ('pwdPolicySubentry', u'Users', None, 'aeUser', u'Search all personal user accounts restricted by this password policy.'),
        ('pwdPolicySubentry', u'Services', None, 'aeService', u'Search all service accounts restricted by this password policy.'),
        ('pwdPolicySubentry', u'Tokens', None, 'aeAuthcToken', u'Search all authentication tokens restricted by this password policy.'),
        ('oathHOTPParams', u'HOTP Tokens', None, 'oathHOTPToken', u'Search all HOTP tokens affected by this HOTP parameters.'),
        ('oathTOTPParams', u'TOTP Tokens', None, 'oathTOTPToken', u'Search all TOTP tokens affected by this TOTP parameters.'),
    )

syntax_registry.reg_at(
    AEEntryDNAEPolicy.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_POLICY_OID, # aePolicy
    ],
)


class AEUserSshPublicKey(SshPublicKey):
    oid: str = 'AEUserSshPublicKey-oid'
    desc: str = 'AE-DIR: aeUser:sshPublicKey'

syntax_registry.reg_at(
    AEUserSshPublicKey.oid, [
        '1.3.6.1.4.1.24552.500.1.1.1.13', # sshPublicKey
    ],
    structural_oc_oids=[
        AE_USER_OID, # aeUser
    ]
)


class AERFC822MailMember(DynamicValueSelectList):
    oid: str = 'AERFC822MailMember-oid'
    desc: str = 'AE-DIR: rfc822MailMember'
    ldap_url = 'ldap:///_?mail,displayName?sub?(&(|(objectClass=inetLocalMailRecipient)(objectClass=aeContact))(mail=*)(aeStatus=0))'
    html_tmpl = RFC822Address.html_tmpl
    showValueButton = False

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        if 'member' not in self._entry:
            return []
        if int(self._entry['aeStatus'][0]) == 2:
            return []
        entrydn_filter = compose_filter(
            '|',
            map_filter_parts('entryDN', self._entry['member']),
        )
        ldap_result = self._app.ls.l.search_s(
            self._search_root(),
            ldap0.SCOPE_SUBTREE,
            entrydn_filter,
            attrlist=['mail'],
        )
        mail_addresses = [
            entry['mail'][0]
            for _, entry in ldap_result
        ]
        return sorted(mail_addresses)

    def formField(self) -> str:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues, None,
        )
        input_field.charset = self._app.form.accept_charset
        input_field.set_default(self.formValue())
        return input_field

syntax_registry.reg_at(
    AERFC822MailMember.oid, [
        '1.3.6.1.4.1.42.2.27.2.1.15', # rfc822MailMember
    ],
    structural_oc_oids=[
        AE_MAILGROUP_OID, # aeMailGroup
    ]
)


class AEPwdPolicy(web2ldap.app.plugins.ppolicy.PwdPolicySubentry):
    oid: str = 'AEPwdPolicy-oid'
    desc: str = 'AE-DIR: pwdPolicySubentry'
    ldap_url = 'ldap:///_??sub?(&(objectClass=aePolicy)(objectClass=pwdPolicy)(aeStatus=0))'

syntax_registry.reg_at(
    AEPwdPolicy.oid, [
        '1.3.6.1.4.1.42.2.27.8.1.23', # pwdPolicySubentry
    ],
    structural_oc_oids=[
        AE_USER_OID,    # aeUser
        AE_SERVICE_OID, # aeService
        AE_HOST_OID,    # aeHost
    ]
)


class AESudoHost(IA5String):
    oid: str = 'AESudoHost-oid'
    desc: str = 'AE-DIR: sudoHost'
    maxValues = 1
    reobj = re.compile('^ALL$')

    def transmute(self, attrValues: List[bytes]) -> List[bytes]:
        return ['ALL']

    def formField(self) -> str:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.maxLen, self.maxValues, None,
            default=self.formValue()
        )
        input_field.charset = self._app.form.accept_charset
        return input_field

syntax_registry.reg_at(
    AESudoHost.oid, [
        '1.3.6.1.4.1.15953.9.1.2', # sudoHost
    ],
    structural_oc_oids=[
        AE_SUDORULE_OID, # aeSudoRule
    ]
)


class AELoginShell(Shell):
    oid: str = 'AELoginShell-oid'
    desc: str = 'AE-DIR: Login shell for POSIX users'
    attr_value_dict = {
        u'/bin/bash': u'/bin/bash',
        u'/bin/true': u'/bin/true',
        u'/bin/false': u'/bin/false',
    }

syntax_registry.reg_at(
    AELoginShell.oid, [
        '1.3.6.1.1.1.1.4', # loginShell
    ],
    structural_oc_oids=[
        AE_USER_OID,    # aeUser
        AE_SERVICE_OID, # aeService
    ]
)


class AEOathHOTPToken(OathHOTPToken):
    oid: str = 'AEOathHOTPToken-oid'
    desc: str = 'DN of the associated oathHOTPToken entry in aeUser entry'
    ref_attrs = (
        (None, u'Users', None, None),
    )
    input_fallback = False

    def _filterstr(self):
        if 'aePerson' in self._entry:
            return '(&{0}(aeOwner={1}))'.format(
                OathHOTPToken._filterstr(self),
                self._entry['aePerson'][0],
            )
        return OathHOTPToken._filterstr(self)

syntax_registry.reg_at(
    AEOathHOTPToken.oid, [
        '1.3.6.1.4.1.5427.1.389.4226.4.9.1', # oathHOTPToken
    ],
    structural_oc_oids=[AE_USER_OID], # aeUser
)


# see sshd(AUTHORIZED_KEYS FILE FORMAT
# and the -O option in ssh-keygen(1)
class AESSHPermissions(SelectList):
    oid: str = 'AESSHPermissions-oid'
    desc: str = 'AE-DIR: Status of object'
    attr_value_dict = {
        u'pty': u'PTY allocation',
        u'X11-forwarding': u'X11 forwarding',
        u'agent-forwarding': u'Key agent forwarding',
        u'port-forwarding': u'Port forwarding',
        u'user-rc': u'Execute ~/.ssh/rc',
    }

syntax_registry.reg_at(
    AESSHPermissions.oid, [
        AE_OID_PREFIX+'.4.47', # aeSSHPermissions
    ]
)


class AERemoteHostAEHost(DynamicValueSelectList):
    oid: str = 'AERemoteHostAEHost-oid'
    desc: str = 'AE-DIR: aeRemoteHost in aeHost entry'
    ldap_url = 'ldap:///.?ipHostNumber,aeFqdn?one?(&(objectClass=aeNwDevice)(aeStatus=0))'
    input_fallback = True # fallback to normal input field

syntax_registry.reg_at(
    AERemoteHostAEHost.oid, [
        AE_OID_PREFIX+'.4.8',  # aeRemoteHost
    ],
    structural_oc_oids=[AE_HOST_OID], # aeHost
)


class AEDescriptionAENwDevice(ComposedAttribute):
    oid: str = 'AEDescriptionAENwDevice-oid'
    desc: str = 'Attribute description in object class  aeNwDevice'
    compose_templates = (
        '{cn}: {aeFqdn} {ipHostNumber})',
        '{cn}: {ipHostNumber})',
    )

syntax_registry.reg_at(
    AEDescriptionAENwDevice.oid, [
        '2.5.4.13', # description
    ],
    structural_oc_oids=[AE_NWDEVICE_OID], # aeNwDevice
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
