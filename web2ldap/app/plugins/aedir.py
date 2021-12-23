# -*- coding: ascii -*-
"""
web2ldap plugin classes for

\xC6-DIR -- Authorized Entities Directory
"""

# Python's standard lib
import re
import time
import socket
from typing import Dict, List, Optional

# from ldap0 package
import ldap0
import ldap0.filter
from ldap0.filter import escape_str as escape_filter_str
from ldap0.functions import strf_secs as ldap0_strf_secs
from ldap0.pw import random_string
from ldap0.controls.readentry import PreReadControl
from ldap0.controls.deref import DereferenceControl
from ldap0.filter import compose_filter, map_filter_parts
from ldap0.dn import DNObj
from ldap0.res import SearchResultEntry
from ldap0.base import decode_list

import web2ldapcnf

from ...log import logger
from ...web.forms import HiddenInput, Field
from ..searchform import (
    SEARCH_OPT_IS_EQUAL,
    SEARCH_OPT_DN_SUBTREE,
)
from .nis import UidNumber, GidNumber, MemberUID, Shell
from .inetorgperson import DisplayNameInetOrgPerson, CNInetOrgPerson
from .groups import GroupEntryDN
from .oath import OathHOTPToken
from .opensshlpk import SshPublicKey
from .posixautogen import HomeDirectory
from .ppolicy import PwdPolicySubentry
from .sudoers import SudoUserGroup
from ..schema.syntaxes import (
    ComposedAttribute,
    DirectoryString,
    DistinguishedName,
    DNSDomain,
    DerefDynamicDNSelectList,
    DynamicValueSelectList,
    IA5String,
    Integer,
    NotAfter,
    NotBefore,
    RFC822Address,
    SelectList,
    syntax_registry,
)
from .. import ErrorExit


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
          '(|(!(aeNotBefore=*))(aeNotBefore<={0}))'
          '(|(!(aeNotAfter=*))(aeNotAfter>={0}))'
        ')'
    ).format(ldap0_strf_secs(secs))


class AEObjectMixIn:
    """
    utility mix-in class for all aeObject entries
    """

    @property
    def ae_status(self):
        try:
            ae_status = int(self._entry['aeStatus'][0])
        except (KeyError, ValueError, IndexError):
            ae_status = None
        return ae_status

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
            )
        except ldap0.LDAPError:
            res = {}
        else:
            if zone is None:
                res = {}
            else:
                res = zone.entry_s
        return res

    def _get_zone_dn(self) -> str:
        return str(self.dn.slice(-len(DNObj.from_str(self._app.naming_context))-1, None))

    def _get_zone_name(self) -> str:
        return self.dn[-len(DNObj.from_str(self._app.naming_context))-1][0][1]


class AEHomeDirectory(HomeDirectory):
    """
    Plugin for attribute 'homeDirectory' in aeUser and aeService entries
    """
    oid: str = 'AEHomeDirectory-oid'
    # all valid directory prefixes for attribute 'homeDirectory'
    # but without trailing slash
    homeDirectoryPrefixes = (
        '/home',
    )
    homeDirectoryHidden = b'-/-'

    def _validate(self, attr_value: bytes) -> bool:
        av_u = self._app.ls.uc_decode(attr_value)[0]
        if attr_value == self.homeDirectoryHidden:
            return True
        for prefix in self.homeDirectoryPrefixes:
            if av_u.startswith(prefix):
                uid = self._app.ls.uc_decode(self._entry.get('uid', [b''])[0])[0]
                return av_u.endswith(uid)
        return False

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if attr_values == [self.homeDirectoryHidden]:
            return attr_values
        if 'uid' in self._entry:
            uid = self._app.ls.uc_decode(self._entry['uid'][0])[0]
        else:
            uid = ''
        if attr_values:
            av_u = self._app.ls.uc_decode(attr_values[0])[0]
            for prefix in self.homeDirectoryPrefixes:
                if av_u.startswith(prefix):
                    break
            else:
                prefix = self.homeDirectoryPrefixes[0]
        else:
            prefix = self.homeDirectoryPrefixes[0]
        return [self._app.ls.uc_encode('/'.join((prefix, uid)))[0]]

    def input_field(self) -> Field:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.max_len,
            self.max_values,
            None,
            default=self.form_value()
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
    """
    Plugin for attribute 'uidNumber' in aeUser and aeService entries
    """
    oid: str = 'AEUIDNumber-oid'
    desc: str = 'numeric Unix-UID'

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        return self._entry.get('gidNumber', [b''])

    def input_field(self) -> Field:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.max_len, self.max_values, None,
            default=self.form_value()
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
    """
    Plugin for attribute 'gidNumber' in aeUser, aeGroup and aeService entries
    """
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
            [(ldap0.MOD_INCREMENT, self._app.ls.uc_encode(self._at)[0], [b'1'])],
            req_ctrls=[prc],
        )
        return int(ldap_result.ctrls[0].res.entry_s[self._at][0])

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if attr_values and attr_values[0]:
            return attr_values
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
                return ldap_result.entry_as[self._at]
        # return next ID from pool entry
        return [str(self._get_next_gid()).encode('ascii')]

    def form_value(self) -> str:
        return Integer.form_value(self)

    def input_field(self) -> Field:
        return Integer.input_field(self)

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
    """
    Base class for attribute 'uid' mainly for sanitizing input values
    """
    oid: str = 'AEUid-oid'
    sani_funcs = (
        bytes.strip,
        bytes.lower,
    )


class AEUserUid(AEUid):
    """
    Class for auto-generating values for aeUser -> uid
    """
    oid: str = 'AEUserUid-oid'
    desc: str = 'AE-DIR: User name'
    max_values = 1
    min_len: int = 4
    max_len: int = 4
    maxCollisionChecks: int = 15
    UID_LETTERS = 'abcdefghijklmnopqrstuvwxyz'
    pattern = re.compile('^[{}]+$'.format(UID_LETTERS))
    genLen = 4
    sani_funcs = (
        bytes.strip,
        bytes.lower,
    )

    def __init__(self, app, dn: str, schema, attrType: str, attr_value: bytes, entry=None):
        IA5String.__init__(self, app, dn, schema, attrType, attr_value, entry=entry)

    def _gen_uid(self):
        uid_candidates = []
        while len(uid_candidates) < self.maxCollisionChecks:
            # generate new random UID candidate
            uid_candidate = random_string(alphabet=self.UID_LETTERS, length=self.genLen)
            # check whether UID candidate already exists
            uid_result = self._app.ls.l.search_s(
                str(self._app.naming_context),
                ldap0.SCOPE_SUBTREE,
                '(uid=%s)' % (escape_filter_str(uid_candidate)),
                attrlist=['1.1'],
            )
            if not uid_result:
                logger.info(
                    'Generated aeUser-uid after %d collisions: %r',
                    len(uid_candidates),
                    uid_candidate,
                )
                return uid_candidate
            uid_candidates.append(uid_candidate)
        logger.error(
            'Generating aeUser-uid stopped after %d collisions. Tried candidates: %r',
            len(uid_candidates),
            uid_candidates,
        )
        raise ErrorExit(
            'Gave up generating new unique <em>uid</em> after {0:d} attempts.'.format(
                len(uid_candidates),
            )
        )
        # end of _gen_uid()

    def form_value(self) -> str:
        fval = IA5String.form_value(self)
        if not self._av:
            fval = self._gen_uid()
        return fval

    def input_field(self) -> Field:
        return HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.max_len, self.max_values, None,
            default=self.form_value()
        )

    def sanitize(self, attr_value: bytes) -> bytes:
        return attr_value.strip().lower()

syntax_registry.reg_at(
    AEUserUid.oid, [
        '0.9.2342.19200300.100.1.1', # uid
    ],
    structural_oc_oids=[
        AE_USER_OID, # aeUser
    ],
)


class AEServiceUid(AEUid):
    """
    Plugin for attribute 'uid' in aeService entries
    """
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
    """
    Plugin for attribute 'aeTicketId' in all aeObject entries
    """
    oid: str = 'AETicketId-oid'
    desc: str = 'AE-DIR: Ticket no. related to last change of entry'
    sani_funcs = (
        bytes.upper,
        bytes.strip,
    )

syntax_registry.reg_at(
    AETicketId.oid, [
        AE_OID_PREFIX+'.4.3', # aeTicketId
    ]
)


class AERootDynamicDNSelectList(DerefDynamicDNSelectList):
    """
    custom variant with smarter handling of search base
    """
    oid: str = 'AERootDynamicDNSelectList-oid'
    input_fallback = False # no fallback to normal input field
    suffix_attr = 'aeRoot'

    def _search_root(self) -> str:
        if self.lu_obj.dn == self.suffix_attr:
            try:
                ae_suffix = self._app.ls.l.read_rootdse_s(
                    attrlist=['self.suffix_attr']
                ).entry_s[self.suffix_attr][0]
            except (ldap0.LDAPError, KeyError):
                pass
            else:
                return ae_suffix
        return DerefDynamicDNSelectList._search_root(self)


class AEZoneDN(AERootDynamicDNSelectList):
    """
    Plugin for attributes holding DNs of aeZone entries
    """
    oid: str = 'AEZoneDN-oid'
    desc: str = 'AE-DIR: Zone'
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeZone)(aeStatus=0))'
    ref_attrs = (
        (None, 'Same zone', None, 'aeGroup', 'Search all groups constrained to same zone'),
    )

syntax_registry.reg_at(
    AEZoneDN.oid, [
        AE_OID_PREFIX+'.4.36', # aeMemberZone
    ]
)


class AEHost(AERootDynamicDNSelectList):
    """
    Plugin for attribute 'host' in aeHost entries
    """
    oid: str = 'AEHost-oid'
    desc: str = 'AE-DIR: Host'
    ldap_url = 'ldap:///_?host?sub?(&(objectClass=aeHost)(aeStatus=0))'
    ref_attrs = (
        (None, 'Same host', None, 'aeService', 'Search all services running on same host'),
    )

syntax_registry.reg_at(
    AEHost.oid, [
        AE_OID_PREFIX+'.4.28', # aeHost
    ]
)


class AENwDevice(AERootDynamicDNSelectList):
    """
    Plugin for attributes holding DNs of aeNwDevice entries
    """
    oid: str = 'AENwDevice-oid'
    desc: str = 'AE-DIR: network interface'
    ldap_url = 'ldap:///..?cn?sub?(&(objectClass=aeNwDevice)(aeStatus=0))'
    ref_attrs = (
        (None, 'Siblings', None, 'aeNwDevice', 'Search sibling network devices'),
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


class AEGroupMember(DerefDynamicDNSelectList, AEObjectMixIn):
    """
    Plugin for attribute 'member' in aeGroup entries
    """
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

    def _extract_attr_value_dict(self, ldap_result, deref_person_attrset):
        attr_value_dict: Dict[str, str] = SelectList.get_attr_value_dict(self)
        for ldap_res in ldap_result:
            if not isinstance(ldap_res, SearchResultEntry):
                # ignore search continuations
                continue
            # process dn and entry
            if ldap_res.ctrls:
                deref_control = ldap_res.ctrls[0]
                deref_entry = deref_control.derefRes['aePerson'][0].entry_as
            elif deref_person_attrset:
                # if we have constrained attributes, no deref response control
                # means constraint not valid
                continue
            # check constrained values here
            valid = True
            for attr_type, attr_values in deref_person_attrset.items():
                if (
                        attr_type not in deref_entry
                        or deref_entry[attr_type][0] not in attr_values
                    ):
                    valid = False
                    break
            if valid:
                option_value = ldap_res.dn_s
                try:
                    option_text = ldap_res.entry_s['displayName'][0]
                except KeyError:
                    option_text = option_value
                try:
                    option_title = ldap_res.entry_s['description'][0]
                except KeyError:
                    option_title = option_value
                attr_value_dict[option_value] = (option_text, option_title)
        return attr_value_dict

    def get_attr_value_dict(self) -> Dict[str, str]:
        deref_person_attrset = self._deref_person_attrset()
        if not deref_person_attrset:
            return DerefDynamicDNSelectList.get_attr_value_dict(self)
        member_filter = self._filterstr()
        try:
            # Use the existing LDAP connection as current user
            ldap_result = self._app.ls.l.search_s(
                self._search_root(),
                self.lu_obj.scope or ldap0.SCOPE_SUBTREE,
                filterstr=member_filter,
                attrlist=self.lu_obj.attrs+['description'],
                req_ctrls=[
                    DereferenceControl(True, {'aePerson': deref_person_attrset.keys()})
                ],
                cache_ttl=min(30, 5*web2ldapcnf.ldap_cache_ttl),
            )
        except self.ignored_errors as ldap_err:
            logger.warning(
                '%s.get_attr_value_dict() searching %r failed: %s',
                self.__class__.__name__,
                member_filter,
                ldap_err,
            )
            return SelectList.get_attr_value_dict(self)
        return self._extract_attr_value_dict(ldap_result, deref_person_attrset)
        # get_attr_value_dict()

    def _validate(self, attr_value: bytes) -> bool:
        if 'memberURL' in self._entry and self._entry['memberURL'] != [b'']:
            # reduce to simple DN syntax check for dynamic groups
            return DistinguishedName._validate(self, attr_value)
        return SelectList._validate(self, attr_value)

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if self.ae_status == 2:
            return []
        return DerefDynamicDNSelectList.transmute(self, attr_values)

syntax_registry.reg_at(
    AEGroupMember.oid, [
        '2.5.4.31', # member
    ],
    structural_oc_oids=[
        AE_GROUP_OID, # aeGroup
    ],
)


class AEMailGroupMember(AEGroupMember):
    """
    Plugin for attribute 'member' in aeMailGroup entries
    """
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


class AEMemberUid(MemberUID, AEObjectMixIn):
    """
    Plugin for attribute 'memberUid' in aeGroup entries
    """
    oid: str = 'AEMemberUid-oid'
    desc: str = 'AE-DIR: username (uid) of member of a group'
    ldap_url = None
    show_val_button = False

    def _member_uids_from_member(self):
        return [
            dn[4:].split(b',')[0]
            for dn in self._entry.get('member', [])
        ]

    def _validate(self, attr_value: bytes) -> bool:
        """
        Because AEMemberUid.transmute() always resets all attribute values it's
        ok to not validate values at all
        """
        return True

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if 'member' not in self._entry:
            return []
        if self.ae_status == 2:
            return []
        return list(filter(None, self._member_uids_from_member()))

    def form_value(self) -> str:
        return ''

    def input_field(self) -> Field:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.max_len, self.max_values, None,
        )
        input_field.charset = self._app.form.accept_charset
        input_field.set_default(self.form_value())
        return input_field

    def display(self, vidx, links) -> str:
        return IA5String.display(self, vidx, links)

syntax_registry.reg_at(
    AEMemberUid.oid, [
        '1.3.6.1.1.1.1.12', # memberUid
    ],
    structural_oc_oids=[
        AE_GROUP_OID, # aeGroup
    ],
)


class AEGroupDN(AERootDynamicDNSelectList):
    """
    Plugin for attribute 'memberOf' in group member entries
    """
    oid: str = 'AEGroupDN-oid'
    desc: str = 'AE-DIR: DN of user group entry'
    ldap_url = 'ldap:///_??sub?(&(|(objectClass=aeGroup)(objectClass=aeMailGroup))(aeStatus=0))'
    ref_attrs = (
        ('memberOf', 'Members', None, 'Search all member entries of this user group'),
    )

    def display(self, vidx, links) -> str:
        group_dn = DNObj.from_str(self.av_u)
        group_cn = group_dn[0][0][1]
        res = [
            'cn=<strong>{0}</strong>,{1}'.format(
                self._app.form.s2d(group_cn),
                self._app.form.s2d(str(group_dn.parent())),
            )
        ]
        if links:
            res.extend(self._additional_links())
        return web2ldapcnf.command_link_separator.join(res)

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
    """
    Plugin for attributes holding DNs of zone admin groups
    """
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
    """
    Plugin for attributes holding DNs of zone auditor groups
    """
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
    """
    Plugin class for attributes holding DNs of user groups
    in aeSrvGroup entries
    """
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
    """
    Plugin class for attribute 'aeDisplayNameGroups' in aeSrvGroup entries
    """
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
    """
    Plugin class for attribute 'aeVisibleGroups' in aeSrvGroup entries
    """
    oid: str = 'AEVisibleGroups-oid'
    desc: str = 'AE-DIR: DN of visible user group entry'
    always_add_groups = (
        'aeLoginGroups',
        'aeDisplayNameGroups',
    )

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        attr_values = set(attr_values)
        for attr_type in self.always_add_groups:
            attr_values.update(self._entry.get(attr_type, []))
        return list(attr_values)

syntax_registry.reg_at(
    AEVisibleGroups.oid, [
        AE_OID_PREFIX+'.4.20', # aeVisibleGroups
    ]
)


class AESameZoneObject(DerefDynamicDNSelectList, AEObjectMixIn):
    """
    Plugin class for attributes storing DN references limited to reference
    entries within the same zone
    """
    oid: str = 'AESameZoneObject-oid'
    desc: str = 'AE-DIR: DN of referenced aeSrvGroup entry this is proxy for'
    input_fallback = False # no fallback to normal input field
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeObject)(aeStatus=0))'

    def _search_root(self):
        return self._get_zone_dn()


class AESrvGroupDN(AEGroupDN):
    """
    Plugin for attributes holding DNs of aeSrvGroup entries
    """
    oid: str = 'AESrvGroupDN-oid'
    desc: str = 'AE-DIR: DN of a referenced aeSrvGroup entry'
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0))'
    ref_attrs = DerefDynamicDNSelectList.ref_attrs


class AESrvGroup(AESrvGroupDN, AESameZoneObject):
    """
    Plugin class for attribute 'aeSrvGroup' in aeUser and aeService entries
    """
    oid: str = 'AESrvGroup-oid'
    desc: str = 'AE-DIR: DN of supplemental aeSrvGroup entry'
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0)(!(aeProxyFor=*)))'

    def _filterstr(self):
        filter_str = self.lu_obj.filterstr or '(objectClass=aeSrvGroup)'
        return '(&%s(!(entryDN=%s)))' % (
            filter_str,
            escape_filter_str(str(self.dn.parent())),
        )

syntax_registry.reg_at(
    AESrvGroup.oid, [
        AE_OID_PREFIX+'.4.27', # aeSrvGroup
    ]
)


class AERequires(AESrvGroupDN):
    """
    Plugin class for attribute 'aeRequires' in aeSrvGroup entries
    """
    oid: str = 'AERequires-oid'
    desc: str = 'AE-DIR: DN of required aeSrvGroup'
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0))'
    ref_attrs = (
        (
            'aeRequires', 'Same require', None, 'aeSrvGroup',
            'Search all service groups depending on this service group.'
        ),
    )

syntax_registry.reg_at(
    AERequires.oid, [
        AE_OID_PREFIX+'.4.48', # aeRequires
    ]
)


class AEProxyFor(AESrvGroupDN, AESameZoneObject):
    """
    Plugin class for attribute 'aeProxyFor' in aeSrvGroup entries
    """
    oid: str = 'AEProxyFor-oid'
    desc: str = 'AE-DIR: DN of referenced aeSrvGroup entry this is proxy for'
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0)(!(aeProxyFor=*)))'

    def _filterstr(self):
        filter_str = self.lu_obj.filterstr or '(objectClass=*)'
        return '(&%s(!(entryDN=%s)))' % (
            filter_str,
            escape_filter_str(self._dn),
        )

syntax_registry.reg_at(
    AEProxyFor.oid, [
        AE_OID_PREFIX+'.4.25', # aeProxyFor
    ]
)


class AETag(DynamicValueSelectList):
    """
    Plugin class for attribute 'aeTag' in all aeObject entries
    """
    oid: str = 'AETag-oid'
    desc: str = 'AE-DIR: cn of referenced aeTag entry'
    ldap_url = 'ldap:///_?cn,cn?sub?(&(objectClass=aeTag)(aeStatus=0))'

syntax_registry.reg_at(
    AETag.oid, [
        AE_OID_PREFIX+'.4.24', # aeTag
    ]
)


class AEEntryDNAEPerson(DistinguishedName):
    """
    Plugin class for attribute 'entryDN' in aePerson entries
    """
    oid: str = 'AEEntryDNAEPerson-oid'
    desc: str = 'AE-DIR: entryDN of aePerson entry'
    ref_attrs = (
        ('manager', 'Manages', None, 'Search all entries managed by this person'),
        (
            'aePerson', 'Users', None, 'aeUser',
            'Search all personal AE-DIR user accounts (aeUser entries) of this person.'
        ),
        (
            'aeOwner', 'Devices', None, 'aeDevice',
            'Search all devices (aeDevice entries) assigned to this person.'
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
    """
    Plugin class for attribute 'entryDN' in aeUser entries
    """
    oid: str = 'AEEntryDNAEUser-oid'
    desc: str = 'AE-DIR: entryDN of aeUser entry'

    def _additional_links(self):
        res = DistinguishedName._additional_links(self)
        res.append(self._app.anchor(
            'searchform', 'Created/Modified',
            (
                ('dn', self._dn),
                ('search_root', str(self._app.naming_context)),
                ('searchform_mode', 'adv'),
                ('search_mode', '(|%s)'),
                ('search_attr', 'creatorsName'),
                ('search_option', SEARCH_OPT_IS_EQUAL),
                ('search_string', self.av_u),
                ('search_attr', 'modifiersName'),
                ('search_option', SEARCH_OPT_IS_EQUAL),
                ('search_string', self.av_u),
            ),
            title='Search entries created or modified by %s' % (self.av_u),
        ))
        if self._app.audit_context:
            res.append(self._app.anchor(
                'search', 'Activity',
                (
                    ('dn', self._app.audit_context),
                    ('searchform_mode', 'adv'),
                    ('search_attr', 'objectClass'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', 'auditObject'),
                    ('search_attr', 'reqAuthzID'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', self.av_u),
                ),
                title='Search modifications made by %s in accesslog DB' % (self.av_u),
            ))
        return res

syntax_registry.reg_at(
    AEEntryDNAEUser.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_USER_OID, # aeUser
        AE_SERVICE_OID, # aeService
    ],
)


class AEEntryDNAEHost(DistinguishedName):
    """
    Plugin class for attribute 'entryDN' in aeHost entries
    """
    oid: str = 'AEEntryDNAEHost-oid'
    desc: str = 'AE-DIR: entryDN of aeUser entry'
    ref_attrs = (
        ('aeHost', 'Services', None, 'aeService', 'Search all services running on this host'),
    )

    def _additional_links(self):
        res = DistinguishedName._additional_links(self)
        srv_group_assertion_values = [escape_filter_str(str(self.dn.parent()))]
        srv_group_assertion_values.extend([
            escape_filter_str(av.decode(self._app.ls.charset))
            for av in self._entry.get('aeSrvGroup', [])
        ])
        res.extend([
            self._app.anchor(
                'search', 'Siblings',
                (
                    ('dn', self._dn),
                    ('search_root', str(self._app.naming_context)),
                    ('searchform_mode', 'exp'),
                    (
                        'filterstr',
                        '(&(|(objectClass=aeHost)(objectClass=aeService))(|{0}{1}))'.format(
                            ''.join([
                                '(entryDN:dnSubordinateMatch:=%s)' % av
                                for av in srv_group_assertion_values
                            ]),
                            ''.join([
                                '(aeSrvGroup=%s)' % av
                                for av in srv_group_assertion_values
                            ]),
                        )
                    ),
                ),
                title=(
                    'Search all host entries which are member in '
                    'at least one common server group(s) with this host'
                ),
            ),
        ])
        return res

syntax_registry.reg_at(
    AEEntryDNAEHost.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_HOST_OID, # aeHost
    ],
)


class AEEntryDNAEZone(DistinguishedName):
    """
    Plugin class for attribute 'entryDN' in aeZone entries
    """
    oid: str = 'AEEntryDNAEZone-oid'
    desc: str = 'AE-DIR: entryDN of aeZone entry'

    def _additional_links(self):
        res = DistinguishedName._additional_links(self)
        if self._app.audit_context:
            res.append(self._app.anchor(
                'search', 'Audit all',
                (
                    ('dn', self._app.audit_context),
                    ('searchform_mode', 'adv'),
                    ('search_attr', 'objectClass'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', 'auditObject'),
                    ('search_attr', 'reqDN'),
                    ('search_option', SEARCH_OPT_DN_SUBTREE),
                    ('search_string', self.av_u),
                ),
                title='Search all audit log entries for sub-tree %s' % (self.av_u),
            ))
            res.append(self._app.anchor(
                'search', 'Audit writes',
                (
                    ('dn', self._app.audit_context),
                    ('searchform_mode', 'adv'),
                    ('search_attr', 'objectClass'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', 'auditObject'),
                    ('search_attr', 'reqDN'),
                    ('search_option', SEARCH_OPT_DN_SUBTREE),
                    ('search_string', self.av_u),
                ),
                title='Search audit log entries for write operation within sub-tree %s' % (
                    self.av_u
                ),
            ))
        return res

syntax_registry.reg_at(
    AEEntryDNAEZone.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_ZONE_OID, # aeZone
    ],
)


class AEEntryDNAEMailGroup(GroupEntryDN):
    """
    Plugin class for attribute 'entryDN' in aeMailGroup entries
    """
    oid: str = 'AEEntryDNAEMailGroup-oid'
    desc: str = 'AE-DIR: entryDN of aeGroup entry'
    ref_attrs = (
        ('memberOf', 'Members', None, 'Search all member entries of this mail group'),
        (
            'aeVisibleGroups', 'Visible', None, 'aeSrvGroup',
            'Search all server/service groups (aeSrvGroup)\n'
            'on which this mail group is visible'
        ),
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
    """
    Plugin class for attribute 'entryDN' in aeGroup entries
    """
    oid: str = 'AEEntryDNAEGroup-oid'
    desc: str = 'AE-DIR: entryDN of aeGroup entry'
    ref_attrs = (
        ('memberOf', 'Members', None, 'Search all member entries of this user group'),
        (
            'aeLoginGroups', 'Login', None, 'aeSrvGroup',
            'Search all server/service groups (aeSrvGroup)\n'
            'on which this user group has login right'
        ),
        (
            'aeLogStoreGroups', 'View Logs', None, 'aeSrvGroup',
            'Search all server/service groups (aeSrvGroup)\n'
            'on which this user group has log view right'
        ),
        (
            'aeSetupGroups', 'Setup', None, 'aeSrvGroup',
            'Search all server/service groups (aeSrvGroup)\n'
            'on which this user group has setup/installation rights'
        ),
        (
            'aeVisibleGroups', 'Visible', None, 'aeSrvGroup',
            'Search all server/service groups (aeSrvGroup)\n'
            'on which this user group is at least visible'
        ),
    )

    def _additional_links(self):
        aegroup_cn = self._entry['cn'][0].decode(self._app.ls.charset)
        ref_attrs = list(AEEntryDNAEGroup.ref_attrs)
        if aegroup_cn.endswith('zone-admins'):
            ref_attrs.extend([
                (
                    'aeZoneAdmins', 'Zone Admins', None,
                    'Search all zones (aeZone)\n'
                    'for which members of this user group act as zone admins'
                ),
                (
                    'aePasswordAdmins', 'Password Admins', None,
                    'Search all zones (aeZone)\n'
                    'for which members of this user group act as password admins'
                ),
            ])
        if aegroup_cn.endswith('zone-auditors') or aegroup_cn.endswith('zone-admins'):
            ref_attrs.append(
                (
                    'aeZoneAuditors', 'Zone Auditors', None,
                    'Search all zones (aeZone)\n'
                    'for which members of this user group act as zone auditors'
                ),
            )
        self.ref_attrs = tuple(ref_attrs)
        res = DistinguishedName._additional_links(self)
        res.append(self._app.anchor(
            'search', 'SUDO rules',
            (
                ('dn', self._dn),
                ('search_root', str(self._app.naming_context)),
                ('searchform_mode', 'adv'),
                ('search_attr', 'sudoUser'),
                ('search_option', SEARCH_OPT_IS_EQUAL),
                ('search_string', '%'+self._entry['cn'][0].decode(self._app.ls.charset)),
            ),
            title='Search for SUDO rules\napplicable with this user group',
        ))
        return res

syntax_registry.reg_at(
    AEEntryDNAEGroup.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_GROUP_OID, # aeGroup
    ],
)


class AEEntryDNAESrvGroup(DistinguishedName):
    """
    Plugin class for attribute 'entryDN' in aeSrvGroup entries
    """
    oid: str = 'AEEntryDNAESrvGroup-oid'
    desc: str = 'AE-DIR: entryDN'
    ref_attrs = (
        (
            'aeProxyFor', 'Proxy', None, 'aeSrvGroup',
            'Search access gateway/proxy group for this server group'
        ),
        (
            'aeRequires', 'Required by', None, 'aeSrvGroup',
            'Search all service groups depending on this service group.'
        ),
    )

    def _additional_links(self):
        res = DistinguishedName._additional_links(self)
        res.append(
            self._app.anchor(
                'search', 'All members',
                (
                    ('dn', self._dn),
                    ('search_root', str(self._app.naming_context)),
                    ('searchform_mode', 'exp'),
                    (
                        'filterstr',
                        (
                            '(&'
                            '(|(objectClass=aeHost)(objectClass=aeService))'
                            '(|(entryDN:dnSubordinateMatch:={0})(aeSrvGroup={0}))'
                            ')'
                        ).format(self.av_u)
                    ),
                ),
                title=(
                    'Search all service and host entries '
                    'which are member in this service/host group {0}'
                ).format(self.av_u),
            )
        )
        return res

syntax_registry.reg_at(
    AEEntryDNAESrvGroup.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_SRVGROUP_OID, # aeSrvGroup
    ],
)


class AEEntryDNSudoRule(DistinguishedName):
    """
    Plugin class for attribute 'entryDN' in aeSudoRule entries
    """
    oid: str = 'AEEntryDNSudoRule-oid'
    desc: str = 'AE-DIR: entryDN'
    ref_attrs = (
        (
            'aeVisibleSudoers', 'Used on', None, 'aeSrvGroup',
            'Search all server groups (aeSrvGroup) referencing this SUDO rule'
        ),
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
    """
    Plugin class for attribute 'entryDN' in aeLocation entries
    """
    oid: str = 'AEEntryDNAELocation-oid'
    desc: str = 'AE-DIR: entryDN of aeLocation entry'
    ref_attrs = (
        (
            'aeLocation', 'Persons', None, 'aePerson',
            'Search all persons assigned to this location.'
        ),
        (
            'aeLocation', 'Zones', None, 'aeZone',
            'Search all location-based zones associated with this location.'
        ),
        (
            'aeLocation', 'Groups', None, 'groupOfEntries',
            'Search all location-based zones associated with this location.'
        ),
    )

syntax_registry.reg_at(
    AEEntryDNAELocation.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_LOCATION_OID, # aeLocation
    ],
)


class AELocation(AERootDynamicDNSelectList):
    """
    Plugin class for attribute 'aeLocation' in various entries
    """
    oid: str = 'AELocation-oid'
    desc: str = 'AE-DIR: DN of location entry'
    ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aeLocation)(aeStatus=0))'
    ref_attrs = AEEntryDNAELocation.ref_attrs
    desc_sep: str = '<br>'

syntax_registry.reg_at(
    AELocation.oid, [
        AE_OID_PREFIX+'.4.35', # aeLocation
    ]
)


class AEEntryDNAEDept(DistinguishedName):
    """
    Plugin class for attribute 'entryDN' in aeDept entries
    """
    oid: str = 'AEEntryDNAEDept-oid'
    desc: str = 'AE-DIR: entryDN of aePerson entry'
    ref_attrs = (
        (
            'aeDept', 'Persons', None, 'aePerson',
            'Search all persons assigned to this department.'
        ),
        (
            'aeDept', 'Zones', None, 'aeZone',
            'Search all team-related zones associated with this department.'
        ),
        (
            'aeDept', 'Groups', None, 'groupOfEntries',
            'Search all team-related groups associated with this department.'
        ),
    )

syntax_registry.reg_at(
    AEEntryDNAEDept.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_DEPT_OID, # aeDept
    ],
)


class AEDept(AERootDynamicDNSelectList):
    """
    Plugin class for attribute 'aeDept' in various entries
    """
    oid: str = 'AEDept-oid'
    desc: str = 'AE-DIR: DN of department entry'
    ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aeDept)(aeStatus=0))'
    ref_attrs = AEEntryDNAEDept.ref_attrs
    desc_sep: str = '<br>'

syntax_registry.reg_at(
    AEDept.oid, [
        AE_OID_PREFIX+'.4.29', # aeDept
    ]
)


class AEOwner(AERootDynamicDNSelectList):
    """
    Plugin class for attribute 'aeOwner' in aeDevice and aeSession entries
    """
    oid: str = 'AEOwner-oid'
    desc: str = 'AE-DIR: DN of owner entry'
    ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aePerson)(aeStatus=0))'
    ref_attrs = (
        (
            'aeOwner', 'Devices', None, 'aeDevice',
            'Search all devices (aeDevice entries) assigned to same owner.'
        ),
    )
    desc_sep: str = '<br>'

syntax_registry.reg_at(
    AEOwner.oid, [
        AE_OID_PREFIX+'.4.2', # aeOwner
    ]
)


class AEPerson(DerefDynamicDNSelectList, AEObjectMixIn):
    """
    Plugin class for attribute 'aePerson' in aeUser entries
    """
    oid: str = 'AEPerson-oid'
    desc: str = 'AE-DIR: DN of person entry'
    ldap_url = 'ldap:///_?displayName?sub?(objectClass=aePerson)'
    ref_attrs = (
        (
            'aePerson', 'Users', None, 'aeUser',
            'Search all personal AE-DIR user accounts (aeUser entries) of this person.'
        ),
    )
    desc_sep: str = '<br>'
    ae_status_map = {
        -1: (-1, 0),
        0: (0,),
        1: (0, 1, 2),
        2: (0, 1, 2),
    }
    deref_attrs = ('aeDept', 'aeLocation')

    def _status_filter(self):
        ae_status = self.ae_status or 0
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
        zone_entry = self._zone_entry(attrlist=self.deref_attrs)
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

    def _validate(self, attr_value: bytes) -> bool:
        if self.ae_status == 2:
            return True
        return DerefDynamicDNSelectList._validate(self, attr_value)


syntax_registry.reg_at(
    AEPerson.oid, [
        AE_OID_PREFIX+'.4.16', # aePerson
    ]
)


class AEManager(AERootDynamicDNSelectList):
    """
    Plugin class for attribute 'aeManager' in aePerson and aeDept entries
    """
    oid: str = 'AEManager-oid'
    desc: str = 'AE-DIR: Manager responsible for a person/department'
    ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aePerson)(aeStatus=0))'
    desc_sep: str = '<br>'

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
    """
    Plugin class for attributes referencing other entries
    """
    oid: str = 'AEDerefAttribute-oid'
    max_values: int = 1
    deref_object_class: Optional[str] = None
    deref_attribute_type: Optional[str] = None
    deref_filter_tmpl: str = (
        '(&(objectClass={deref_object_class})(aeStatus<=0)({attribute_type}=*))'
    )

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

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if self.deref_attribute_type in self._entry:
            ae_person_attribute = self._read_person_attr()
            if ae_person_attribute is not None:
                result = [ae_person_attribute.encode(self._app.ls.charset)]
            else:
                result = []
        else:
            result = attr_values
        return result

    def form_value(self) -> str:
        return ''

    def input_field(self) -> Field:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.max_len, self.max_values, None,
        )
        input_field.charset = self._app.form.accept_charset
        input_field.set_default(self.form_value())
        return input_field


class AEPersonAttribute(AEDerefAttribute):
    """
    Plugin class for aeUser attributes copied from referenced aePerson entries
    """
    oid: str = 'AEPersonAttribute-oid'
    max_values = 1
    deref_object_class = 'aePerson'
    deref_attribute_type = 'aePerson'


class AEUserNames(AEPersonAttribute, DirectoryString):
    """
    Plugin class for aeUser attributes 'sn' and 'givenName' copied
    from referenced aePerson entries
    """
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
    """
    Plugin class for attribute 'mailLocalAddress' in aeUser and aeService entries
    """
    oid: str = 'AEMailLocalAddress-oid'
    sani_funcs = (
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


class AEUserMailaddress(AEPersonAttribute, RFC822Address, SelectList):
    """
    Plugin class for attribute 'mail' in aeUser entries

    For primary mail user accounts this contains one of
    the values in attribute 'mailLocalAddress'.
    """
    oid: str = 'AEUserMailaddress-oid'
    max_values = 1
    input_fallback = False
    sani_funcs = (
        bytes.strip,
        bytes.lower,
    )

    def get_attr_value_dict(self) -> Dict[str, str]:
        attr_value_dict: Dict[str, str] = {
            '': '-/-',
        }
        for addr in self._entry.get('mailLocalAddress', []):
            addr_u = addr.decode(self._app.ls.charset)
            attr_value_dict[addr_u] = addr_u
        return attr_value_dict

    def _is_mail_account(self):
        return b'inetLocalMailRecipient' in self._entry['objectClass']

    def _validate(self, attr_value: bytes) -> bool:
        if self._is_mail_account():
            return SelectList._validate(self, attr_value)
        return AEPersonAttribute._validate(self, attr_value)

    def display(self, vidx, links) -> str:
        return RFC822Address.display(self, vidx, links)

    def form_value(self) -> str:
        if self._is_mail_account():
            return SelectList.form_value(self)
        return AEPersonAttribute.form_value(self)

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if self._is_mail_account():
            # make sure only non-empty strings are in attribute value list
            if not list(filter(None, map(bytes.strip, attr_values))):
                try:
                    attr_values = [self._entry['mailLocalAddress'][0]]
                except KeyError:
                    attr_values = []
        else:
            attr_values = AEPersonAttribute.transmute(self, attr_values)
        return attr_values

    def input_field(self) -> Field:
        if self._is_mail_account():
            return SelectList.input_field(self)
        return AEPersonAttribute.input_field(self)

syntax_registry.reg_at(
    AEUserMailaddress.oid, [
        '0.9.2342.19200300.100.1.3', # mail
    ],
    structural_oc_oids=[
        AE_USER_OID, # aeUser
    ],
)


class AEPersonMailaddress(DynamicValueSelectList, RFC822Address):
    """
    Plugin class for attribute 'mail' in aePerson entries

    If there exists a primary mail user account for this person this
    contains one of the values in attribute 'mailLocalAddress' in that
    aeUser entry.
    """
    oid: str = 'AEPersonMailaddress-oid'
    max_values = 1
    ldap_url = 'ldap:///_?mail,mail?sub?'
    input_fallback = True
    html_tmpl = RFC822Address.html_tmpl

    def _validate(self, attr_value: bytes) -> bool:
        if not RFC822Address._validate(self, attr_value):
            return False
        attr_value_dict: Dict[str, str] = self.get_attr_value_dict()
        if (
                not attr_value_dict
                or (
                    len(attr_value_dict) == 1
                    and tuple(attr_value_dict.keys()) == ('',)
                    )
            ):
            return True
        return DynamicValueSelectList._validate(self, attr_value)

    def _filterstr(self):
        return (
            '(&'
              '(objectClass=aeUser)'
              '(objectClass=inetLocalMailRecipient)'
              '(aeStatus=0)'
              '(aePerson=%s)'
              '(mailLocalAddress=*)'
            ')'
        ) % escape_filter_str(self._dn)

syntax_registry.reg_at(
    AEPersonMailaddress.oid, [
        '0.9.2342.19200300.100.1.3', # mail
    ],
    structural_oc_oids=[
        AE_PERSON_OID, # aePerson
    ],
)


class AEDeptAttribute(AEDerefAttribute, DirectoryString):
    """
    Plugin class for aePerson attributes copied from referenced aeDept entries
    """
    oid: str = 'AEDeptAttribute-oid'
    max_values = 1
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
    """
    Plugin class for attribute 'host' in aeHost entries
    """
    oid: str = 'AEHostname-oid'
    desc: str = 'Canonical hostname / FQDN'
    host_lookup = 0

    def _validate(self, attr_value: bytes) -> bool:
        if not DNSDomain._validate(self, attr_value):
            return False
        if self.host_lookup:
            try:
                ip_addr = socket.gethostbyname(self._app.ls.uc_decode(attr_value)[0])
            except (socket.gaierror, socket.herror):
                return False
            if self.host_lookup >= 2:
                try:
                    reverse_hostname = socket.gethostbyaddr(ip_addr)[0]
                except (socket.gaierror, socket.herror):
                    return False
                else:
                    return reverse_hostname == attr_value
        return True

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        result = []
        for attr_value in attr_values:
            attr_value.lower().strip()
            if self.host_lookup:
                try:
                    ip_addr = socket.gethostbyname(self._app.ls.uc_decode(attr_value)[0])
                    reverse_hostname = socket.gethostbyaddr(ip_addr)[0]
                except (socket.gaierror, socket.herror):
                    pass
                else:
                    attr_value = reverse_hostname.encode(self._app.ls.charset)
            result.append(attr_value)
        return attr_values

syntax_registry.reg_at(
    AEHostname.oid, [
        '0.9.2342.19200300.100.1.9', # host
    ],
    structural_oc_oids=[
        AE_HOST_OID, # aeHost
    ],
)


class AEDisplayNameUser(ComposedAttribute, DirectoryString):
    """
    Plugin class for attribute 'displayName' in aeUser entries
    """
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
    """
    Plugin class for attribute 'displayName' in aeContact entries
    """
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
    """
    Plugin class for attribute 'displayName' in aeDept entries
    """
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
    """
    Plugin class for attribute 'displayName' in aeLocation entries
    """
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
    """
    Plugin class for attribute 'displayName' in aePerson entries
    """
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
    """
    Plugin class for attribute 'uniqueIdentifier' in aePerson entries
    """
    oid: str = 'AEUniqueIdentifier-oid'
    max_values = 1
    gen_template = 'web2ldap-{timestamp}'

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if not attr_values or not attr_values[0].strip():
            return [self.gen_template.format(timestamp=time.time()).encode(self._app.ls.charset)]
        return attr_values

    def input_field(self) -> Field:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.max_len, self.max_values, None,
            default=self.form_value(),
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
    """
    Plugin class for attribute 'departmentNumber' in aeDept entries
    """
    oid: str = 'AEDepartmentNumber-oid'
    max_values = 1

syntax_registry.reg_at(
    AEDepartmentNumber.oid, [
        '2.16.840.1.113730.3.1.2', # departmentNumber
    ],
    structural_oc_oids=[
        AE_DEPT_OID,   # aeDept
    ]
)


class AECommonName(DirectoryString):
    """
    Base class for all plugin classes handling 'cn' in xC6-DIR plugin classes,
    not directly used
    """
    oid: str = 'AECommonName-oid'
    desc: str = 'AE-DIR: common name of aeObject'
    max_values = 1
    sani_funcs = (
        bytes.strip,
    )


class AECommonNameAEZone(AECommonName):
    """
    Plugin for attribute 'cn' in aeZone entries
    """
    oid: str = 'AECommonNameAEZone-oid'
    desc: str = 'AE-DIR: common name of aeZone'
    sani_funcs = (
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
    """
    Plugin for attribute 'cn' in aeLocation entries
    """
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
    """
    Plugin for attribute 'cn' in aeHost entries
    """
    oid: str = 'AECommonNameAEHost-oid'
    desc: str = 'Canonical hostname'
    derive_from_host = True
    host_begin_item = 0
    host_end_item = None

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if self.derive_from_host:
            return list({
                b'.'.join(av.strip().lower().split(b'.')[self.host_begin_item:self.host_end_item])
                for av in self._entry['host']
            })
        return attr_values

syntax_registry.reg_at(
    AECommonNameAEHost.oid, [
        '2.5.4.3', # cn alias commonName
    ],
    structural_oc_oids=[
        AE_HOST_OID, # aeHost
    ],
)


class AEZonePrefixCommonName(AECommonName, AEObjectMixIn):
    """
    Base class for handling 'cn' in entries which must have zone name as prefix
    """
    oid: str = 'AEZonePrefixCommonName-oid'
    desc: str = 'AE-DIR: Attribute values have to be prefixed with zone name'
    pattern = re.compile(r'^[a-z0-9]+-[a-z0-9-]+$')
    special_names = {
        'zone-admins',
        'zone-auditors',
    }

    def sanitize(self, attr_value: bytes) -> bytes:
        return attr_value.strip()

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        attr_values = [attr_values[0].lower()]
        return attr_values

    def _validate(self, attr_value: bytes) -> bool:
        result = DirectoryString._validate(self, attr_value)
        if result and attr_value:
            zone_cn = self._get_zone_name()
            result = (
                zone_cn and
                (
                    zone_cn == 'pub'
                    or attr_value.decode(self._app.ls.charset).startswith(zone_cn+'-')
                )
            )
        return result

    def form_value(self) -> str:
        result = DirectoryString.form_value(self)
        zone_cn = self._get_zone_name()
        if zone_cn:
            if not self._av:
                result = zone_cn+'-'
            elif self._av_u in self.special_names:
                result = '-'.join((zone_cn, self.av_u))
        return result


class AECommonNameAEGroup(AEZonePrefixCommonName):
    """
    Plugin for attribute 'cn' in aeGroup entries
    """
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
    """
    Plugin for attribute 'cn' in aeSrvGroup entries
    """
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
    """
    Plugin for attribute 'cn' in aeTag entries
    """
    oid: str = 'AECommonNameAETag-oid'

    def display(self, vidx, links) -> str:
        display_value = AEZonePrefixCommonName.display(self, vidx, links)
        if links:
            search_anchor = self._app.anchor(
                'searchform', '&raquo;',
                (
                    ('dn', self._dn),
                    ('search_root', str(self._app.naming_context)),
                    ('searchform_mode', 'adv'),
                    ('search_attr', 'aeTag'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', self.av_u),
                ),
                title='Search all entries tagged with this tag',
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
    """
    Plugin for attribute 'cn' in aeSudoRule entries
    """
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
    CNInetOrgPerson.oid, [
        '2.5.4.3', # commonName
    ],
    structural_oc_oids=[
        AE_PERSON_OID, # aePerson
        AE_USER_OID,   # aeUser
    ]
)


class AESudoRuleDN(AERootDynamicDNSelectList):
    """
    Plugin for attribute 'aeVisibleSudoers' in aeSrvGroup entries
    """
    oid: str = 'AESudoRuleDN-oid'
    desc: str = 'AE-DIR: DN(s) of visible SUDO rules'
    ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSudoRule)(aeStatus=0))'

syntax_registry.reg_at(
    AESudoRuleDN.oid, [
        AE_OID_PREFIX+'.4.21', # aeVisibleSudoers
    ]
)


class AENotBefore(NotBefore):
    """
    Plugin for attribute 'aeNotBefore' in all aeObject entries
    """
    oid: str = 'AENotBefore-oid'
    desc: str = 'AE-DIR: begin of validity period'

syntax_registry.reg_at(
    AENotBefore.oid, [
        AE_OID_PREFIX+'.4.22', # aeNotBefore
    ]
)


class AENotAfter(NotAfter):
    """
    Plugin for attribute 'aeNotAfter' in all aeObject entries
    """
    oid: str = 'AENotAfter-oid'
    desc: str = 'AE-DIR: begin of validity period'

    def _validate(self, attr_value: bytes) -> bool:
        result = NotAfter._validate(self, attr_value)
        if result:
            ae_not_after = time.strptime(attr_value.decode('ascii'), '%Y%m%d%H%M%SZ')
            if (
                    'aeNotBefore' not in self._entry
                    or not self._entry['aeNotBefore']
                    or not self._entry['aeNotBefore'][0]
                ):
                return True
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
    """
    Plugin for attribute 'aeStatus' in all aeObject entries
    """
    oid: str = 'AEStatus-oid'
    desc: str = 'AE-DIR: Status of object'
    attr_value_dict: Dict[str, str] = {
        '-1': 'requested',
        '0': 'active',
        '1': 'deactivated',
        '2': 'archived',
    }

    def _validate(self, attr_value: bytes) -> bool:
        result = SelectList._validate(self, attr_value)
        if not result or not attr_value:
            return result
        ae_status = int(attr_value)
        current_time = time.gmtime(time.time())
        try:
            ae_not_before = time.strptime(
                self._entry['aeNotBefore'][0].decode('ascii'),
                '%Y%m%d%H%M%SZ',
            )
        except (KeyError, IndexError, ValueError, UnicodeDecodeError):
            ae_not_before = time.strptime('19700101000000Z', '%Y%m%d%H%M%SZ')
        try:
            ae_not_after = time.strptime(
                self._entry['aeNotAfter'][0].decode('ascii'),
                '%Y%m%d%H%M%SZ',
            )
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

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if not attr_values or not attr_values[0]:
            return attr_values
        ae_status = int(attr_values[0].decode('ascii'))
        current_time = time.gmtime(time.time())
        try:
            ae_not_before = time.strptime(
                self._entry['aeNotBefore'][0].decode('ascii'),
                '%Y%m%d%H%M%SZ',
            )
        except (KeyError, IndexError, ValueError):
            pass
        else:
            if ae_status == 0 and current_time < ae_not_before:
                ae_status = -1
        try:
            ae_not_after = time.strptime(
                self._entry['aeNotAfter'][0].decode('ascii'),
                '%Y%m%d%H%M%SZ',
            )
        except (KeyError, IndexError, ValueError):
            ae_not_after = None
        else:
            if current_time > ae_not_after:
                try:
                    ae_expiry_status = int(
                        self._entry.get('aeExpiryStatus', ['1'])[0].decode('ascii')
                    )
                except (KeyError, IndexError, ValueError):
                    pass
                else:
                    ae_status = max(ae_status, ae_expiry_status)
        return [str(ae_status).encode('ascii')]

    def display(self, vidx, links) -> str:
        if not links:
            return Integer.display(self, vidx, links)
        return SelectList.display(self, vidx, links)

syntax_registry.reg_at(
    AEStatus.oid, [
        AE_OID_PREFIX+'.4.5', # aeStatus
    ]
)


class AEExpiryStatus(SelectList):
    """
    Plugin for attribute 'aeExpiryStatus' in all aeObject entries
    """
    oid: str = 'AEExpiryStatus-oid'
    desc: str = 'AE-DIR: Expiry status of object'
    attr_value_dict: Dict[str, str] = {
        '-/-': '',
        '1': 'deactivated',
        '2': 'archived',
    }

syntax_registry.reg_at(
    AEStatus.oid, [
        AE_OID_PREFIX+'.4.46', # aeExpiryStatus
    ]
)


class AESudoUser(SudoUserGroup):
    """
    Plugin for attribute 'sudoUser' in aeSudoRule entries
    """
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
    """
    Plugin for attribute 'sshPublicKey' in aeService entries

    Mainly this can be used to assign specific regex pattern
    e.g. for limiting values to certain OpenSSH key types
    in aeService entries.
    """
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


class AEUserSshPublicKey(SshPublicKey):
    """
    Plugin for attribute 'sshPublicKey' in aeUser entries

    Mainly this can be used to assign specific regex pattern
    e.g. for limiting values to certain OpenSSH key types
    in aeUser entries.
    """
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


class AEEntryDNAEAuthcToken(DistinguishedName):
    """
    Plugin for attribute 'entryDN' in aeAuthcToken entries
    """
    oid: str = 'AEEntryDNAEAuthcToken-oid'
    desc: str = 'AE-DIR: entryDN of aeAuthcToken entry'
    ref_attrs = (
        (
            'oathToken', 'Users', None, 'aeUser',
            'Search all personal user accounts using this OATH token.'
        ),
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
    """
    Plugin for attribute 'entryDN' in aePolicy entries
    """
    oid: str = 'AEEntryDNAEPolicy-oid'
    desc: str = 'AE-DIR: entryDN of aePolicy entry'
    ref_attrs = (
        (
            'pwdPolicySubentry', 'Users', None, 'aeUser',
            'Search all personal user accounts restricted by this password policy.'
        ),
        (
            'pwdPolicySubentry', 'Services', None, 'aeService',
            'Search all service accounts restricted by this password policy.'
        ),
        (
            'pwdPolicySubentry', 'Tokens', None, 'aeAuthcToken',
            'Search all authentication tokens restricted by this password policy.'
        ),
        (
            'oathHOTPParams', 'HOTP Tokens', None, 'oathHOTPToken',
            'Search all HOTP tokens affected by this HOTP parameters.'
        ),
        (
            'oathTOTPParams', 'TOTP Tokens', None, 'oathTOTPToken',
            'Search all TOTP tokens affected by this TOTP parameters.'
        ),
    )

syntax_registry.reg_at(
    AEEntryDNAEPolicy.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        AE_POLICY_OID, # aePolicy
    ],
)


class AERFC822MailMember(DynamicValueSelectList, AEObjectMixIn):
    """
    Plugin for attribute 'rfc822MailMember' in aeMailGroup entries
    """
    oid: str = 'AERFC822MailMember-oid'
    desc: str = 'AE-DIR: rfc822MailMember'
    ldap_url = (
        'ldap:///_?mail,displayName?sub?'
        '(&(|(objectClass=inetLocalMailRecipient)(objectClass=aeContact))(mail=*)(aeStatus=0))'
    )
    html_tmpl = RFC822Address.html_tmpl
    show_val_button = False

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        if 'member' not in self._entry:
            return []
        if self.ae_status == 2:
            return []
        entrydn_filter = compose_filter(
            '|',
            map_filter_parts(
                'entryDN',
                decode_list(self._entry['member'], encoding=self._app.ls.charset),
            ),
        )
        ldap_result = self._app.ls.l.search_s(
            self._search_root(),
            ldap0.SCOPE_SUBTREE,
            entrydn_filter,
            attrlist=['mail'],
        )
        mail_addresses = []
        for res in ldap_result or []:
            mail_addresses.extend(res.entry_as['mail'])
        return sorted(mail_addresses)

    def input_field(self) -> Field:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.max_len, self.max_values, None,
        )
        input_field.charset = self._app.form.accept_charset
        input_field.set_default(self.form_value())
        return input_field

syntax_registry.reg_at(
    AERFC822MailMember.oid, [
        '1.3.6.1.4.1.42.2.27.2.1.15', # rfc822MailMember
    ],
    structural_oc_oids=[
        AE_MAILGROUP_OID, # aeMailGroup
    ]
)


class AEPwdPolicy(PwdPolicySubentry):
    """
    Plugin for attribute 'pwdPolicySubentry' in aeUser, aeService and aeHost entries
    """
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
    """
    Plugin for attribute 'sudoHost' in aeSudoRule entries
    """
    oid: str = 'AESudoHost-oid'
    desc: str = 'AE-DIR: sudoHost'
    max_values = 1

    def transmute(self, attr_values: List[bytes]) -> List[bytes]:
        return [b'ALL']

    def input_field(self) -> Field:
        input_field = HiddenInput(
            self._at,
            ': '.join([self._at, self.desc]),
            self.max_len, self.max_values, None,
            default=self.form_value()
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
    """
    Plugin for attribute 'loginShell' in aeUser and aeService entries
    """
    oid: str = 'AELoginShell-oid'
    desc: str = 'AE-DIR: Login shell for POSIX users'
    attr_value_dict: Dict[str, str] = {
        '/bin/bash': '/bin/bash',
        '/bin/true': '/bin/true',
        '/bin/false': '/bin/false',
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
    """
    Plugin for attribute 'oathHOTPToken' in aeUser entries
    """
    oid: str = 'AEOathHOTPToken-oid'
    desc: str = 'DN of the associated oathHOTPToken entry in aeUser entry'
    ref_attrs = (
        (None, 'Users', None, None),
    )
    input_fallback = False

    def _filterstr(self):
        if 'aePerson' in self._entry:
            return '(&{0}(aeOwner={1}))'.format(
                OathHOTPToken._filterstr(self),
                escape_filter_str(
                    self._entry['aePerson'][0].decode(self._app.form.accept_charset)
                ),
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
    """
    Plugin for attribute 'aeSSHPermissions' in aeUser and aeService entries
    """
    oid: str = 'AESSHPermissions-oid'
    desc: str = 'AE-DIR: Status of object'
    attr_value_dict: Dict[str, str] = {
        'pty': 'PTY allocation',
        'X11-forwarding': 'X11 forwarding',
        'agent-forwarding': 'Key agent forwarding',
        'port-forwarding': 'Port forwarding',
        'user-rc': 'Execute ~/.ssh/rc',
    }

syntax_registry.reg_at(
    AESSHPermissions.oid, [
        AE_OID_PREFIX+'.4.47', # aeSSHPermissions
    ]
)


class AERemoteHostAEHost(DynamicValueSelectList):
    """
    Plugin for attribute 'aeRemoteHost' in aeHost entries
    """
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
    """
    Plugin for attribute 'description' in aeNwDevice entries
    """
    oid: str = 'AEDescriptionAENwDevice-oid'
    desc: str = 'Attribute description in object class aeNwDevice'
    compose_templates = (
        '{cn}: {aeFqdn} / {ipHostNumber}',
        '{cn}: {ipHostNumber}',
    )

syntax_registry.reg_at(
    AEDescriptionAENwDevice.oid, [
        '2.5.4.13', # description
    ],
    structural_oc_oids=[AE_NWDEVICE_OID], # aeNwDevice
)


class AEChildClasses(SelectList):
    """
    Plugin for attribute 'aeChildClasses' in aeZone entries
    """
    oid = 'AEChildClasses-oid'
    desc = 'AE-DIR: Structural object classes allowed to be added in child entries'
    attr_value_dict: Dict[str, str] = {
        '-/-': '',
        'aeAuthcToken': 'Authentication Token (aeAuthcToken)',
        'aeContact': 'Contact (aeContact)',
        'aeDept': 'Department (aeDept)',
        'aeLocation': 'Location (aeLocation)',
        'aeMailGroup': 'Mail Group (aeMailGroup)',
        'aePerson': 'Person (aePerson)',
        'aePolicy': 'Policy (aePolicy)',
        'aeService': 'Service/tool Account (aeService)',
        'aeSrvGroup': 'Service Group (aeSrvGroup)',
        'aeSudoRule': 'Sudoers Rule (sudoRole)',
        'aeUser': 'User account (aeUser)',
        'aeGroup': 'User group (aeGroup)',
        'aeTag': 'Tag (aeTag)',
    }

syntax_registry.reg_at(
    AEChildClasses.oid, [
        AE_OID_PREFIX+'.4.49', # aeChildClasses
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
