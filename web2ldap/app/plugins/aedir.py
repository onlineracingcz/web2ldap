# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for

Æ-DIR -- Yet another LDAP user and systems management
"""

from __future__ import absolute_import

# Python's standard lib
import re,time,socket

# from ldap0 package
import ldap0
from ldap0.filter import escape_filter_chars
from ldap0.pw import random_string
from ldap0.controls.readentry import PreReadControl
from ldap0.controls.deref import DereferenceControl

# from pyweblib
from pyweblib.forms import HiddenInput

import web2ldapcnf

# from internal base modules
import web2ldap.ldaputil.base
from web2ldap.ldaputil.base import compose_filter, map_filter_parts

# web2ldap's internal application modules
import web2ldap.app.searchform,web2ldap.app.plugins.inetorgperson,web2ldap.app.plugins.sudoers,web2ldap.app.plugins.ppolicy

from web2ldap.app.schema.syntaxes import \
  DirectoryString,DistinguishedName,SelectList, \
  DynamicValueSelectList,IA5String,DNSDomain, \
  DynamicDNSelectList,RFC822Address,Integer,ComposedAttribute, \
  NotBefore,NotAfter,syntax_registry

from web2ldap.app.plugins.nis import UidNumber,GidNumber,MemberUID,Shell
from web2ldap.app.plugins.inetorgperson import DisplayNameInetOrgPerson
from web2ldap.app.plugins.groups import GroupEntryDN
from web2ldap.app.plugins.oath import OathHOTPToken
try:
  from web2ldap.app.plugins.opensshlpk import ParamikoSshPublicKey as SshPublicKey
except ImportError:
  # paramiko is missing
  from web2ldap.app.plugins.opensshlpk import SshPublicKey
from web2ldap.app.plugins.posixautogen import HomeDirectory

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


syntax_registry.registerAttrType(
  DNSDomain.oid,[
    AE_OID_PREFIX+'.4.10',   # aeFqdn
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

  def _zone_entry(self,attrlist=None):
    zone_dn = 'cn={0},{1}'.format(
      self._get_zone_name(),
      self._ls.currentSearchRoot.encode(self._ls.charset),
    )
    try:
      ldap_result = self._ls.readEntry(
        zone_dn,
        attrtype_list=attrlist,
        search_filter='(objectClass=aeZone)',
      )
    except ldap0.LDAPError:
      zone_entry = {}
    else:
      if ldap_result:
        _,zone_entry = ldap_result[0]
      else:
        zone_entry = {}
      return zone_entry

  def _get_zone_dn(self):
    dn_list = ldap0.dn.explode_dn(
      self._dn[:-len(self._ls.currentSearchRoot)-1].encode(self._ls.charset)
    )
    result = ','.join((
      dn_list[-1],
      self._ls.currentSearchRoot.encode(self._ls.charset),
    ))
    return result # _get_zone_dn()

  def _get_zone_name(self):
    dn_list = ldap0.dn.str2dn(
      self._dn[:-len(self._ls.currentSearchRoot)-1].encode(self._ls.charset)
    )
    try:
      zone_cn = dict([
        (at,av)
        for at,av,_ in dn_list[-1]
      ])['cn'].decode(self._ls.charset)
    except (KeyError,IndexError):
      result = None
    else:
      result = zone_cn
    return result # _get_zone_name()

  def _constrained_persons(
    self,
    entry,
    deref_attrs,
    person_filter='(objectClass=aePerson)(aeStatus=0)',
    person_attrs=None
  ):
    """
    return additional aePerson filter based on derefing `deref_attrs'
    """
    person_filter_parts = [person_filter]
    for deref_attr_type in deref_attrs:
      deref_attr_values = filter(None,entry.get(deref_attr_type,[]))
      if deref_attr_values:
        person_filter_parts.append(
          compose_filter(
            '|',
            map_filter_parts(deref_attr_type,deref_attr_values),
          )
        )
    if not person_filter_parts:
      return []
    ldap_result = self._ls.l.search_s(
      self._ls.uc_encode(self._determineSearchDN(self._dn,self.lu_obj.dn))[0],
      ldap0.SCOPE_SUBTREE,
      '(&{0})'.format(
        ''.join(person_filter_parts)
      ),
      attrlist=person_attrs or ['1.1'],
    )
    return ldap_result


class AEHomeDirectory(HomeDirectory):
  oid = 'AEHomeDirectory-oid'
  # all valid directory prefixes for attribute 'homeDirectory'
  # but without trailing slash
  homeDirectoryPrefixes = (
    '/home',
  )
  homeDirectoryHidden = '-/-'

  def _validate(self,attrValue):
    if attrValue==self.homeDirectoryHidden:
      return True
    for prefix in self.homeDirectoryPrefixes:
      if attrValue.startswith(prefix):
        uid = self._entry.get('uid',[''])[0]
        return attrValue.endswith(uid)
    return False

  def transmute(self,attrValues):
    if attrValues==[self.homeDirectoryHidden]:
      return attrValues
    uid = self._entry.get('uid',[''])[0]
    for prefix in self.homeDirectoryPrefixes:
      if attrValues[0].startswith(prefix):
        break
    else:
      prefix = self.homeDirectoryPrefixes[0]
    return ['/'.join((prefix,uid))]

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )
    input_field.charset = self._form.accept_charset
    return input_field

syntax_registry.registerAttrType(
  AEHomeDirectory.oid,[
    '1.3.6.1.1.1.1.3', # homeDirectory
  ],
  structural_oc_oids=[AE_USER_OID,AE_SERVICE_OID], # aeUser and aeService
)


class AEUIDNumber(UidNumber):
  oid = 'AEUIDNumber-oid'
  desc = 'numeric Unix-UID'

  def transmute(self,attrValues):
    return self._entry.get('gidNumber',[''])

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )
    input_field.charset = self._form.accept_charset
    return input_field

syntax_registry.registerAttrType(
  AEUIDNumber.oid,[
    '1.3.6.1.1.1.1.0', # uidNumber
  ],
  structural_oc_oids=[
    AE_USER_OID,    # aeUser
    AE_SERVICE_OID, # aeService
  ],
)


class AEGIDNumber(GidNumber):
  oid = 'AEGIDNumber-oid'
  desc = 'numeric Unix-GID'
  minNewValue = 30000L
  maxNewValue = 49999L
  id_pool_dn = None

  def _get_id_pool_dn(self):
    """
    determine which ID pool entry to use
    """
    return self.id_pool_dn or self._ls.currentSearchRoot.encode(self._ls.charset)

  def _get_next_gid(self):
    """
    consumes next ID by sending MOD_INCREMENT modify operation with
    pre-read entry control
    """
    prc = PreReadControl(criticality=True, attrList=[self.attrType])
    msg_id = self._ls.l.modify(
        self._get_id_pool_dn(),
        [(ldap0.MOD_INCREMENT, self.attrType, '1')],
        serverctrls=[prc],
    )
    _, _, _, resp_ctrls, _, _ = self._ls.l.result(msg_id)
    return int(resp_ctrls[0].entry[self.attrType][0])

  def transmute(self,attrValues):
    attrValues = GidNumber.transmute(self,attrValues)
    if attrValues and attrValues[0]:
      return attrValues
    # first try to re-read gidNumber from existing entry
    try:
      ldap_result = self._ls.readEntry(
        self._dn,
        attrtype_list=[self.attrType],
        search_filter='({0}=*)'.format(self.attrType),
      )
    except (
      ldap0.NO_SUCH_OBJECT,
      ldap0.INSUFFICIENT_ACCESS,
    ):
      # search failed => ignore
      pass
    else:
      if ldap_result:
        return ldap_result[0][1][self.attrType]
    # return next ID from pool entry
    return [str(self._get_next_gid())] # formValue()

  def formValue(self):
    return Integer.formValue(self)

  def formField(self):
    return Integer.formField(self)

syntax_registry.registerAttrType(
  AEGIDNumber.oid,[
    '1.3.6.1.1.1.1.1', # gidNumber
  ],
  structural_oc_oids=[
    AE_USER_OID,    # aeUser
    AE_GROUP_OID,   # aeGroup
    AE_SERVICE_OID, # aeService
  ],
)


class AEUid(IA5String):
  oid = 'AEUid-oid'
  simpleSanitizers = (
    str.strip,
    str.lower,
  )


class AEUserUid(AEUid):
  """
  Class for auto-generating values for aeUser -> uid
  """
  oid = 'AEUserUid-oid'
  desc = 'AE-DIR: User name'
  maxValues = 1
  minLen = 4
  maxLen = 4
  maxCollisionChecks = 15
  UID_LETTERS = 'abcdefghijklmnopqrstuvwxyz'
  reobj = re.compile('^%s$' % (UID_LETTERS))
  genLen = 4
  simpleSanitizers = (
    str.strip,
    str.lower,
  )

  def __init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=None):
    IA5String.__init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=entry)

  def _genUid(self):
    gen_collisions = 0
    while gen_collisions < self.maxCollisionChecks:
      # generate new random UID candidate
      uid_candidate = random_string(alphabet=self.UID_LETTERS,length=self.genLen)
      # check whether UID candidate already exists
      uid_result = self._ls.l.search_s(
        self._ls.currentSearchRoot.encode(self._ls.charset),
        ldap0.SCOPE_SUBTREE,
        '(uid=%s)' % (escape_filter_chars(uid_candidate)),
        attrlist=['1.1'],
      )
      if not uid_result:
        return uid_candidate
      gen_collisions += 1
    raise web2ldap.app.core.ErrorExit(
      u'Gave up generating new unique <em>uid</em> after %d attempts.' % (gen_collisions)
    )
    return  # _genUid()

  def formValue(self):
    form_value = IA5String.formValue(self)
    if not self.attrValue:
      form_value = self._genUid().decode()
    return form_value

  def formField(self):
    return HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )

  def sanitizeInput(self,attrValue):
    return attrValue.strip().lower()

syntax_registry.registerAttrType(
  AEUserUid.oid,[
    '0.9.2342.19200300.100.1.1', # uid
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ],
)


class AEServiceUid(AEUid):
  oid = 'AEServiceUid-oid'

syntax_registry.registerAttrType(
  AEServiceUid.oid,[
    '0.9.2342.19200300.100.1.1', # uid
  ],
  structural_oc_oids=[
    AE_SERVICE_OID, # aeService
  ],
)


class AETicketId(IA5String):
  oid = 'AETicketId-oid'
  desc = 'AE-DIR: Ticket no. related to last change of entry'
  simpleSanitizers = (
    str.upper,
    str.strip,
  )

syntax_registry.registerAttrType(
  AETicketId.oid,[
    AE_OID_PREFIX+'.4.3', # aeTicketId
  ]
)


class AEZoneDN(DynamicDNSelectList):
  oid = 'AEZoneDN-oid'
  desc = 'AE-DIR: Zone'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeZone)(aeStatus=0))'
  ref_attrs = (
    (None,u'Same zone',None,u'Search all groups constrained to same zone'),
  )

syntax_registry.registerAttrType(
  AEZoneDN.oid,[
    AE_OID_PREFIX+'.4.36', # aeMemberZone
  ]
)


class AEHost(DynamicDNSelectList):
  oid = 'AEHost-oid'
  desc = 'AE-DIR: Host'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_?host?sub?(&(objectClass=aeHost)(aeStatus=0))'
  ref_attrs = (
    (None,u'Same host',None,u'Search all services running on same host'),
  )

syntax_registry.registerAttrType(
  AEHost.oid,[
    AE_OID_PREFIX+'.4.28', # aeHost
  ]
)


class AENwDevice(DynamicDNSelectList):
  oid = 'AENwDevice-oid'
  desc = 'AE-DIR: network interface'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///..?cn?sub?(&(objectClass=aeNwDevice)(aeStatus=0))'
  ref_attrs = (
    (None,u'Siblings',None,u'Search sibling network devices'),
  )

  def _determineSearchDN(self,current_dn,ldap_url_dn):
    if self._dn.startswith('host='):
      return self._dn
    else:
      return DynamicDNSelectList._determineSearchDN(self,current_dn,ldap_url_dn)

  def _determineFilter(self):
    orig_filter = DynamicDNSelectList._determineFilter(self)
    try:
      dev_name = self._entry['cn'][0]
    except (KeyError,IndexError):
      result_filter = orig_filter
    else:
      result_filter = '(&{0}(!(cn={1})))'.format(orig_filter,dev_name)
    return result_filter

syntax_registry.registerAttrType(
  AENwDevice.oid,[
    AE_OID_PREFIX+'.4.34', # aeNwDevice
  ]
)


class AEGroupMember(DynamicDNSelectList,AEObjectUtil):
  oid = 'AEGroupMember-oid'
  desc = 'AE-DIR: Member of a group'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_?displayName?sub?(&(|(objectClass=aeUser)(objectClass=aeService))(aeStatus=0))'
  deref_person_attrs = ('aeDept','aeLocation')

  def _zone_filter(self):
    member_zones = filter(None,self._entry.get('aeMemberZone',[]))
    if member_zones:
      member_zone_filter = compose_filter(
        '|',
        map_filter_parts('entryDN:dnSubordinateMatch:',member_zones),
      )
    else:
      member_zone_filter = ''
    return member_zone_filter

  def _deref_person_attrset(self):
    result = {}
    for attr_type in self.deref_person_attrs:
      if attr_type in self._entry and filter(None,self._entry[attr_type]):
        result[attr_type] = set(self._entry[attr_type])
    return result

  def _determineFilter(self):
    return '(&{0}{1})'.format(
      DynamicDNSelectList._determineFilter(self),
      self._zone_filter(),
    )

  def _get_attr_value_dict(self):
    deref_person_attrset = self._deref_person_attrset()
    if not deref_person_attrset:
      return DynamicDNSelectList._get_attr_value_dict(self)
    if deref_person_attrset:
      srv_ctrls = [DereferenceControl(True, {'aePerson': deref_person_attrset.keys()})]
    else:
      srv_ctrls = None
    # Use the existing LDAP connection as current user
    attr_value_dict = SelectList._get_attr_value_dict(self)
    try:
      ldap_result = self._ls.l.search_s(
        self._ls.uc_encode(self._determineSearchDN(self._dn,self.lu_obj.dn))[0],
        self.lu_obj.scope or ldap0.SCOPE_SUBTREE,
        filterstr=self._determineFilter(),
        attrlist=self.lu_obj.attrs+['description'],
        serverctrls=srv_ctrls,
        add_ctrls=1,
      )
      for dn,entry,controls in ldap_result:
        if dn is None:
          # ignore search continuations
          continue
        # process dn and entry
        if controls:
            deref_control = controls[0]
            _,deref_entry = deref_control.derefRes['aePerson'][0]
        elif deref_person_attrset:
          # if we have constrained attributes, no deref response control
          # means constraint not valid
          continue
        # check constrained values here
        valid = True
        for attr_type,attr_values in deref_person_attrset.items():
          if attr_type not in deref_entry or \
             deref_entry[attr_type][0] not in attr_values:
            valid = False
        if valid:
          option_value = self._ls.uc_decode(dn)[0]
          try:
            option_text = self._ls.uc_decode(entry['displayName'][0])[0]
          except KeyError:
            option_text = option_value
          try:
            entry_desc = entry['description'][0]
          except KeyError:
            option_title = option_value
          else:
            option_title = self._ls.uc_decode(entry_desc)[0]
          attr_value_dict[option_value] = (option_text,option_title)
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

  def _validate(self,attrValue):
    if 'memberURL' in self._entry:
      # reduce to simple DN syntax check for dynamic groups
      return DistinguishedName._validate(self,attrValue)
    return SelectList._validate(self,attrValue)

syntax_registry.registerAttrType(
  AEGroupMember.oid,[
    '2.5.4.31', # member
  ],
  structural_oc_oids=[
    AE_GROUP_OID, # aeGroup
  ],
)


class AEMailGroupMember(AEGroupMember):
  oid = 'AEMailGroupMember-oid'
  desc = 'AE-DIR: Member of a mail group'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_?displayName?sub?(&(|(objectClass=inetLocalMailRecipient)(objectClass=aeContact))(mail=*)(aeStatus=0))'

syntax_registry.registerAttrType(
  AEMailGroupMember.oid,[
    '2.5.4.31', # member
  ],
  structural_oc_oids=[
    AE_MAILGROUP_OID, # aeMailGroup
  ],
)


class AEMemberUid(MemberUID):
  oid = 'AEMemberUid-oid'
  desc = 'AE-DIR: username (uid) of member of a group'
  ldap_url = None
  showValueButton = False

  def _member_uids_from_member(self):
    return [
      dn[4:].split(',')[0]
      for dn in self._entry.get('member',[])
    ]

  # Because AEMemberUid.transmute() always resets all attribute values it's
  # ok to not validate values thoroughly
  def _validate(self,attrValue):
    return MemberUID._validate(self,attrValue) and \
           attrValue in set(self._member_uids_from_member())

  def transmute(self,attrValues):
    return filter(None,self._member_uids_from_member())

  def formValue(self):
    return u''

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
    )
    input_field.charset = self._form.accept_charset
    input_field.setDefault(self.formValue())
    return input_field

syntax_registry.registerAttrType(
  AEMemberUid.oid,[
    '1.3.6.1.1.1.1.12', # memberUID
  ],
  structural_oc_oids=[
    AE_GROUP_OID,     # aeGroup
  ],
)


class AEGroupDN(DynamicDNSelectList):
  oid = 'AEGroupDN-oid'
  desc = 'AE-DIR: DN of user group entry'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_??sub?(&(|(objectClass=aeGroup)(objectClass=aeMailGroup))(aeStatus=0))'
  ref_attrs = (
    ('memberOf',u'Members',None,u'Search all member entries of this user group'),
  )

  def displayValue(self,valueindex=0,commandbutton=0):
    dn_comp_list = ldap0.dn.str2dn(self.attrValue)
    group_cn = dn_comp_list[0][0][1].decode(self._ls.charset)
    parent_dn = ldap0.dn.dn2str(dn_comp_list[1:]).decode(self._ls.charset)
    r = [
      'cn=<strong>{0}</strong>,{1}'.format(
        self._form.utf2display(group_cn),
        self._form.utf2display(parent_dn),
      ).encode()
    ]
    if commandbutton:
      r.extend(self._additional_links())
    return web2ldapcnf.command_link_separator.join(r)

syntax_registry.registerAttrType(
  AEGroupDN.oid,[
    '1.2.840.113556.1.2.102', # memberOf
  ],
  structural_oc_oids=[
    AE_USER_OID,    # aeUser
    AE_SERVICE_OID, # aeService
  ],
)


class AEZoneAdminGroupDN(AEGroupDN):
  oid = 'AEZoneAdminGroupDN-oid'
  desc = 'AE-DIR: DN of zone admin group entry'
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

syntax_registry.registerAttrType(
  AEZoneAdminGroupDN.oid,[
    AE_OID_PREFIX+'.4.31',  # aeZoneAdmins
    AE_OID_PREFIX+'.4.33',  # aePasswordAdmins
  ]
)


class AEZoneAuditorGroupDN(AEGroupDN):
  oid = 'AEZoneAuditorGroupDN-oid'
  desc = 'AE-DIR: DN of zone auditor group entry'
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

syntax_registry.registerAttrType(
  AEZoneAuditorGroupDN.oid,[
    AE_OID_PREFIX+'.4.32',  # aeZoneAuditors
  ]
)


class AESrvGroupRightsGroupDN(AEGroupDN):
  oid = 'AESrvGroupRightsGroupDN-oid'
  desc = 'AE-DIR: DN of user group entry'
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

syntax_registry.registerAttrType(
  AESrvGroupRightsGroupDN.oid,[
    AE_OID_PREFIX+'.4.4',  # aeLoginGroups
    AE_OID_PREFIX+'.4.6',  # aeSetupGroups
    AE_OID_PREFIX+'.4.7',  # aeLogStoreGroups
  ]
)


class AEDisplayNameGroups(AESrvGroupRightsGroupDN):
  oid = 'AEDisplayNameGroups-oid'
  desc = 'AE-DIR: DN of visible user group entry'
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

syntax_registry.registerAttrType(
  AEDisplayNameGroups.oid,[
    AE_OID_PREFIX+'.4.30', # aeDisplayNameGroups
  ]
)


class AEVisibleGroups(AEDisplayNameGroups):
  oid = 'AEVisibleGroups-oid'
  desc = 'AE-DIR: DN of visible user group entry'
  always_add_groups = (
    'aeLoginGroups',
    'aeDisplayNameGroups',
  )

  def transmute(self,attrValues):
    attrValues = set(attrValues)
    for attr_type in self.always_add_groups:
      attrValues.update(self._entry.get(attr_type,[]))
    return list(attrValues)

syntax_registry.registerAttrType(
  AEVisibleGroups.oid,[
    AE_OID_PREFIX+'.4.20', # aeVisibleGroups
  ]
)


class AESameZoneObject(DynamicDNSelectList,AEObjectUtil):
  oid = 'AESameZoneObject-oid'
  desc = 'AE-DIR: DN of referenced aeSrvGroup entry this is proxy for'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeObject)(aeStatus=0))'

  def _determineSearchDN(self,current_dn,ldap_url_dn):
    return self._get_zone_dn()


class AESrvGroup(AESameZoneObject):
  oid = 'AESrvGroup-oid'
  desc = 'AE-DIR: DN of referenced aeSrvGroup entry'
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0)(!(aeProxyFor=*)))'

  def _determineFilter(self):
    filter_str = self.lu_obj.filterstr or '(objectClass=*)'
    dn_u = self._dn.decode(self._ls.charset)
    parent_dn = web2ldap.ldaputil.base.ParentDN(dn_u)
    return '(&%s(!(entryDN=%s)))' % (
      filter_str,
      parent_dn.encode(self._ls.charset),
    )

syntax_registry.registerAttrType(
  AESrvGroup.oid,[
    AE_OID_PREFIX+'.4.27',  # aeSrvGroup
  ]
)


class AEProxyFor(AESameZoneObject,AEObjectUtil):
  oid = 'AEProxyFor-oid'
  desc = 'AE-DIR: DN of referenced aeSrvGroup entry this is proxy for'
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSrvGroup)(aeStatus=0)(!(aeProxyFor=*)))'

  def _determineFilter(self):
    filter_str = self.lu_obj.filterstr or '(objectClass=*)'
    return '(&%s(!(entryDN=%s)))' % (
      filter_str,
      self._dn.encode(self._ls.charset),
    )

syntax_registry.registerAttrType(
  AEProxyFor.oid,[
    AE_OID_PREFIX+'.4.25',  # aeProxyFor
  ]
)


class AETag(DynamicValueSelectList):
  oid = 'AETag-oid'
  desc = 'AE-DIR: cn of referenced aeTag entry'
  ldap_url = 'ldap:///_?cn,cn?sub?(&(objectClass=aeTag)(aeStatus=0))'

syntax_registry.registerAttrType(
  AETag.oid,[
    AE_OID_PREFIX+'.4.24',  # aeTag
  ]
)


class AEEntryDNAEPerson(DistinguishedName):
  oid = 'AEEntryDNAEPerson-oid'
  desc = 'AE-DIR: entryDN of aePerson entry'
  ref_attrs = (
    ('manager',u'Manages',None,u'Search all entries managed by this person'),
    ('aePerson',u'Users',None,'aeUser',u'Search all personal AE-DIR user accounts (aeUser entries) of this person.'),
    ('aeOwner',u'Devices',None,'aeDevice',u'Search all devices (aeDevice entries) assigned to this person.'),
  )

syntax_registry.registerAttrType(
  AEEntryDNAEPerson.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
  ],
)


class AEEntryDNAEUser(DistinguishedName):
  oid = 'AEEntryDNAEUser-oid'
  desc = 'AE-DIR: entryDN of aeUser entry'

  def _additional_links(self):
    attr_value_u = self.attrValue.decode(self._ls.charset)
    r = DistinguishedName._additional_links(self)
    audit_context = self._ls.getAuditContext(self._ls.currentSearchRoot)
    if audit_context:
      r.append(self._form.applAnchor(
        'search','Activity',self._sid,
        (
          ('dn',audit_context),
          ('searchform_mode','adv'),
          ('search_attr','objectClass'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string','auditObject'),
          ('search_attr','reqAuthzID'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string',attr_value_u),
        ),
        title=u'Search modifications made by %s in accesslog DB' % (attr_value_u),
      ))
    return r

syntax_registry.registerAttrType(
  AEEntryDNAEUser.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ],
)


class AEEntryDNAEHost(DistinguishedName):
  oid = 'AEEntryDNAEHost-oid'
  desc = 'AE-DIR: entryDN of aeUser entry'
  ref_attrs = (
    ('aeHost',u'Services',None,u'Search all services running on this host'),
  )

  def _additional_links(self):
    attr_value_u = self.attrValue.decode(self._ls.charset)
    parent_dn = web2ldap.ldaputil.base.ParentDN(attr_value_u)
    aesrvgroup_filter = u''.join([
      u'(aeSrvGroup=%s)' % av.decode(self._ls.charset)
      for av in self._entry.get('aeSrvGroup',[])
    ])
    r = DistinguishedName._additional_links(self)
    r.extend([
      self._form.applAnchor(
        'search','Siblings',self._sid,
        (
          ('dn',self._dn),
          ('search_root',self._ls.currentSearchRoot),
          ('searchform_mode',u'exp'),
          (
            'filterstr',
            u'(&(|(objectClass=aeHost)(objectClass=aeService))(|(entryDN:dnSubordinateMatch:=%s)%s))' % (
              parent_dn,
              aesrvgroup_filter,
            )
          ),
        ),
        title=u'Search all host entries which are member in at least one common server group(s) with this host',
      ),
    ])
    return r

syntax_registry.registerAttrType(
  AEEntryDNAEHost.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_HOST_OID, # aeHost
  ],
)


class AEEntryDNAEZone(DistinguishedName):
  oid = 'AEEntryDNAEZone-oid'
  desc = 'AE-DIR: entryDN of aeZone entry'

  def _additional_links(self):
    attr_value_u = self.attrValue.decode(self._ls.charset)
    r = DistinguishedName._additional_links(self)
    audit_context = self._ls.getAuditContext(self._ls.currentSearchRoot)
    if audit_context:
      r.append(self._form.applAnchor(
        'search','Audit all',self._sid,
        (
          ('dn',audit_context),
          ('searchform_mode','adv'),
          ('search_attr','objectClass'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string','auditObject'),
          ('search_attr','reqDN'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_DN_SUBTREE),
          ('search_string',attr_value_u),
        ),
        title=u'Search all audit log entries for sub-tree %s' % (attr_value_u),
      ))
      r.append(self._form.applAnchor(
        'search','Audit writes',self._sid,
        (
          ('dn',audit_context),
          ('searchform_mode','adv'),
          ('search_attr','objectClass'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string','auditObject'),
          ('search_attr','reqDN'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_DN_SUBTREE),
          ('search_string',attr_value_u),
        ),
        title=u'Search audit log entries for write operation within sub-tree %s' % (attr_value_u),
      ))
    return r

syntax_registry.registerAttrType(
  AEEntryDNAEZone.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_ZONE_OID, # aeZone
  ],
)


class AEEntryDNAEMailGroup(GroupEntryDN):
  oid = 'AEEntryDNAEMailGroup-oid'
  desc = 'AE-DIR: entryDN of aeGroup entry'
  ref_attrs = [
    ('memberOf',u'Members',None,u'Search all member entries of this mail group'),
    ('aeVisibleGroups',u'Visible',None,u'Search all server/service groups (aeSrvGroup)\non which this mail group is visible'),
  ]

syntax_registry.registerAttrType(
  AEEntryDNAEMailGroup.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_MAILGROUP_OID, # aeMailGroup
  ],
)


class AEEntryDNAEGroup(GroupEntryDN):
  oid = 'AEEntryDNAEGroup-oid'
  desc = 'AE-DIR: entryDN of aeGroup entry'
  ref_attrs = [
    ('memberOf',u'Members',None,u'Search all member entries of this user group'),
    ('aeLoginGroups',u'Login',None,u'Search all server/service groups (aeSrvGroup)\non which this user group has login right'),
    ('aeLogStoreGroups',u'View Logs',None,u'Search all server/service groups (aeSrvGroup)\non which this user group has log view right'),
    ('aeSetupGroups',u'Setup',None,u'Search all server/service groups (aeSrvGroup)\non which this user group has setup/installation rights'),
    ('aeVisibleGroups',u'Visible',None,u'Search all server/service groups (aeSrvGroup)\non which this user group is at least visible'),
  ]

  def _additional_links(self):
    aegroup_cn = self._entry['cn'][0]
    ref_attrs = list(AEEntryDNAEGroup.ref_attrs)
    if aegroup_cn.endswith('zone-admins'):
      ref_attrs.extend([
        ('aeZoneAdmins',u'Zone Admins',None,u'Search all zones (aeZone)\nfor which members of this user group act as zone admins'),
        ('aePasswordAdmins',u'Password Admins',None,u'Search all zones (aeZone)\nfor which members of this user group act as password admins'),
      ])
    if aegroup_cn.endswith('zone-auditors') or aegroup_cn.endswith('zone-admins'):
      ref_attrs.append(
        ('aeZoneAuditors',u'Zone Auditors',None,u'Search all zones (aeZone)\nfor which members of this user group act as zone auditors'),
      )
    self.ref_attrs = tuple(ref_attrs)
    r = DistinguishedName._additional_links(self)
    r.append(self._form.applAnchor(
      'search','SUDO rules',self._sid,
      (
        ('dn',self._dn),
        ('search_root',self._ls.currentSearchRoot),
        ('searchform_mode','adv'),
        ('search_attr','sudoUser'),
        ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
        (
          'search_string','%'+self._entry['cn'][0].decode(self._ls.charset),
        ),
      ),
      title=u'Search for SUDO rules\napplicable with this user group',
    ))
    return r

syntax_registry.registerAttrType(
  AEEntryDNAEGroup.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_GROUP_OID, # aeGroup
  ],
)


class AEEntryDNAESrvGroup(DistinguishedName):
  oid = 'AEEntryDNAESrvGroup-oid'
  desc = 'AE-DIR: entryDN'
  ref_attrs = (
    ('aeProxyFor',u'Proxy',None,u'Search access gateway/proxy group for this server group'),
  )

  def _additional_links(self):
    attr_value_u = self.attrValue.decode(self._ls.charset)
    r = DistinguishedName._additional_links(self)
    r.append(
      self._form.applAnchor(
        'search','All members',self._sid,
        (
          ('dn',self._dn),
          ('search_root',self._ls.currentSearchRoot),
          ('searchform_mode',u'exp'),
          (
            'filterstr',
            u'(&(|(objectClass=aeHost)(objectClass=aeService))(|(entryDN:dnSubordinateMatch:={0})(aeSrvGroup={0})))'.format(attr_value_u)
          ),
        ),
        title=u'Search all service and host entries which are member in this service/host group {0}'.format(attr_value_u),
      )
    )
    return r


syntax_registry.registerAttrType(
  AEEntryDNAESrvGroup.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_SRVGROUP_OID, # aeSrvGroup
  ],
)


class AEEntryDNSudoRule(DistinguishedName):
  oid = 'AEEntryDNSudoRule-oid'
  desc = 'AE-DIR: entryDN'
  ref_attrs = (
    ('aeVisibleSudoers',u'Used on',None,u'Search all server groups (aeSrvGroup entries) referencing this SUDO rule'),
  )

syntax_registry.registerAttrType(
  AEEntryDNSudoRule.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_SUDORULE_OID, # aeSudoRule
  ],
)


class AEEntryDNAELocation(DistinguishedName):
  oid = 'AEEntryDNAELocation-oid'
  desc = 'AE-DIR: entryDN of aeLocation entry'
  ref_attrs = (
    ('aeLocation',u'Persons',None,'aePerson',u'Search all persons assigned to this location.'),
    ('aeLocation',u'Zones',None,'aeZone',u'Search all location-based zones associated with this location.'),
    ('aeLocation',u'Groups',None,'groupOfEntries',u'Search all location-based zones associated with this location.'),
  )

syntax_registry.registerAttrType(
  AEEntryDNAELocation.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_LOCATION_OID, # aeLocation
  ],
)


class AELocation(DynamicDNSelectList):
  oid = 'AELocation-oid'
  desc = 'AE-DIR: DN of location entry'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aeLocation)(aeStatus=0))'
  ref_attrs = AEEntryDNAELocation.ref_attrs

syntax_registry.registerAttrType(
  AELocation.oid,[
    AE_OID_PREFIX+'.4.35', # aeLocation
  ]
)


class AEEntryDNAEDept(DistinguishedName):
  oid = 'AEEntryDNAEDept-oid'
  desc = 'AE-DIR: entryDN of aePerson entry'
  ref_attrs = (
    ('aeDept',u'Persons',None,'aePerson',u'Search all persons assigned to this department.'),
    ('aeDept',u'Zones',None,'aeZone',u'Search all team-related zones associated with this department.'),
    ('aeDept',u'Groups',None,'groupOfEntries',u'Search all team-related groups associated with this department.'),
  )

syntax_registry.registerAttrType(
  AEEntryDNAEDept.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_DEPT_OID, # aeDept
  ],
)


class AEDept(DynamicDNSelectList):
  oid = 'AEDept-oid'
  desc = 'AE-DIR: DN of department entry'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aeDept)(aeStatus=0))'
  ref_attrs = AEEntryDNAEDept.ref_attrs

syntax_registry.registerAttrType(
  AEDept.oid,[
    AE_OID_PREFIX+'.4.29', # aeDept
  ]
)


class AEOwner(DynamicDNSelectList):
  oid = 'AEOwner-oid'
  desc = 'AE-DIR: DN of owner entry'
  ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aePerson)(aeStatus=0))'
  ref_attrs = (
    ('aeOwner',u'Devices',None,'aeDevice',u'Search all devices (aeDevice entries) assigned to same owner.'),
  )

syntax_registry.registerAttrType(
  AEOwner.oid,[
    AE_OID_PREFIX+'.4.2', # aeOwner
  ]
)


class AEPerson(DynamicDNSelectList,AEObjectUtil):
  oid = 'AEPerson-oid'
  desc = 'AE-DIR: DN of person entry'
  ldap_url = 'ldap:///_?displayName?sub?(objectClass=aePerson)'
  ref_attrs = (
    ('aePerson',u'Users',None,'aeUser',u'Search all personal AE-DIR user accounts (aeUser entries) of this person.'),
  )
  ae_status_map = {
    -1:(0,),
    0:(0,),
    1:(0,1,2),
    2:(0,1,2),
  }
  deref_attrs = ('aeDept','aeLocation')

  def _status_filter(self):
    try:
      ae_status = int(self._entry['aeStatus'][0])
    except (KeyError,ValueError,IndexError):
      ae_status = 0
    return compose_filter(
      '|',
      map_filter_parts(
        'aeStatus',
        map(str,self.ae_status_map.get(ae_status,[])),
      ),
    )

  def _determineFilter(self):
    filter_components = [
      DynamicDNSelectList._determineFilter(self),
      self._status_filter(),
      # ae_validity_filter(),
    ]
    zone_entry = self._zone_entry(attrlist=self.deref_attrs) or {}
    for deref_attr_type in self.deref_attrs:
      deref_attr_values = filter(None,zone_entry.get(deref_attr_type,[]))
      if deref_attr_values:
        filter_components.append(
          compose_filter(
            '|',
            map_filter_parts(deref_attr_type,deref_attr_values),
          )
        )
    ocs = self._entry.object_class_oid_set()
    if 'inetLocalMailRecipient' not in ocs:
      filter_components.append('(mail=*)')
    filter_str = '(&{})'.format(''.join(filter_components))
    return filter_str


class AEPerson2(AEPerson):
  oid = 'AEPerson2-oid'
  sanitize_filter_tmpl = '(|(cn={av}*)(uniqueIdentifier={av})(employeeNumber={av})(displayName={av})(mail={av}))'

  def formValue(self):
    form_value = DistinguishedName.formValue(self)
    if self.attrValue:
      person_entry = self._readReferencedEntry(self.attrValue)
      if person_entry:
        form_value = person_entry.get('displayName',[form_value])[0].decode(self._form.accept_charset)
    return form_value

  def formField(self):
    return DistinguishedName.formField(self)

  def transmute(self,attrValues):
    if not attrValues or not attrValues[0]:
      return attrValues
    sanitize_filter = '(&{0}{1})'.format(
        self._determineFilter(),
        self.sanitize_filter_tmpl.format(
          av=escape_filter_chars(attrValues[0]),
        )
    )
    try:
      ldap_result = self._ls.l.search_s(
        self._ls.uc_encode(self._determineSearchDN(self._dn,self.lu_obj.dn))[0],
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
    else:
      if ldap_result and len(ldap_result)==1:
        return [ldap_result[0][0]]
      else:
        return attrValues

syntax_registry.registerAttrType(
  AEPerson.oid,[
    AE_OID_PREFIX+'.4.16', # aePerson
  ]
)


class AEManager(DynamicDNSelectList):
  oid = 'AEManager-oid'
  desc = 'AE-DIR: Manager responsible for a person/department'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_?displayName?sub?(&(objectClass=aePerson)(aeStatus=0))'

syntax_registry.registerAttrType(
  AEManager.oid,[
    '0.9.2342.19200300.100.1.10', # manager
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
    AE_DEPT_OID, # aeDept
  ]
)


class AEDerefAttribute(DirectoryString):
  oid = 'AEDerefAttribute-oid'
  maxValues = 1
  deref_object_class = None
  deref_attribute_type = None
  deref_filter_tmpl = '(&(objectClass={deref_object_class})(aeStatus=0)({attribute_type}=*))'

  def _readPersonAttribute(self):
    try:
      ldap_result = self._ls.readEntry(
        self._entry[self.deref_attribute_type][0].decode(self._ls.charset),
        attrtype_list=[self.attrType],
        search_filter=self.deref_filter_tmpl.format(
          deref_object_class=self.deref_object_class,
          attribute_type=self.attrType,
        ),
      )
    except ldap0.LDAPError:
      result = None
    else:
      if ldap_result:
        _,person_entry = ldap_result[0]
        result = person_entry[self.attrType][0].decode(self._ls.charset)
      else:
        result = None
    return result

  def transmute(self,attrValues):
    if self.deref_attribute_type in self._entry:
      ae_person_attribute = self._readPersonAttribute()
      if ae_person_attribute!=None:
        result = [ae_person_attribute.encode(self._ls.charset)]
      else:
        raise KeyError
    else:
      result = attrValues
    return result

  def formValue(self):
    return u''

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
    )
    input_field.charset = self._form.accept_charset
    input_field.setDefault(self.formValue())
    return input_field


class AEPersonAttribute(AEDerefAttribute):
  oid = 'AEPersonAttribute-oid'
  maxValues = 1
  deref_object_class = 'aePerson'
  deref_attribute_type = 'aePerson'


class AEUserNames(AEPersonAttribute,DirectoryString):
  oid = 'AEUserNames-oid'

syntax_registry.registerAttrType(
  AEUserNames.oid,[
    '2.5.4.4', # sn
    '2.5.4.42', # givenName
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ],
)


class AEMailLocalAddress(RFC822Address):
  oid = 'AEMailLocalAddress-oid'
  simpleSanitizers = (
    str.strip,
    str.lower,
  )

syntax_registry.registerAttrType(
  AEMailLocalAddress.oid,[
    '2.16.840.1.113730.3.1.13', # mailLocalAddress
  ],
  structural_oc_oids=[
    AE_USER_OID,    # aeUser
    AE_SERVICE_OID, # aeService
  ],
)


class AEUserMailaddress(AEPersonAttribute,SelectList):
  oid = 'AEUserMailaddress-oid'
  html_tmpl = RFC822Address.html_tmpl
  maxValues = 1
  input_fallback = False
  simpleSanitizers = AEMailLocalAddress.simpleSanitizers

  def _get_attr_value_dict(self):
    attr_value_dict = {
      u'':u'-/-',
    }
    attr_value_dict.update([
      (addr.decode(self._ls.charset),addr.decode(self._ls.charset))
      for addr in self._entry.get('mailLocalAddress',[])
    ])
    return attr_value_dict

  def _is_mail_account(self):
    return 'inetLocalMailRecipient' in self._entry['objectClass']

  def _validate(self,attrValue):
    if self._is_mail_account():
      return SelectList._validate(self,attrValue)
    else:
      return AEPersonAttribute._validate(self,attrValue)

  def formValue(self):
    if self._is_mail_account():
      return SelectList.formValue(self)
    else:
      return AEPersonAttribute.formValue(self)

  def transmute(self,attrValues):
    if self._is_mail_account():
      # make sure only non-empty strings are in attribute value list
      if not filter(None,map(str.strip,attrValues)):
        try:
          attrValues = [self._entry['mailLocalAddress'][0]]
        except KeyError:
          attrValues = []
    else:
      attrValues = AEPersonAttribute.transmute(self,attrValues)
    return attrValues

  def formField(self):
    if self._is_mail_account():
      return SelectList.formField(self)
    else:
      return AEPersonAttribute.formField(self)

syntax_registry.registerAttrType(
  AEUserMailaddress.oid,[
    '0.9.2342.19200300.100.1.3', # mail
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ],
)


class AEPersonMailaddress(DynamicValueSelectList,RFC822Address):
  oid = 'AEPersonMailaddress-oid'
  maxValues = 1
  ldap_url = 'ldap:///_?mail,mail?sub?'
  input_fallback = True
  html_tmpl = RFC822Address.html_tmpl

  def _validate(self,attrValue):
    if not RFC822Address._validate(self,attrValue):
      return False
    attr_value_dict = self._get_attr_value_dict()
    if not attr_value_dict or attr_value_dict.keys()==[u'']:
      return True
    return DynamicValueSelectList._validate(self,attrValue)

  def _determineFilter(self):
    return (
      '(&'
        '(objectClass=aeUser)'
        '(objectClass=inetLocalMailRecipient)'
        '(aeStatus=0)'
        '(aePerson=%s)'
        '(mailLocalAddress=*)'
      ')'
    ) % self._ls.uc_encode(self._dn)[0]

syntax_registry.registerAttrType(
  AEPersonMailaddress.oid,[
    '0.9.2342.19200300.100.1.3', # mail
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
  ],
)


class AEDeptAttribute(AEDerefAttribute,DirectoryString):
  oid = 'AEDeptAttribute-oid'
  maxValues = 1
  deref_object_class = 'aeDept'
  deref_attribute_type = 'aeDept'

syntax_registry.registerAttrType(
  AEDeptAttribute.oid,[
    '2.16.840.1.113730.3.1.2', # departmentNumber
    '2.5.4.11',                # ou, organizationalUnitName
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
  ],
)


class AEHostname(DNSDomain):
  oid = 'AEHostname-oid'
  desc = 'Canonical hostname / FQDN'
  host_lookup = 0

  def _validate(self,attrValue):
    if not DNSDomain._validate(self,attrValue):
      return False
    if self.host_lookup:
      try:
        ip_addr = socket.gethostbyname(attrValue)
      except (socket.gaierror,socket.herror):
        return False
      if self.host_lookup>=2:
        try:
          reverse_hostname = socket.gethostbyaddr(ip_addr)[0]
        except (socket.gaierror,socket.herror):
          return False
        else:
          return reverse_hostname==attrValue
    return True

  def transmute(self,attrValues):
    result = []
    for attr_value in attrValues:
      attr_value.lower().strip()
      if self.host_lookup:
        try:
          ip_addr = socket.gethostbyname(attr_value)
          reverse_hostname = socket.gethostbyaddr(ip_addr)[0]
        except (socket.gaierror,socket.herror):
          pass
        else:
          attr_value = reverse_hostname
      result.append(attr_value)
    return attrValues

syntax_registry.registerAttrType(
  AEHostname.oid,[
    '0.9.2342.19200300.100.1.9', # host
  ],
  structural_oc_oids=[
    AE_HOST_OID, # aeHost
  ],
)


class AEDisplayNameUser(ComposedAttribute,DirectoryString):
  oid = 'AEDisplayNameUser-oid'
  desc = 'Attribute displayName in object class aeUser'
  compose_templates = (
    '{givenName} {sn} ({uid}/{uidNumber})',
    '{givenName} {sn} ({uid})',
  )

syntax_registry.registerAttrType(
  AEDisplayNameUser.oid,[
    '2.16.840.1.113730.3.1.241', # displayName
  ],
  structural_oc_oids=[AE_USER_OID], # aeUser
)


class AEDisplayNameContact(ComposedAttribute,DirectoryString):
  oid = 'AEDisplayNameContact-oid'
  desc = 'Attribute displayName in object class aeContact'
  compose_templates = (
    '{cn} <{mail}>',
    '{cn}',
  )

syntax_registry.registerAttrType(
  AEDisplayNameContact.oid,[
    '2.16.840.1.113730.3.1.241', # displayName
  ],
  structural_oc_oids=[AE_CONTACT_OID], # aeContact
)


class AEDisplayNameDept(ComposedAttribute,DirectoryString):
  oid = 'AEDisplayNameDept-oid'
  desc = 'Attribute displayName in object class aeDept'
  compose_templates = (
    '{ou} ({departmentNumber})',
    '{ou}',
    '#{departmentNumber}',
  )

syntax_registry.registerAttrType(
  AEDisplayNameDept.oid,[
    '2.16.840.1.113730.3.1.241', # displayName
  ],
  structural_oc_oids=[AE_DEPT_OID], # aeDept
)


class AEDisplayNameLocation(ComposedAttribute,DirectoryString):
  oid = 'AEDisplayNameLocation-oid'
  desc = 'Attribute displayName in object class aeLocation'
  compose_templates = (
    '{cn}: {l}, {street}',
    '{cn}: {l}',
    '{cn}: {street}',
    '{cn}: {st}',
    '{cn}',
  )

syntax_registry.registerAttrType(
  AEDisplayNameLocation.oid,[
    '2.16.840.1.113730.3.1.241', # displayName
  ],
  structural_oc_oids=[AE_LOCATION_OID], # aeLocation
)


class AEDisplayNamePerson(DisplayNameInetOrgPerson):
  oid = 'AEDisplayNamePerson-oid'
  desc = 'Attribute displayName in object class aePerson'
  # do not stuff confidential employeeNumber herein!
  compose_templates = (
    '{givenName} {sn} / {ou}',
    '{givenName} {sn} / #{departmentNumber}',
    '{givenName} {sn} ({uniqueIdentifier})',
    '{givenName} {sn}',
  )

syntax_registry.registerAttrType(
  AEDisplayNamePerson.oid,[
    '2.16.840.1.113730.3.1.241', # displayName
  ],
  structural_oc_oids=[AE_PERSON_OID], # aePerson
)


class AEUniqueIdentifier(DirectoryString):
  oid = 'AEUniqueIdentifier-oid'
  maxValues = 1
  gen_template = 'web2ldap-{timestamp}'

  def transmute(self,attrValues):
    if not attrValues or not attrValues[0].strip():
      return [self.gen_template.format(timestamp=time.time())]
    else:
      return attrValues

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )
    input_field.charset = self._form.accept_charset
    return input_field

syntax_registry.registerAttrType(
  AEUniqueIdentifier.oid,[
    '0.9.2342.19200300.100.1.44', # uniqueIdentifier
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
  ]
)


class AEDepartmentNumber(DirectoryString):
  oid = 'AEDepartmentNumber-oid'
  maxValues = 1

syntax_registry.registerAttrType(
  AEDepartmentNumber.oid,[
    '2.16.840.1.113730.3.1.2', # departmentNumber
  ],
  structural_oc_oids=[
    AE_DEPT_OID,   # aeDept
  ]
)


class AECommonName(DirectoryString):
  oid = 'AECommonName-oid'
  desc = 'AE-DIR: common name of aeObject'
  maxValues = 1
  simpleSanitizers = (
    str.strip,
  )


class AECommonNameAEZone(AECommonName):
  oid = 'AECommonNameAEZone-oid'
  desc = 'AE-DIR: common name of aeZone'
  simpleSanitizers = (
    str.strip,
    str.lower,
  )

syntax_registry.registerAttrType(
  AECommonNameAEZone.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_ZONE_OID, # aeZone
  ],
)


class AECommonNameAELocation(AECommonName):
  oid = 'AECommonNameAELocation-oid'
  desc = 'AE-DIR: common name of aeLocation'

syntax_registry.registerAttrType(
  AECommonNameAELocation.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_LOCATION_OID, # aeLocation
  ],
)


class AECommonNameAEHost(AECommonName):
  oid = 'AECommonNameAEHost-oid'
  desc = 'Canonical hostname'
  derive_from_host = True
  host_begin_item = 0
  host_end_item = None

  def transmute(self,attrValues):
    if self.derive_from_host:
      return list(set([
        '.'.join(av.strip().lower().split('.')[self.host_begin_item:self.host_end_item])
        for av in self._entry['host']
      ]))
    else:
      return attrValues

syntax_registry.registerAttrType(
  AECommonNameAEHost.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_HOST_OID, # aeHost
  ],
)


class AEZonePrefixCommonName(AECommonName,AEObjectUtil):
  oid = 'AEZonePrefixCommonName-oid'
  desc = 'AE-DIR: Attribute values have to be prefixed with zone name'
  reObj = re.compile('^[a-z0-9]+-[a-z0-9-]+$')
  special_names = ('zone-admins','zone-auditors')

  def sanitizeInput(self,attrValue):
    return attrValue.strip()

  def transmute(self,attrValues):
    attrValues = [attrValues[0].lower()]
    return attrValues

  def _validate(self,attrValue):
    result = DirectoryString._validate(self,attrValue)
    if result and attrValue:
      zone_cn = self._get_zone_name()
      result = zone_cn and (zone_cn=='pub' or attrValue.startswith(zone_cn+u'-'))
    return result

  def formValue(self):
    result = DirectoryString.formValue(self)
    zone_cn = self._get_zone_name()
    if zone_cn:
      if not self.attrValue:
        result = zone_cn+u'-'
      elif self.attrValue in self.special_names:
        result = '-'.join((zone_cn,self.attrValue.decode(self._ls.charset)))
    return result # formValue()


class AECommonNameAEGroup(AEZonePrefixCommonName):
  oid = 'AECommonNameAEGroup-oid'

syntax_registry.registerAttrType(
  AECommonNameAEGroup.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_GROUP_OID,     # aeGroup
    AE_MAILGROUP_OID, # aeMailGroup
  ]
)


class AECommonNameAESrvGroup(AEZonePrefixCommonName):
  oid = 'AECommonNameAESrvGroup-oid'

syntax_registry.registerAttrType(
  AECommonNameAESrvGroup.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_SRVGROUP_OID, # aeSrvGroup
  ]
)


class AECommonNameAETag(AEZonePrefixCommonName):
  oid = 'AECommonNameAETag-oid'

  def displayValue(self,valueindex=0,commandbutton=0):
    display_value = AEZonePrefixCommonName.displayValue(self,valueindex,commandbutton)
    if commandbutton:
      search_anchor = self._form.applAnchor(
        'searchform','&raquo;',self._sid,
        [
          ('dn',self._dn),
          ('search_root',self._ls.currentSearchRoot),
          ('searchform_mode',u'adv'),
          ('search_attr',u'aeTag'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string',self._ls.uc_decode(self.attrValue)[0]),
        ],
        title=u'Search all entries tagged with this tag',
      )
    else:
      search_anchor = ''
    return ''.join((display_value,search_anchor))

syntax_registry.registerAttrType(
  AECommonNameAETag.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_TAG_OID, # aeTag
  ]
)


class AECommonNameAESudoRule(AEZonePrefixCommonName):
  oid = 'AECommonNameAESudoRule-oid'

syntax_registry.registerAttrType(
  AECommonNameAESudoRule.oid,[
    '2.5.4.3', # cn alias commonName
  ],
  structural_oc_oids=[
    AE_SUDORULE_OID, # aeSudoRule
  ]
)


syntax_registry.registerAttrType(
  web2ldap.app.plugins.inetorgperson.CNInetOrgPerson.oid,[
    '2.5.4.3', # commonName
  ],
  structural_oc_oids=[
    AE_PERSON_OID, # aePerson
    AE_USER_OID,   # aeUser
  ]
)


class AESudoRuleDN(DynamicDNSelectList):
  oid = 'AESudoRuleDN-oid'
  desc = 'AE-DIR: DN(s) of visible SUDO rules'
  input_fallback = False # no fallback to normal input field
  ldap_url = 'ldap:///_?cn?sub?(&(objectClass=aeSudoRule)(aeStatus=0))'

syntax_registry.registerAttrType(
  AESudoRuleDN.oid,[
    AE_OID_PREFIX+'.4.21', # aeVisibleSudoers
  ]
)


class AENotBefore(NotBefore):
  oid = 'AENotBefore-oid'
  desc = 'AE-DIR: begin of validity period'

syntax_registry.registerAttrType(
  AENotBefore.oid,[
    AE_OID_PREFIX+'.4.22', # aeNotBefore
  ]
)


class AENotAfter(NotAfter):
  oid = 'AENotAfter-oid'
  desc = 'AE-DIR: begin of validity period'

  def _validate(self,attrValue):
    result = NotAfter._validate(self,attrValue)
    if result:
      ae_not_after = time.strptime(attrValue,r'%Y%m%d%H%M%SZ')
      try:
        ae_not_before = time.strptime(self._entry['aeNotBefore'][0],r'%Y%m%d%H%M%SZ')
      except (KeyError,ValueError):
        result = True
      else:
        result = (ae_not_before<=ae_not_after)
    return result

syntax_registry.registerAttrType(
  AENotAfter.oid,[
    AE_OID_PREFIX+'.4.23', # aeNotAfter
  ]
)


class AEStatus(SelectList,Integer):
  oid = 'AEStatus-oid'
  desc = 'AE-DIR: Status of object'
  attr_value_dict = {
    u'-1':u'requested',
    u'0':u'active',
    u'1':u'deactivated',
    u'2':u'archived',
  }

  def _validate(self,attrValue):
    result = SelectList._validate(self,attrValue)
    if not result or not attrValue:
      return result
    ae_status = int(attrValue)
    current_time = time.gmtime(time.time())
    try:
      ae_not_before = time.strptime(self._entry['aeNotBefore'][0],r'%Y%m%d%H%M%SZ')
    except (KeyError, ValueError):
      ae_not_before = time.strptime('19700101000000Z',r'%Y%m%d%H%M%SZ')
    try:
      ae_not_after = time.strptime(self._entry['aeNotAfter'][0],r'%Y%m%d%H%M%SZ')
    except (KeyError, ValueError):
      ae_not_after = current_time
    # see https://www.ae-dir.com/docs.html#schema-validity-period
    result = ae_not_before <= current_time <= ae_not_after
    if current_time > ae_not_after:
      result = ae_status>=1
    elif current_time < ae_not_before:
      result = ae_status==-1
    return result

  def transmute(self,attrValues):
    if not attrValues or not attrValues[0]:
      return attrValues
    ae_status = int(attrValues[0])
    current_time = time.gmtime(time.time())
    try:
      ae_not_before = time.strptime(self._entry['aeNotBefore'][0],r'%Y%m%d%H%M%SZ')
    except (KeyError, ValueError):
      pass
    else:
      if ae_status==0 and current_time < ae_not_before:
        ae_status = -1
    try:
      ae_not_after = time.strptime(self._entry['aeNotAfter'][0],r'%Y%m%d%H%M%SZ')
    except (KeyError, ValueError):
      pass
    else:
      if current_time > ae_not_after:
        try:
          ae_expiry_status = int(self._entry.get('aeExpiryStatus',['1'])[0])
        except ValueError:
          pass
        else:
          if ae_status<=ae_expiry_status:
            ae_status = ae_expiry_status
    return [str(ae_status)]

  def displayValue(self,valueindex=0,commandbutton=0):
    if not commandbutton:
      return Integer.displayValue(self,valueindex)
    else:
      return SelectList.displayValue(self,valueindex,commandbutton)

syntax_registry.registerAttrType(
  AEStatus.oid,[
    AE_OID_PREFIX+'.4.5', # aeStatus
  ]
)


class AEExpiryStatus(SelectList):
  oid = 'AEExpiryStatus-oid'
  desc = 'AE-DIR: Expiry status of object'
  attr_value_dict = {
    u'-/-':u'',
    u'1':u'deactivated',
    u'2':u'archived',
  }

syntax_registry.registerAttrType(
  AEStatus.oid,[
    AE_OID_PREFIX+'.4.46', # aeExpiryStatus
  ]
)


class AESudoUser(web2ldap.app.plugins.sudoers.SudoUserGroup):
  oid = 'AESudoUser-oid'
  desc = 'AE-DIR: sudoUser'
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

syntax_registry.registerAttrType(
  AESudoUser.oid,[
    '1.3.6.1.4.1.15953.9.1.1', # sudoUser
  ],
  structural_oc_oids=[
    AE_SUDORULE_OID, # aeSudoRule
  ]
)


class AEServiceSshPublicKey(SshPublicKey):
  oid = 'AEServiceSshPublicKey-oid'
  desc = 'AE-DIR: aeService:sshPublicKey'
  reObj = re.compile('(^|.* )(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ssh-ed25519) (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)? .+$')

syntax_registry.registerAttrType(
  AEServiceSshPublicKey.oid,[
    '1.3.6.1.4.1.24552.500.1.1.1.13', # sshPublicKey
  ],
  structural_oc_oids=[
    AE_SERVICE_OID, # aeService
  ]
)


class AEEntryDNAEAuthcToken(DistinguishedName):
  oid = 'AEEntryDNAEAuthcToken-oid'
  desc = 'AE-DIR: entryDN of aeAuthcToken entry'
  ref_attrs = (
    ('oathToken',u'Users',None,'aeUser',u'Search all personal user accounts using this OATH token.'),
  )

syntax_registry.registerAttrType(
  AEEntryDNAEAuthcToken.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_AUTHCTOKEN_OID, # aeAuthcToken
  ],
)


class AEEntryDNAEPolicy(DistinguishedName):
  oid = 'AEEntryDNAEPolicy-oid'
  desc = 'AE-DIR: entryDN of aePolicy entry'
  ref_attrs = (
    ('pwdPolicySubentry',u'Users',None,'aeUser',u'Search all personal user accounts restricted by this password policy.'),
    ('pwdPolicySubentry',u'Services',None,'aeService',u'Search all service accounts restricted by this password policy.'),
    ('pwdPolicySubentry',u'Tokens',None,'aeAuthcToken',u'Search all authentication tokens restricted by this password policy.'),
    ('oathHOTPParams',u'HOTP Tokens',None,'oathHOTPToken',u'Search all HOTP tokens affected by this HOTP parameters.'),
    ('oathTOTPParams',u'TOTP Tokens',None,'oathTOTPToken',u'Search all TOTP tokens affected by this TOTP parameters.'),
  )

syntax_registry.registerAttrType(
  AEEntryDNAEPolicy.oid,[
    '1.3.6.1.1.20', # entryDN
  ],
  structural_oc_oids=[
    AE_POLICY_OID, # aePolicy
  ],
)


class AEUserSshPublicKey(SshPublicKey):
  oid = 'AEUserSshPublicKey-oid'
  desc = 'AE-DIR: aeUser:sshPublicKey'

syntax_registry.registerAttrType(
  AEUserSshPublicKey.oid,[
    '1.3.6.1.4.1.24552.500.1.1.1.13', # sshPublicKey
  ],
  structural_oc_oids=[
    AE_USER_OID, # aeUser
  ]
)


class AERFC822MailMember(DynamicValueSelectList):
  oid = 'AERFC822MailMember-oid'
  desc = 'AE-DIR: rfc822MailMember'
  ldap_url = 'ldap:///_?mail,displayName?sub?(&(|(objectClass=inetLocalMailRecipient)(objectClass=aeContact))(mail=*)(aeStatus=0))'
  html_tmpl = RFC822Address.html_tmpl
  showValueButton = False

  def transmute(self, attrValues):
    if 'member' not in self._entry:
      return []
    entrydn_filter = compose_filter(
      '|',
      map_filter_parts('entryDN',self._entry['member']),
    )
    ldap_result = self._ls.l.search_s(
      self._ls.uc_encode(self._determineSearchDN(self._dn,self.lu_obj.dn))[0],
      ldap0.SCOPE_SUBTREE,
      entrydn_filter,
      attrlist=['mail'],
    )
    mail_addresses = [
      entry['mail'][0]
      for _, entry in ldap_result
    ]
    return sorted(mail_addresses)

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
    )
    input_field.charset = self._form.accept_charset
    input_field.setDefault(self.formValue())
    return input_field

syntax_registry.registerAttrType(
  AERFC822MailMember.oid,[
    '1.3.6.1.4.1.42.2.27.2.1.15', # rfc822MailMember
  ],
  structural_oc_oids=[
    AE_MAILGROUP_OID, # aeMailGroup
  ]
)


class AEPwdPolicy(web2ldap.app.plugins.ppolicy.PwdPolicySubentry):
  oid = 'AEPwdPolicy-oid'
  desc = 'AE-DIR: pwdPolicySubentry'
  ldap_url = 'ldap:///_??sub?(&(objectClass=aePolicy)(objectClass=pwdPolicy)(aeStatus=0))'

syntax_registry.registerAttrType(
  AEPwdPolicy.oid,[
    '1.3.6.1.4.1.42.2.27.8.1.23', # pwdPolicySubentry
  ],
  structural_oc_oids=[
    AE_USER_OID,    # aeUser
    AE_SERVICE_OID, # aeService
    AE_HOST_OID,    # aeHost
  ]
)


class AESudoHost(IA5String):
  oid = 'AESudoHost-oid'
  desc = 'AE-DIR: sudoHost'
  maxValues = 1
  reobj = re.compile('^ALL$')

  def transmute(self,attrValues):
    return ['ALL']

  def formField(self):
    input_field = HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )
    input_field.charset = self._form.accept_charset
    return input_field

syntax_registry.registerAttrType(
  AESudoHost.oid,[
    '1.3.6.1.4.1.15953.9.1.2', # sudoHost
  ],
  structural_oc_oids=[
    AE_SUDORULE_OID, # aeSudoRule
  ]
)


class AELoginShell(Shell):
  oid = 'AELoginShell-oid'
  desc = 'AE-DIR: Login shell for POSIX users'
  attr_value_dict = {
    u'/bin/bash':u'/bin/bash',
    u'/bin/true':u'/bin/true',
    u'/bin/false':u'/bin/false',
  }

syntax_registry.registerAttrType(
  AELoginShell.oid,[
    '1.3.6.1.1.1.1.4', # loginShell
  ],
  structural_oc_oids=[
    AE_USER_OID,    # aeUser
    AE_SERVICE_OID, # aeService
  ]
)

class AEOathHOTPToken(OathHOTPToken):
  oid = 'AEOathHOTPToken-oid'
  desc = 'DN of the associated oathHOTPToken entry in aeUser entry'
  ref_attrs = (
    (None,u'Users',None,None),
  )
  input_fallback = False

  def _determineFilter(self):
    if 'aePerson' in self._entry:
      return '(&{0}(aeOwner={1}))'.format(
        OathHOTPToken._determineFilter(self),
        self._entry['aePerson'][0],
      )
    return OathHOTPToken._determineFilter(self)

syntax_registry.registerAttrType(
  AEOathHOTPToken.oid,[
    '1.3.6.1.4.1.5427.1.389.4226.4.9.1', # oathHOTPToken
  ],
  structural_oc_oids=[AE_USER_OID], # aeUser
)


# see sshd(AUTHORIZED_KEYS FILE FORMAT
# and the -O option in ssh-keygen(1)
class AESSHPermissions(SelectList):
  oid = 'AESSHPermissions-oid'
  desc = 'AE-DIR: Status of object'
  attr_value_dict = {
    u'pty':u'PTY allocation',
    u'X11-forwarding':u'X11 forwarding',
    u'agent-forwarding':u'Key agent forwarding',
    u'port-forwarding':u'Port forwarding',
    u'user-rc':u'Execute ~/.ssh/rc',
  }

syntax_registry.registerAttrType(
  AESSHPermissions.oid,[
    AE_OID_PREFIX+'.4.47', # aeSSHPermissions
  ]
)


class AERemoteHostAEHost(DynamicValueSelectList):
  oid = 'AERemoteHostAEHost-oid'
  desc = 'AE-DIR: aeRemoteHost in aeHost entry'
  ldap_url = 'ldap:///.?ipHostNumber,aeFqdn?one?(&(objectClass=aeNwDevice)(aeStatus=0))'
  input_fallback = True # fallback to normal input field

syntax_registry.registerAttrType(
  AERemoteHostAEHost.oid,[
    AE_OID_PREFIX+'.4.8',  # aeRemoteHost
  ],
  structural_oc_oids=[AE_HOST_OID], # aeHost
)


class AEDescriptionAENwDevice(ComposedAttribute):
  oid = 'AEDescriptionAENwDevice-oid'
  desc = 'Attribute description in object class  aeNwDevice'
  compose_templates = (
    '{cn}: {aeFqdn} {ipHostNumber})',
    '{cn}: {ipHostNumber})',
  )

syntax_registry.registerAttrType(
  AEDescriptionAENwDevice.oid,[
    '2.5.4.13', # description
  ],
  structural_oc_oids=[AE_NWDEVICE_OID], # aeNwDevice
)


# Register all syntax classes in this module
for name in dir():
  syntax_registry.registerSyntaxClass(eval(name))


from web2ldap.ldapsession import LDAPSession as LDAPSessionOrig

class AEDirLDAPSession(LDAPSessionOrig):
  binddn_tmpl = u'uid={username},{searchroot}'

  def getBindDN(self,username,searchroot,filtertemplate):
    if not username:
      return u''
    elif web2ldap.ldaputil.base.is_dn(username):
      return username
    else:
      return self.binddn_tmpl.format(
        username=username,searchroot=searchroot
      )
