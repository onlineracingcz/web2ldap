# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for OpenLDAP
"""

from __future__ import absolute_import

import re

from pyasn1.codec.ber import decoder as ber_decoder

import ldap0.ldapurl,ldap0.controls
import ldap0.openldap

import web2ldapcnf

import web2ldap.app.gui
from web2ldap.mspki.util import HexString
from web2ldap.app.schema.syntaxes import \
  DistinguishedName,IA5String,OctetString,DirectoryString,Uri,SelectList, \
  LDAPUrl,BindDN,MultilineText,AuthzDN,UUID,Integer,NotBefore, \
  DynamicDNSelectList,LDAPv3ResultCode,syntax_registry
from web2ldap.ldaputil.oidreg import oid as oid_desc_reg
from web2ldap.app.plugins.quirks import NamingContexts

#---------------------------------------------------------------------------
# slapo-syncprov
#---------------------------------------------------------------------------

# see https://www.openldap.org/faq/data/cache/1145.html
class CSN_SID(IA5String):
  oid = '1.3.6.1.4.1.4203.666.11.2.4'
  desc = 'change sequence number SID (CSN SID)'
  minLen = 3
  maxLen = 3
  reObj = re.compile('^[a-fA-F0-9]{3}$')


# see https://www.openldap.org/faq/data/cache/1145.html
class CSN(IA5String):
  oid = '1.3.6.1.4.1.4203.666.11.2.1'
  desc = 'change sequence number (CSN)'
  minLen = 40
  maxLen = 40
  reObj = re.compile('^[0-9]{14}\\.[0-9]{6}Z#[a-fA-F0-9]{6}#[a-fA-F0-9]{3}#[a-fA-F0-9]{6}$')


syntax_registry.registerAttrType(
  CSN.oid, [
    '1.3.6.1.4.1.4203.666.1.25', # contextCSN
    '1.3.6.1.4.1.4203.666.1.7', # entryCSN
    '1.3.6.1.4.1.4203.666.1.13', # namingCSN
    # also register by name in case OpenLDAP was built without -DSLAP_SCHEMA_EXPOSE
    'contextCSN','entryCSN','namingCSN',
  ]
)

#---------------------------------------------------------------------------
# back-config
#---------------------------------------------------------------------------


syntax_registry.registerAttrType(
  NamingContexts.oid, [
    '1.3.6.1.4.1.4203.1.12.2.3.2.0.10', # olcSuffix
  ]
)


class OlcDbIndex(DirectoryString):
  oid = 'OlcDbIndex-oid'
  desc = 'OpenLDAP indexing directive'
  reObj = re.compile("^[a-zA-Z]?[a-zA-Z0-9.,;-]* (pres|eq|sub)(,(pres|eq|sub))*$")


syntax_registry.registerAttrType(
  OlcDbIndex.oid, [
    '1.3.6.1.4.1.4203.1.12.2.3.2.0.2', # olcDbIndex
  ]
)


class OlcSubordinate(SelectList):
  oid = 'OlcSubordinate-oid'
  desc = 'Indicates whether backend is subordinate'
  attr_value_dict = {
    u'': u'-/- (FALSE)',
    u'TRUE': u'TRUE',
    u'advertise': u'advertise',
  }

syntax_registry.registerAttrType(
  OlcSubordinate.oid, [
    '1.3.6.1.4.1.4203.1.12.2.3.2.0.15', # olcSubordinate
  ]
)


class OlcRootDN(BindDN):
  oid = 'OlcRootDN-oid'
  desc = 'The rootdn in the database'
  default_rdn = u'cn=admin'

  def formValue(self):
    form_value = BindDN.formValue(self)
    try:
      olc_suffix = self._entry['olcSuffix'][0].decode()
    except KeyError:
      pass
    else:
      if not form_value or not form_value.endswith(olc_suffix):
        try:
          form_value = u','.join((self.default_rdn,olc_suffix))
        except KeyError:
          pass
    return form_value

syntax_registry.registerAttrType(
  OlcRootDN.oid, [
    '1.3.6.1.4.1.4203.1.12.2.3.2.0.8', # olcRootDN
  ]
)


class OlcMultilineText(MultilineText):
  oid = 'OlcMultilineText-oid'
  desc = 'OpenLDAP multiline configuration strings'
  cols = 90
  minInputRows = 3
  whitespace_cleaning = False

  def displayValue(self, valueindex=0, commandbutton=False):
    return '<code>%s</code>' % MultilineText.displayValue(self, valueindex, commandbutton)


syntax_registry.registerAttrType(
  OlcMultilineText.oid, [
    '1.3.6.1.4.1.4203.1.12.2.3.0.1', # olcAccess
    '1.3.6.1.4.1.4203.1.12.2.3.0.6', # olcAuthIDRewrite
    '1.3.6.1.4.1.4203.1.12.2.3.0.8', # olcAuthzRegexp
  ]
)

class OlcSyncRepl(OlcMultilineText,LDAPUrl):
  oid = 'OlcSyncRepl-oid'
  desc = 'OpenLDAP syncrepl directive'
  minInputRows = 5

  def __init__(self, sid, form, ls, dn, schema, attrType, attrValue, entry=None):
    OlcMultilineText.__init__(self, sid, form, ls, dn, schema, attrType, attrValue, entry)
    self._sync_repl_desc = ldap0.openldap.SyncReplDesc(attrValue)
    return # __init__()

  def displayValue(self, valueindex=0, commandbutton=False):
    if commandbutton and self.attrValue:
      return ' '.join((
        OlcMultilineText.displayValue(self, valueindex, commandbutton),
        web2ldap.app.gui.LDAPURLButton(
            self._sid, self._form, self._ls,
            self._sync_repl_desc.ldap_url(),
        ),
      ))
    else:
      OlcMultilineText.displayValue(self, valueindex, commandbutton)

syntax_registry.registerAttrType(
  OlcSyncRepl.oid, [
    '1.3.6.1.4.1.4203.1.12.2.3.2.0.11', # olcSyncrepl
  ]
)


class OlmSeeAlso(DynamicDNSelectList):
  oid = 'OlmSeeAlso-oid'
  desc = 'DN of a overlase or database object in back-monitor'
  ldap_url = 'ldap:///_?monitoredInfo?sub?(&(objectClass=monitoredObject)(|(entryDN:dnOneLevelMatch:=cn=Databases,cn=Monitor)(entryDN:dnOneLevelMatch:=cn=Overlays,cn=Monitor)(entryDN:dnOneLevelMatch:=cn=Backends,cn=Monitor)))'

syntax_registry.registerAttrType(
  OlmSeeAlso.oid, [
    '2.5.4.34', # seeAlso
  ],
  structural_oc_oids=['1.3.6.1.4.1.4203.666.3.16.8'], # monitoredObject
)


class OlcPPolicyDefault(DistinguishedName,DynamicDNSelectList):
  oid = 'OlcPPolicyDefault-oid'
  desc = 'DN of a pwdPolicy object for uncustomized objects'
  ldap_url = 'ldap:///_?cn?sub?(objectClass=pwdPolicy)'

  def __init__(self, sid, form, ls, dn, schema, attrType, attrValue, entry=None):
    DynamicDNSelectList.__init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=entry)

  def _validate(self, attrValue):
    return DynamicDNSelectList._validate(self,attrValue)

syntax_registry.registerAttrType(
  OlcPPolicyDefault.oid, [
    '1.3.6.1.4.1.4203.1.12.2.3.3.12.1', # olcPPolicyDefault
  ]
)


class OlcMemberOfDangling(SelectList):
  oid = 'OlcMemberOfDangling-oid'
  desc = 'Behavior in case of dangling references during modification'
  attr_value_dict = {
    u'': u'-/-',
    u'ignore': u'ignore',
    u'drop': u'drop',
    u'error': u'error',
  }

syntax_registry.registerAttrType(
  OlcMemberOfDangling.oid, [
    '1.3.6.1.4.1.4203.1.12.2.3.3.18.1', # olcMemberOfDangling
  ]
)


#---------------------------------------------------------------------------
# slapo-accesslog
#---------------------------------------------------------------------------


syntax_registry.registerAttrType(
  NotBefore.oid, [
    '1.3.6.1.4.1.4203.666.11.5.1.2','reqStart',
    '1.3.6.1.4.1.4203.666.11.5.1.3','reqEnd',
  ]
)


class AuditContext(NamingContexts):
  oid = 'AuditContext'
  desc = 'OpenLDAP DN pointing to audit naming context'

  def displayValue(self, valueindex=0, commandbutton=False):
    r = [DistinguishedName.displayValue(self, valueindex, commandbutton)]
    if commandbutton:
      r.extend([
        self._form.applAnchor(
          'searchform','Search',self._sid,
          [
            ('dn',self.attrValue),
            ('scope',str(ldap0.SCOPE_ONELEVEL)),
          ],
          title=u'Go to search form for audit log',
        ),
        self._form.applAnchor(
          'search','List all',self._sid,
          [
            ('dn',self.attrValue),
            ('filterstr','(objectClass=auditObject)'),
            ('scope',str(ldap0.SCOPE_ONELEVEL)),
          ],
          title=u'List audit log entries of all operations',
        ),
        self._form.applAnchor(
          'search','List writes',self._sid,
          [
            ('dn',self.attrValue),
            ('filterstr','(objectClass=auditWriteObject)'),
            ('scope',str(ldap0.SCOPE_ONELEVEL)),
          ],
          title=u'List audit log entries of all write operations',
        ),
      ])
    return web2ldapcnf.command_link_separator.join(r)

syntax_registry.registerAttrType(
  AuditContext.oid,
  [
    '1.3.6.1.4.1.4203.666.11.5.1.30','auditContext',
    '1.3.6.1.4.1.4203.1.12.2.3.3.4.1',  # olcAccessLogDB
  ]
)


class ReqResult(LDAPv3ResultCode):
  oid = 'ReqResult-oid'

syntax_registry.registerAttrType(
  ReqResult.oid, [
    '1.3.6.1.4.1.4203.666.11.5.1.7','reqResult', # reqResult
  ]
)


class ReqMod(OctetString,DirectoryString):
  oid = 'ReqMod-oid'
  desc = 'List of modifications/old values'
  known_modtypes = set(('+','-','=','#',''))

  def displayValue(self, valueindex=0, commandbutton=False):
    if self.attrValue==':':
      # magic value used for fixing OpenLDAP ITS#6545
      return self.attrValue
    try:
      mod_attr_type,mod_attr_rest = self.attrValue.split(':',1)
      mod_type = mod_attr_rest[0].strip()
    except (ValueError,IndexError):
      return OctetString.displayValue(self, valueindex, commandbutton)
    if not mod_type in self.known_modtypes:
      return OctetString.displayValue(self, valueindex, commandbutton)
    if len(mod_attr_rest)>1:
      try:
        mod_type,mod_attr_value = mod_attr_rest.split(' ',1)
      except ValueError:
        return OctetString.displayValue(self, valueindex, commandbutton)
    else:
      mod_attr_value = ''
    mod_attr_type_u = mod_attr_type.decode(self._ls.charset)
    mod_type_u = mod_type.decode(self._ls.charset)
    try:
      mod_attr_value.decode(self._ls.charset)
    except UnicodeDecodeError:
      return '%s:%s<br>\n<code>\n%s\n</code>\n' % (
        self._form.utf2display(mod_attr_type_u),
        self._form.utf2display(mod_type_u),
        HexString(
          mod_attr_value,
          delimiter=':',wrap=64,linesep='<br>\n'
        )[:-1]
      )
    else:
      return DirectoryString.displayValue(self, valueindex, commandbutton)
    raise ValueError

syntax_registry.registerAttrType(
  ReqMod.oid, [
    '1.3.6.1.4.1.4203.666.11.5.1.16','reqMod',
    '1.3.6.1.4.1.4203.666.11.5.1.17','reqOld',
  ]
)


class ReqControls(IA5String):
  oid = '1.3.6.1.4.1.4203.666.11.5.3.1'
  desc = 'List of LDAPv3 extended controls sent along with a request'

  def displayValue(self, valueindex=0, commandbutton=False):
    result_lines = [IA5String.displayValue(self, valueindex, commandbutton)]
    # Eliminate X-ORDERED prefix
    _,rest = self.attrValue.strip().split('}{',1)
    # check whether it ends with }
    if rest.endswith('}'):
      result_lines.append('Extracted:')
      # consume } and split tokens
      ctrl_tokens = filter(None,[ t.strip() for t in rest[:-1].split(' ') ])
      ctrl_type = ctrl_tokens[0]
      try:
        ctrl_name,_,_ = oid_desc_reg[ctrl_type]
      except (KeyError,ValueError):
        try:
          ctrl_name = ldap0.controls.KNOWN_RESPONSE_CONTROLS.get(ctrl_type).__class__.__name__
        except KeyError:
          ctrl_name = None
      if ctrl_name:
        result_lines.append(self._form.utf2display(ctrl_name.decode('utf-8')))
      # Extract criticality
      try:
        ctrl_criticality = {
          'TRUE':True,
          'FALSE':False,
        }[ctrl_tokens[ctrl_tokens.index('criticality')+1].upper()]
      except (KeyError,ValueError,IndexError):
        ctrl_criticality = False
      result_lines.append('criticality %s' % str(ctrl_criticality).upper())
      # Extract controlValue
      try:
        ctrl_value = ctrl_tokens[ctrl_tokens.index('controlValue')+1].upper()[1:-1].decode('hex')
      except (KeyError,ValueError,IndexError):
        pass
      else:
        try:
          decoded_control_value = ber_decoder.decode(ctrl_value)
        except:
          decoded_control_value = ctrl_value
        result_lines.append('controlValue %s' % (
          self._form.utf2display(
            repr(decoded_control_value).decode('ascii')
          ).replace('\n','<br>')
        ))
    return '<br>'.join(result_lines)

syntax_registry.registerAttrType(
  ReqControls.oid, [
    '1.3.6.1.4.1.4203.666.11.5.1.10','reqControls',
    '1.3.6.1.4.1.4203.666.11.5.1.11','reqRespControls',
  ]
)


class ReqEntryUUID(UUID):
  oid = 'ReqEntryUUID-oid'

  def displayValue(self, valueindex=0, commandbutton=False):
    display_value = UUID.displayValue(self, valueindex, commandbutton)
    if commandbutton:
      return web2ldapcnf.command_link_separator.join((
        display_value,
        self._form.applAnchor(
            'search','Search target',self._sid,
            (
              ('dn',self._dn),
              (
                'filterstr',
                '(entryUUID=%s)' % (self.attrValue.decode('ascii'))
              ),
              ('search_root',self._ls.getSearchRoot(self._ls.uc_decode(self._entry['reqDN'][0])[0])),
            ),
            title=u'Search entry by UUID',
        )
      ))
    else:
      return display_value

syntax_registry.registerAttrType(
  ReqEntryUUID.oid, [
    '1.3.6.1.4.1.4203.666.11.5.1.31','reqEntryUUID', # reqEntryUUID
  ]
)


class ReqSession(Integer):
  oid = 'ReqSession-oid'

  def displayValue(self, valueindex=0, commandbutton=False):
    display_value = Integer.displayValue(self, valueindex, commandbutton)
    if commandbutton:
      return web2ldapcnf.command_link_separator.join((
        display_value,
        self._form.applAnchor(
            'search','&raquo;',self._sid,
            (
              ('dn',self._dn),
              ('search_root',self._ls.currentSearchRoot),
              ('searchform_mode',u'adv'),
              ('search_attr',u'reqSession'),
              ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
              ('search_string',self._ls.uc_decode(self.attrValue)[0]),
            ),
            title=u'Search all audit entries with same session number',
        )
      ))
    else:
      return display_value

syntax_registry.registerAttrType(
  ReqSession.oid, [
    '1.3.6.1.4.1.4203.666.11.5.1.5','reqSession', # reqSession
  ]
)


#---------------------------------------------------------------------------
# General
#---------------------------------------------------------------------------


class Authz(DirectoryString):
  oid = '1.3.6.1.4.1.4203.666.2.7'
  desc = 'OpenLDAP authz'


syntax_registry.registerAttrType(
  AuthzDN.oid, [
    'monitorConnectionAuthzDN',
    '1.3.6.1.4.1.4203.666.1.55.7', # monitorConnectionAuthzDN
    'reqAuthzID',
    '1.3.6.1.4.1.4203.666.11.5.1.6', # reqAuthzID
  ]
)


class OpenLDAPACI(DirectoryString):
  oid = '1.3.6.1.4.1.4203.666.2.1'
  desc = 'OpenLDAP ACI'


class OpenLDAPSpecialBackendSuffix(NamingContexts):
  oid = 'OpenLDAPSpecialBackendSuffix-oid'
  desc = 'OpenLDAP special backend suffix'

  def _config_link(self):
    attr_type_u = self._ls.uc_decode(self.attrType)[0][:-7]
    try:
      config_context = self._ls.uc_decode(self._ls.rootDSE['configContext'][0])[0]
    except KeyError:
      return None
    else:
      return self._form.applAnchor(
        'search','Config',self._sid,
        (
          ('dn',config_context),
          ('scope',web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
          (
            'filterstr',
            u'(&(objectClass=olcDatabaseConfig)(olcDatabase=%s))' % (attr_type_u),
          ),
        ),
        title=u'Search for configuration entry below %s' % (config_context),
      )

syntax_registry.registerAttrType(
  OpenLDAPSpecialBackendSuffix.oid,
  [
    'monitorContext','1.3.6.1.4.1.4203.666.1.10',
    'configContext','1.3.6.1.4.1.4203.1.12.2.1',
  ]
)


syntax_registry.registerAttrType(
  Uri.oid, ['monitorConnectionListener']
)


syntax_registry.registerAttrType(
  DistinguishedName.oid, [
    'entryDN',
    'reqDN',
  ]
)

# Register all syntax classes in this module
for name in dir():
    syntax_registry.registerSyntaxClass(eval(name))
