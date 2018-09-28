# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for schema elements defined in RFC2307
"""

from __future__ import absolute_import

import re,web2ldap.app.searchform

from web2ldap.app.schema.syntaxes import SelectList,IA5String,Integer, \
                         IPHostAddress,IPNetworkAddress,IPServicePortNumber,MacAddress, \
                         DaysSinceEpoch,DNSDomain,DynamicValueSelectList,\
                         syntax_registry


class RFC2307BootParameter(IA5String):
  oid = '1.3.6.1.1.1.0.1'
  desc = 'RFC2307 Boot Parameter'
  reObj=None # just a stub, should be made stricter


class GidNumber(DynamicValueSelectList,Integer):
  oid = 'GidNumber-oid'
  desc = 'RFC2307: An integer uniquely identifying a group in an administrative domain'
  minValue = 0
  maxValue = 4294967295L
  ldap_url = 'ldap:///_?gidNumber,cn?sub?(objectClass=posixGroup)'

  def _validate(self,attrValue):
    return Integer._validate(self,attrValue)

  def displayValue(self,valueindex=0,commandbutton=0):
    # Possibly display a link
    ocs = self._entry.object_class_oid_set()
    if 'posixAccount' in ocs or 'shadowAccount' in ocs:
      return DynamicValueSelectList.displayValue(self,valueindex,commandbutton)
    else:
      r = [Integer.displayValue(self,valueindex,commandbutton=0)]
      if not commandbutton:
        return r[0]
      if 'posixGroup' in ocs:
        title = u'Search primary group members'
        searchform_params = [
          ('dn',self._dn),
          ('searchform_mode',u'adv'),
          ('search_attr',u'objectClass'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string',u'posixAccount'),
          ('search_attr',u'gidNumber'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string',self._ls.uc_decode(self.attrValue)[0]),
        ]
      else:
        title = None
        searchform_params = None
      if title and searchform_params:
        r.append(self._form.applAnchor(
            'searchform','&raquo;',self._sid,
            searchform_params,
            title=title,
        ))
      return ' '.join(r)

  def formField(self):
    ocs = self._entry.object_class_oid_set()
    if 'posixAccount' in ocs or 'shadowAccount' in ocs:
      return DynamicValueSelectList.formField(self)
    else:
      return Integer.formField(self)

syntax_registry.registerAttrType(
  GidNumber.oid,[
    '1.3.6.1.1.1.1.1', # gidNumber
  ]
)


class MemberUID(IA5String,DynamicValueSelectList):
  oid = 'MemberUID-oid'
  desc = 'RFC2307 numerical UID of group member(s)'
  ldap_url = None
#  ldap_url = 'ldap:///_?uid,cn?sub?(objectClass=posixAccount)'

  def __init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=None):
    IA5String.__init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry)
    if self.ldap_url:
      DynamicValueSelectList.__init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry)

  def _validate(self,attrValue):
    if self.ldap_url:
      return DynamicValueSelectList._validate(self,attrValue)
    else:
      return IA5String._validate(self,attrValue)

  def displayValue(self,valueindex=0,commandbutton=0):
    r = [IA5String.displayValue(self,valueindex,commandbutton=0)]
    if commandbutton:
      r.append(self._form.applAnchor(
          'searchform','&raquo;',self._sid,
          [
            ('dn',self._dn),
            ('filterstr','(&(objectClass=posixAccount)(uid=%s))' % (
                self._form.utf2display(self._ls.uc_decode(self.attrValue)[0])
              )
            ),
            ('searchform_mode','exp'),
          ],
          title=u'Search for user entry',
      ))
    return ' '.join(r)

syntax_registry.registerAttrType(
  MemberUID.oid,[
    '1.3.6.1.1.1.1.12', # memberUid
  ]
)


class RFC2307NISNetgroupTriple(IA5String):
  oid = '1.3.6.1.1.1.0.0'
  desc = 'RFC2307 NIS Netgroup Triple'
  reObj=re.compile('^\([a-z0-9.-]*,[a-z0-9.-]*,[a-z0-9.-]*\)$')


class UidNumber(Integer):
  oid = 'UidNumber-oid'
  desc = 'Numerical user ID for Posix systems'
  minValue = 0
  maxValue = 4294967295L

syntax_registry.registerAttrType(
  UidNumber.oid,[
    '1.3.6.1.1.1.1.0', # uidNumber
  ]
)


class Shell(SelectList):
  oid = 'Shell-oid'
  desc = 'Shell for user of Posix systems'
  attr_value_dict = {
    u'/bin/sh':u'Standard shell /bin/sh',
    u'/bin/bash':u'Bourne-Again SHell /bin/bash',
    u'/bin/csh':u'/bin/csh',
    u'/bin/tcsh':u'/bin/tcsh',
    u'/bin/ksh':u'Korn shell /bin/ksh',
    u'/bin/passwd':u'Password change /bin/passwd',
    u'/bin/true':u'/bin/true',
    u'/bin/false':u'/bin/false',
    u'/bin/zsh':u'Zsh /bin/zsh',
    u'/usr/bin/bash':u'Bourne-Again SHell /usr/bin/bash',
    u'/usr/bin/csh':u'/usr/bin/csh',
    u'/usr/bin/tcsh':u'/usr/bin/csh',
    u'/usr/bin/ksh':u'Korn shell /usr/bin/ksh',
    u'/usr/bin/zsh':u'Zsh /usr/bin/zsh',
    u'/usr/sbin/nologin':u'Login denied /usr/sbin/nologin',
  }

syntax_registry.registerAttrType(
  Shell.oid,[
    '1.3.6.1.1.1.1.4', # loginShell
  ]
)


class IpServiceProtocol(SelectList):
  oid = 'IpServiceProtocol-oid'
  desc = 'RFC 2307: IP service protocol'

  attr_value_dict = {
    u'tcp':u'tcp',
    u'udp':u'udp',
  }

syntax_registry.registerAttrType(
  IpServiceProtocol.oid,[
    '1.3.6.1.1.1.1.16' , # ipServiceProtocol
  ]
)


syntax_registry.registerAttrType(
  IPHostAddress.oid,[
    '1.3.6.1.1.1.1.19', # ipHostNumber
    '1.3.6.1.1.1.1.20', # ipNetworkNumber
  ]
)


syntax_registry.registerAttrType(
  DNSDomain.oid,[
    '1.3.6.1.1.1.1.30', # nisDomain
  ]
)


syntax_registry.registerAttrType(
  DaysSinceEpoch.oid,[
    '1.3.6.1.1.1.1.10', # shadowExpire
    '1.3.6.1.1.1.1.5', # shadowLastChange
  ]
)


syntax_registry.registerAttrType(
  IPServicePortNumber.oid,[
    '1.3.6.1.1.1.1.15', # ipServicePort
  ]
)


syntax_registry.registerAttrType(
  MacAddress.oid,[
    '1.3.6.1.1.1.1.22', # macAddress
  ]
)


# Register all syntax classes in this module
for name in dir():
  syntax_registry.registerSyntaxClass(eval(name))



