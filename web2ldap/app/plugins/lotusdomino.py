# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for PGP key server
"""

from __future__ import absolute_import

import re

from web2ldap.app.schema.syntaxes import MultilineText,YesNoIntegerFlag,\
                                   SelectList,DynamicDNSelectList,syntax_registry


syntax_registry.registerAttrType(
  YesNoIntegerFlag.oid, [
    '2.16.840.1.113678.2.2.2.2.4',  # AvailableForDirSync
    '2.16.840.1.113678.2.2.2.2.18', # EncryptIncomingMail
  ]
)


class DominoCertificate(MultilineText):
  oid = 'DominoCertificate-oid'
  desc = 'Domino certificate'
  reObj = re.compile('^([A-Z0-9]{8} [A-Z0-9]{8} [A-Z0-9]{8} [A-Z0-9]{8}[\x00]?)+[A-Z0-9 ]*$')
  lineSep = '\x00'
  mimeType = 'text/plain'
  cols = 36

  def displayValue(self, valueindex=False, commandbutton=False):
    lines = [
      self._form.utf2display(l)
      for l in self._split_lines(self.attrValue.decode('ascii'))
    ]
    return '<code>%s</code>' % '<br>'.join(lines)

syntax_registry.registerAttrType(
  DominoCertificate.oid, [
    '2.16.840.1.113678.2.2.2.2.22', # dominoCertificate
    '2.16.840.1.113678.2.2.2.2.45', # Certificate-NoEnc
    'inetpublickey',
  ]
)


class CheckPassword(SelectList):
  oid = 'CheckPassword-oid'
  desc = ''
  attr_value_dict = {
    u'0':u'Do not check password',
    u'1':u'Check password',
    u'2':u'ID is locked',
  }

syntax_registry.registerAttrType(
  CheckPassword.oid, [
    '2.16.840.1.113678.2.2.2.2.29' # CheckPassword
  ]
)


class MailServer(DynamicDNSelectList):
  oid = 'MailServer-oid'
  desc = 'DN of mail server entry'
  ldap_url = 'ldap:///?displayname?sub?(objectClass=dominoServer)'

syntax_registry.registerAttrType(
  MailServer.oid, [
    '2.16.840.1.113678.2.2.2.2.12', # MailServer
  ]
)


# Register all syntax classes in this module
for symbol_name in dir():
  syntax_registry.registerSyntaxClass(eval(symbol_name))
