# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for LDAP-based naming service (ldapns.schema)
"""

from __future__ import absolute_import

from web2ldap.app.schema.syntaxes import SelectList,syntax_registry


class AuthorizedService(SelectList):
  """
  See https://www.iana.org/assignments/gssapi-service-names/gssapi-service-names.xhtml
  """
  oid = 'AuthorizedService-oid'
  desc = 'IANA GSS-API authorized service name'

  attr_value_dict = {
    u'':u'',
    u'rcmd':u'remote command/rlogin/telnet',
    u'imap':u'mailstore access/IMAP4',
    u'pop':u'maildrop access/POP3',
    u'acap':u'remote configuration access/ACAP',
    u'nfs':u'distributed file system protocol (NFS)',
    u'ftp':u'file transfer/FTP/TFTP',
    u'ldap':u'Lightweight Directory Access Protocol (LDAP)',
    u'smtp':u'message transfer/SMTP',
    u'beep':u'Blocks Extensible Exchange Protocol (BEEP)',
    u'mupdate':u'Mailbox Update (MUPDATE) Protocol',
    u'sacred':u'Secure Available Credentials (SACRED) Protocol',
    u'sieve':u'ManageSieve Protocol',
    u'xmpp':u'Extensible Messaging and Presence Protocol (XMPP)',
    u'nntp':u'Network News Transfer Protocol (NNTP)',
  }


syntax_registry.registerAttrType(
  AuthorizedService.oid,[
    '1.3.6.1.4.1.5322.17.2.1', # authorizedService
  ]
)


# Register all syntax classes in this module
for name in dir():
  syntax_registry.registerSyntaxClass(eval(name))

