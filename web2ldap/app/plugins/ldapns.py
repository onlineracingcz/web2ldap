# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for LDAP-based naming service (ldapns.schema)
"""

from typing import Dict

from web2ldap.app.schema.syntaxes import SelectList, syntax_registry


class AuthorizedService(SelectList):
    """
    See https://www.iana.org/assignments/gssapi-service-names/gssapi-service-names.xhtml
    """
    oid: str = 'AuthorizedService-oid'
    desc: str = 'IANA GSS-API authorized service name'

    attr_value_dict: Dict[str, str] = {
        '': '',
        'rcmd': 'remote command/rlogin/telnet',
        'imap': 'mailstore access/IMAP4',
        'pop': 'maildrop access/POP3',
        'acap': 'remote configuration access/ACAP',
        'nfs': 'distributed file system protocol (NFS)',
        'ftp': 'file transfer/FTP/TFTP',
        'ldap': 'Lightweight Directory Access Protocol (LDAP)',
        'smtp': 'message transfer/SMTP',
        'beep': 'Blocks Extensible Exchange Protocol (BEEP)',
        'mupdate': 'Mailbox Update (MUPDATE) Protocol',
        'sacred': 'Secure Available Credentials (SACRED) Protocol',
        'sieve': 'ManageSieve Protocol',
        'xmpp': 'Extensible Messaging and Presence Protocol (XMPP)',
        'nntp': 'Network News Transfer Protocol (NNTP)',
    }


syntax_registry.reg_at(
    AuthorizedService.oid, [
        '1.3.6.1.4.1.5322.17.2.1', # authorizedService
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
