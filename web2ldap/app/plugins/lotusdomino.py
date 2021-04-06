# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for PGP key server
"""

import re
from typing import Dict

from ..schema.syntaxes import (
    DynamicDNSelectList,
    MultilineText,
    SelectList,
    syntax_registry,
)


class YesNoIntegerFlag(SelectList):
    """
    Plugin class for flag attribute with value "yes" or "no"
    """
    oid: str = 'YesNoIntegerFlag-oid'
    desc: str = '0 means no, 1 means yes'
    attr_value_dict: Dict[str, str] = {
        '0': 'no',
        '1': 'yes',
    }

syntax_registry.reg_at(
    YesNoIntegerFlag.oid, [
        '2.16.840.1.113678.2.2.2.2.4',  # AvailableForDirSync
        '2.16.840.1.113678.2.2.2.2.18', # EncryptIncomingMail
    ]
)


class DominoCertificate(MultilineText):
    oid: str = 'DominoCertificate-oid'
    desc: str = 'Domino certificate'
    pattern = re.compile('^([A-Z0-9]{8} [A-Z0-9]{8} [A-Z0-9]{8} [A-Z0-9]{8}[\x00]?)+[A-Z0-9 ]*$')
    lineSep = b'\x00'
    mime_type = 'text/plain'
    cols = 36

    def display(self, valueindex=0, commandbutton=False) -> str:
        lines = [
            self._app.form.s2d(l)
            for l in self._split_lines(self.av_u)
        ]
        return '<code>%s</code>' % '<br>'.join(lines)

syntax_registry.reg_at(
    DominoCertificate.oid, [
        '2.16.840.1.113678.2.2.2.2.22', # dominoCertificate
        '2.16.840.1.113678.2.2.2.2.45', # Certificate-NoEnc
        'inetpublickey',
    ]
)


class CheckPassword(SelectList):
    oid: str = 'CheckPassword-oid'
    desc: str = ''
    attr_value_dict: Dict[str, str] = {
        '0': 'Do not check password',
        '1': 'Check password',
        '2': 'ID is locked',
    }

syntax_registry.reg_at(
    CheckPassword.oid, [
        '2.16.840.1.113678.2.2.2.2.29' # CheckPassword
    ]
)


class MailServer(DynamicDNSelectList):
    oid: str = 'MailServer-oid'
    desc: str = 'DN of mail server entry'
    ldap_url = 'ldap:///?displayname?sub?(objectClass=dominoServer)'

syntax_registry.reg_at(
    MailServer.oid, [
        '2.16.840.1.113678.2.2.2.2.12', # MailServer
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
