# -*- coding: ascii -*-
"""
web2ldap plugin classes for Samba 3
"""

import string
import re
from typing import Dict

import ldap0
import ldap0.filter

from ..schema.syntaxes import (
    DirectoryString,
    SelectList,
    SecondsSinceEpoch,
    IA5String,
    DynamicValueSelectList,
    syntax_registry,
)
from .activedirectory import LogonHours


syntax_registry.reg_at(
    SecondsSinceEpoch.oid, [
        '1.3.6.1.4.1.7165.2.1.3', # pwdLastSet
        '1.3.6.1.4.1.7165.2.1.5', # logonTime
        '1.3.6.1.4.1.7165.2.1.6', # logoffTime
        '1.3.6.1.4.1.7165.2.1.7', # kickoffTime
        '1.3.6.1.4.1.7165.2.1.8', # pwdCanChange
        '1.3.6.1.4.1.7165.2.1.9', # pwdMustChange
        '1.3.6.1.4.1.7165.2.1.27', # sambaPwdLastSet
        '1.3.6.1.4.1.7165.2.1.28', # sambaPwdCanChange
        '1.3.6.1.4.1.7165.2.1.29', # sambaPwdMustChange
        '1.3.6.1.4.1.7165.2.1.30', # sambaLogonTime
        '1.3.6.1.4.1.7165.2.1.31', # sambaLogoffTime
        '1.3.6.1.4.1.7165.2.1.32', # sambaKickoffTime
    ]
)


syntax_registry.reg_at(
    LogonHours.oid, [
        '1.3.6.1.4.1.7165.2.1.55', # sambaLogonHours
    ]
)


class SambaAcctFlags(IA5String):
    oid: str = 'SambaAcctFlags-oid'
    desc: str = 'Samba 3 account flags'
    input_pattern: str = r'^\[[NDHTUMWSLXI ]{0,16}\]$'
    pattern = re.compile(input_pattern)
    flags_dict = {
        'N': '<b>N</b>o password.',
        'D': '<b>D</b>isabled.',
        'H': '<b>H</b>omedir required.',
        'T': '<b>T</b>emp account.',
        'U': '<b>U</b>ser account (normal)',
        'M': '<b>M</b>NS logon user account.',
        'W': '<b>W</b>orkstation account.',
        'S': '<b>S</b>erver account.',
        'L': '<b>L</b>ocked account.',
        'X': 'No <b>X</b>piry on password',
        'I': '<b>I</b>nterdomain trust account.',
    }

    def display(self, vidx, links) -> str:
        flags = self.av_u[1:-1] # trim brackets
        table_rows = [
            '<tr><td>%s</td><td>%s</td></tr>\n' % ({True:'*', False:''}[f in flags], d)
            for f, d in self.flags_dict.items()
        ]
        return '<pre>%s</pre><table>\n%s\n</table>\n' % (
            self._app.form.s2d(self.av_u),
            ''.join(table_rows)
        )

syntax_registry.reg_at(
    SambaAcctFlags.oid, [
        '1.3.6.1.4.1.7165.2.1.26', # sambaAcctFlags
        '1.3.6.1.4.1.7165.2.1.4',  # acctFlags
    ]
)


class SambaSID(IA5String):
    oid: str = 'SambaSID-oid'
    desc: str = 'Samba SID (SDDL syntax)'
    input_pattern: str = r'^S(-[0-9]+)+$'
    pattern = re.compile(input_pattern)

    def _search_domain_entry(self, domain_name):
        if domain_name:
            domain_filter = '(&(objectClass=sambaDomain)(sambaDomainName=%s))' % (
                ldap0.filter.escape_str(domain_name)
            )
        else:
            domain_filter = '(objectClass=sambaDomain)'
        try:
            ldap_result = self._app.ls.l.search_s(
                self._app.naming_context.encode(self._app.ls.charset),
                ldap0.SCOPE_SUBTREE,
                domain_filter,
                attrlist=['sambaSID', 'sambaDomainName'],
                sizelimit=2
            )
        except ldap0.NO_SUCH_OBJECT:
            return None
        else:
            if len(ldap_result) != 1:
                return None
            try:
                _, domain_entry = ldap_result[0].entry_as
            except (KeyError, IndexError):
                return None
            return domain_entry

    def _get_domain_sid(self):
        try:
            primary_group_sid = self._entry['sambaPrimaryGroupSID'][0]
        except (KeyError, IndexError):
            domain_name = self._entry.get('sambaDomainName', [None])[0]
            domain_entry = self._search_domain_entry(domain_name)
            if domain_entry is None:
                domain_sid = None
            else:
                domain_sid = domain_entry.get('sambaSID', [None])[0]
        else:
            domain_sid = primary_group_sid.rsplit('-', 1)[0]
        return domain_sid

    def form_value(self) -> str:
        ocs = self._entry.object_class_oid_set()
        result = IA5String.form_value(self)
        if result:
            return result
        domain_sid = self._get_domain_sid()
        if domain_sid is not None:
            try:
                if 'sambaSamAccount' in ocs and 'posixAccount' in ocs:
                    uid_number = int(self._entry['uidNumber'][0])
                    result = '-'.join((
                        self._get_domain_sid(),
                        str(2*uid_number+1000)
                    ))
                elif 'sambaGroupMapping' in ocs and 'posixGroup' in ocs:
                    gid_number = int(self._entry['gidNumber'][0])
                    result = '-'.join((
                        self._get_domain_sid(),
                        str(2*gid_number+1001)
                    ))
            except (IndexError, KeyError, ValueError):
                pass
        return result

syntax_registry.reg_at(
    SambaSID.oid, [
        '1.3.6.1.4.1.7165.2.1.20', # sambaSID
    ]
)


class SambaForceLogoff(SelectList):
    oid: str = 'SambaForceLogoff-oid'
    desc: str = 'Disconnect Users outside logon hours (default: -1 => off, 0 => on)'
    attr_value_dict: Dict[str, str] = {
        '': '',
        '0': 'on',
        '-1': 'off',
    }

syntax_registry.reg_at(
    SambaForceLogoff.oid, [
        '1.3.6.1.4.1.7165.2.1.66', # sambaForceLogoff
    ]
)

class SambaLogonToChgPwd(SelectList):
    oid: str = 'SambaLogonToChgPwd-oid'
    desc: str = 'Force Users to logon for password change (default: 0 => off, 2 => on)'
    attr_value_dict: Dict[str, str] = {
        '': '',
        '0': 'off',
        '2': 'on',
    }

syntax_registry.reg_at(
    SambaLogonToChgPwd.oid, [
        '1.3.6.1.4.1.7165.2.1.60', # sambaLogonToChgPwd
    ]
)

class SambaGroupType(SelectList):
    oid: str = 'SambaGroupType-oid'
    desc: str = 'Samba group type'
    attr_value_dict: Dict[str, str] = {
        '': '',
        '2': 'Domain Group',
        '4': 'Local Group (Alias)',
        '5': 'Built-in Group (well-known)',
    }

syntax_registry.reg_at(
    SambaGroupType.oid, [
        '1.3.6.1.4.1.7165.2.1.19', # sambaGroupType
    ]
)


class ReferencedSID(DynamicValueSelectList):
    oid: str = 'ReferencedSID-oid'
    desc: str = 'SID which points to another object'
    ldap_url = 'ldap:///_?sambaSID,cn?sub?'

syntax_registry.reg_at(
    ReferencedSID.oid, [
        '1.3.6.1.4.1.7165.2.1.51', # sambaSIDList
    ]
)


class SambaGroupSID(DynamicValueSelectList):
    oid: str = 'SambaGroupSID-oid'
    desc: str = 'SID which points to Samba group object'
    ldap_url = 'ldap:///_?sambaSID,cn?sub?(objectClass=sambaGroupMapping)'

syntax_registry.reg_at(
    SambaGroupSID.oid, [
        '1.3.6.1.4.1.7165.2.1.23', # sambaPrimaryGroupSID
    ]
)


class SambaDomainName(DynamicValueSelectList):
    oid: str = 'SambaDomainName-oid'
    desc: str = 'Name of Samba domain'
    ldap_url = 'ldap:///_?sambaDomainName,sambaDomainName?sub?(objectClass=sambaDomain)'

syntax_registry.reg_at(
    SambaDomainName.oid, [
        '1.3.6.1.4.1.7165.2.1.38', # sambaDomainName
    ]
)


syntax_registry.reg_at(
    DirectoryString.oid, [
        '1.3.6.1.4.1.7165.2.1.38', # sambaDomainName
    ],
    structural_oc_oids=[
        '1.3.6.1.4.1.7165.2.2.5', # sambaDomain
    ],
)


class SambaHomeDrive(SelectList):
    oid: str = 'SambaHomeDrive-oid'
    desc: str = 'Samba home drive letter'
    attr_value_dict: Dict[str, str] = {
        driveletter: driveletter
        for driveletter in [
            '%s:' % letter
            for letter in string.ascii_lowercase.upper()
        ]
    }

syntax_registry.reg_at(
    SambaHomeDrive.oid, [
        '1.3.6.1.4.1.7165.2.1.33', # sambaHomeDrive
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
