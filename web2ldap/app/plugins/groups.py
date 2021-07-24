# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for group related attributes
"""

from ..schema.syntaxes import DistinguishedName, syntax_registry


class Member(DistinguishedName):
    oid: str = 'Member-oid'
    desc: str = 'member attribute in a group entry'

syntax_registry.reg_at(
    Member.oid, [
        '2.5.4.31', # member
    ]
)


class MemberOf(DistinguishedName):
    oid: str = 'MemberOf-oid'
    desc: str = 'memberOf attribute in a group member entry'
    ref_attrs = (
        (None, 'Group members', None, 'Search all members of this group'),
    )

syntax_registry.reg_at(
    MemberOf.oid, [
        '1.2.840.113556.1.2.102', # memberOf
    ]
)


class GroupEntryDN(DistinguishedName):
    oid: str = 'GroupEntryDN-oid'
    desc: str = 'entryDN attribute in a group entry'
    ref_attrs = (
        ('memberOf', 'Group members', None, 'Search all members of this group'),
    )

syntax_registry.reg_at(
    GroupEntryDN.oid, [
        '1.3.6.1.1.20', # entryDN
    ],
    structural_oc_oids=[
        '2.5.6.9', # groupOfNames
        '2.5.6.17', # groupOfUniqueNames
        '1.2.826.0.1.3458854.2.1.1.1', # groupOfEntries
    ],
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
