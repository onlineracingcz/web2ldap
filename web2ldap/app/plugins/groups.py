"""
web2ldap plugin classes for group related attributes
"""

from web2ldap.app.schema.syntaxes import DistinguishedName, syntax_registry


class Member(DistinguishedName):
    oid = 'Member-oid'
    desc = 'member attribute in a group entry'

syntax_registry.reg_at(
    Member.oid, [
        '2.5.4.31', # member
    ]
)


class MemberOf(DistinguishedName):
    oid = 'MemberOf-oid'
    desc = 'memberOf attribute in a group member entry'
    ref_attrs = (
        (None, u'Group members', None, u'Search all members of this group'),
    )

syntax_registry.reg_at(
    MemberOf.oid, [
        '1.2.840.113556.1.2.102', # memberOf
    ]
)


class GroupEntryDN(DistinguishedName):
    oid = 'GroupEntryDN-oid'
    desc = 'entryDN attribute in a group entry'
    ref_attrs = (
        ('memberOf', u'Group members', None, u'Search all members of this group'),
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
