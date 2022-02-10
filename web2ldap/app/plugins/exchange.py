# -*- coding: ascii -*-
"""
web2ldap plugin classes for MS Exchange 5.5
"""

from ..schema.syntaxes import syntax_registry, RFC822Address, Binary, BitArrayInteger
from .activedirectory import MsAdGUID

syntax_registry.reg_at(
    RFC822Address.oid, [
        '1.2.840.113556.1.2.728', # rfc822Mailbox
        '1.2.840.113556.1.2.729', # mail
    ]
)

# MS AD declares these attributes with OctetString
# syntax but Binary syntax is more suitable
syntax_registry.reg_at(
    Binary.oid, [
        '1.2.840.113556.1.4.7000.102.80',    # msExchMailboxSecurityDescriptor
        '1.2.840.113556.1.4.7000.102.50765', # msExchSafeSendersHash
    ]
)

syntax_registry.reg_at(
    MsAdGUID.oid, [
        '1.2.840.113556.1.4.7000.102.11058', # msExchMailboxGuid
    ]
)


class MsExchRecipientTypeDetails(BitArrayInteger):
    """
    MS Exchange Recipient Type (no formal spec found yet)
    """
    oid: str = 'MsExchRecipientTypeDetails-oid'
    desc: str = 'MS Exchange Recipient Type'
    flag_desc_table = (
        ('UserMailbox', 1),
        ('LinkedMailbox', 2),
        ('SharedMailbox', 4),
        ('LegacyMailbox', 8),
        ('RoomMailbox', 16),
        ('EquipmentMailbox', 32),
        ('MailContact', 64),
        ('MailUser', 128),
        ('MailUniversalDistributionGroup', 256),
        ('MailNonUniversalGroup', 512),
        ('MailUniversalSecurityGroup', 1024),
        ('DynamicDistributionGroup', 2048),
        ('PublicFolder', 4096),
        ('SystemAttendantMailbox', 8192),
        ('SystemMailbox', 16384),
        ('MailForestContact', 32768),
        ('User', 65536),
        ('Contact', 131072),
        ('UniversalDistributionGroup', 262144),
        ('UniversalSecurityGroup', 524288),
        ('NonUniversalGroup', 1048576),
        ('DisableUser', 2097152),
        ('MicrosoftExchange', 4194304),
        ('ArbitrationMailbox', 8388608),
        ('MailboxPlan', 16777216),
        ('LinkedUser', 33554432),
        ('RoomList', 268435456),
        ('DiscoveryMailbox', 536870912),
        ('RoleGroup', 1073741824),
        ('RemoteUserMailbox', 2147483648),
        ('Computer', 4294967296),
        ('RemoteRoomMailbox', 8589934592),
        ('RemoteEquipmentMailbox', 17179869184),
        ('RemoteSharedMailbox', 34359738368),
        ('PublicFolderMailbox', 68719476736),
        ('TeamMailbox', 137438953472),
        ('RemoteTeamMailbox', 274877906944),
        ('MonitoringMailbox', 549755813888),
        ('GroupMailbox', 1099511627776),
        ('LinkedRoomMailbox', 2199023255552),
        ('AuditLogMailbox', 4398046511104),
        ('RemoteGroupMailbox', 8796093022208),
        ('SchedulingMailbox', 17592186044416),
        ('GuestMailUser', 35184372088832),
        ('AuxAuditLogMailbox', 70368744177664),
        ('SupervisoryReviewPolicyMailbox', 140737488355328),
    )

syntax_registry.reg_at(
    MsExchRecipientTypeDetails.oid, [
        'msExchRecipientTypeDetails',
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
