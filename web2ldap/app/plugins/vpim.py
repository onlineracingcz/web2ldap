# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined in VPIM (see RFC 4237)
"""

from typing import Dict

from ..schema.syntaxes import SelectList, RFC822Address, syntax_registry


syntax_registry.reg_at(
    RFC822Address.oid, [
        '1.3.6.1.1.11.1.2.2', # vPIMRfc822Mailbox
    ]
)


class VPIMExtendedAbsenceStatus(SelectList):
    oid: str = 'VPIMExtendedAbsenceStatus-oid'
    desc: str = ''

    attr_value_dict: Dict[str, str] = {
        '': '',
        'Off': 'Off',
        'On': 'On',
        'MsgBlocked': 'MsgBlocked',
    }

syntax_registry.reg_at(
    VPIMExtendedAbsenceStatus.oid, [
        '1.3.6.1.1.11.1.2.7', # vPIMExtendedAbsenceStatus
    ]
)


class VPIMSupportedUABehaviors(SelectList):
    oid: str = 'VPIMSupportedUABehaviors-oid'
    desc: str = ''

    attr_value_dict: Dict[str, str] = {
        '':'',
        'MessageDispositionNotification': 'recipient will send a MDN in response to an MDN request',
        'MessageSensitivity': 'recipient supports sensitivity indication',
        'MessageImportance': 'recipient supports importance indication',
    }

syntax_registry.reg_at(
    VPIMSupportedUABehaviors.oid, [
        '1.3.6.1.1.11.1.2.8', # vPIMSupportedUABehaviors
    ]
)


class VPIMSupportedAudioMediaTypes(SelectList):
    oid: str = 'VPIMSupportedAudioMediaTypes-oid'
    desc: str = 'Audio Media Types'

    attr_value_dict: Dict[str, str] = {
        'audio/basic': 'audio/basic',
        'audio/mpeg': 'audio/mpeg',
        'audio/x-aiff': 'audio/x-aiff',
        'audio/x-realaudio': 'audio/x-realaudio',
        'audio/x-wav': 'audio/x-wav',
    }

syntax_registry.reg_at(
    VPIMSupportedAudioMediaTypes.oid, [
        '1.3.6.1.1.11.1.2.5', # vPIMSupportedAudioMediaTypes
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
