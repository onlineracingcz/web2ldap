# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined in VPIM (see RFC 4237)
"""

from web2ldap.app.schema.syntaxes import SelectList, RFC822Address, syntax_registry


syntax_registry.reg_at(
    RFC822Address.oid, [
        '1.3.6.1.1.11.1.2.2', # vPIMRfc822Mailbox
    ]
)


class VPIMExtendedAbsenceStatus(SelectList):
    oid = 'VPIMExtendedAbsenceStatus-oid'
    desc = ''

    attr_value_dict = {
        u'': u'',
        u'Off': u'Off',
        u'On': u'On',
        u'MsgBlocked': u'MsgBlocked',
    }

syntax_registry.reg_at(
    VPIMExtendedAbsenceStatus.oid, [
        '1.3.6.1.1.11.1.2.7', # vPIMExtendedAbsenceStatus
    ]
)


class VPIMSupportedUABehaviors(SelectList):
    oid = 'VPIMSupportedUABehaviors-oid'
    desc = ''

    attr_value_dict = {
        u'':'',
        u'MessageDispositionNotification': u'recipient will send a MDN in response to an MDN request',
        u'MessageSensitivity': u'recipient supports sensitivity indication',
        u'MessageImportance': u'recipient supports importance indication',
    }

syntax_registry.reg_at(
    VPIMSupportedUABehaviors.oid, [
        '1.3.6.1.1.11.1.2.8', # vPIMSupportedUABehaviors
    ]
)


class VPIMSupportedAudioMediaTypes(SelectList):
    oid = 'VPIMSupportedAudioMediaTypes-oid'
    desc = 'Audio Media Types'

    attr_value_dict = {
        u'audio/basic': u'audio/basic',
        u'audio/mpeg': u'audio/mpeg',
        u'audio/x-aiff': u'audio/x-aiff',
        u'audio/x-realaudio': u'audio/x-realaudio',
        u'audio/x-wav': u'audio/x-wav',
    }

syntax_registry.reg_at(
    VPIMSupportedAudioMediaTypes.oid, [
        '1.3.6.1.1.11.1.2.5', # vPIMSupportedAudioMediaTypes
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
