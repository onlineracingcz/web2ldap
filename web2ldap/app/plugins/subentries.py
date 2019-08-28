# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for subentries (see RFC 3672)
"""

from web2ldap.app.schema.syntaxes import GSER, SelectList, syntax_registry


class SubtreeSpecification(GSER):
    oid = '1.3.6.1.4.1.1466.115.121.1.45'
    desc = 'SubtreeSpecification'


class AdministrativeRole(SelectList):
    oid = 'AdministrativeRole-oid'
    desc = (
        'RFC 3672: indicate that the associated administrative'
        ' area is concerned with one or more administrative roles'
    )

    attr_value_dict = {
        u'2.5.23.1': u'autonomousArea',
        u'2.5.23.2': u'accessControlSpecificArea',
        u'2.5.23.3': u'accessControlInnerArea',
        u'2.5.23.4': u'subschemaAdminSpecificArea',
        u'2.5.23.5': u'collectiveAttributeSpecificArea',
        u'2.5.23.6': u'collectiveAttributeInnerArea',
    }

syntax_registry.reg_at(
    AdministrativeRole.oid, [
        '2.5.18.5', # administrativeRole (defined in RFC 3672)
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
