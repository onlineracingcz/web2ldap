# -*- coding: ascii -*-
"""
web2ldap plugin classes for attributes defined for subentries (see RFC 3672)
"""

from typing import Dict

from ..schema.syntaxes import GSER, SelectList, syntax_registry


class SubtreeSpecification(GSER):
    oid: str = '1.3.6.1.4.1.1466.115.121.1.45'
    desc: str = 'SubtreeSpecification'


class AdministrativeRole(SelectList):
    oid: str = 'AdministrativeRole-oid'
    desc = (
        'RFC 3672: indicate that the associated administrative'
        ' area is concerned with one or more administrative roles'
    )
    attr_value_dict: Dict[str, str] = {
        '2.5.23.1': 'autonomousArea',
        '2.5.23.2': 'accessControlSpecificArea',
        '2.5.23.3': 'accessControlInnerArea',
        '2.5.23.4': 'subschemaAdminSpecificArea',
        '2.5.23.5': 'collectiveAttributeSpecificArea',
        '2.5.23.6': 'collectiveAttributeInnerArea',
    }

syntax_registry.reg_at(
    AdministrativeRole.oid, [
        '2.5.18.5', # administrativeRole (defined in RFC 3672)
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
