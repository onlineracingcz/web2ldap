# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for DE-Mail
"""

import os.path

from ... import ETC_DIR
from ..schema.syntaxes import PropertiesSelectList, syntax_registry


class DemailMaxAuthLevel(PropertiesSelectList):
    oid: str = 'DemailMaxAuthLevel-oid'
    desc: str = 'Maximum authentication level of person/user in DE-Mail'
    properties_pathname = os.path.join(
        ETC_DIR, 'properties', 'attribute_select_demailMaxAuthLevel.properties'
    )

syntax_registry.reg_at(
    DemailMaxAuthLevel.oid, [
        '1.3.6.1.4.1.7924.2.1.1.1', # demailMaxAuthLevel
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
