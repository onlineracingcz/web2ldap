# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for DE-Mail
"""

import os.path

import web2ldapcnf

from web2ldap.app.schema.syntaxes import PropertiesSelectList, syntax_registry


class DemailMaxAuthLevel(PropertiesSelectList):
    oid = 'DemailMaxAuthLevel-oid'
    desc = 'Maximum authentication level of person/user in DE-Mail'
    properties_pathname = os.path.join(
        web2ldapcnf.etc_dir, 'properties', 'attribute_select_demailMaxAuthLevel.properties'
    )

syntax_registry.reg_at(
    DemailMaxAuthLevel.oid, [
        '1.3.6.1.4.1.7924.2.1.1.1', # demailMaxAuthLevel
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
