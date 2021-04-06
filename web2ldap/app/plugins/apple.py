# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined in apple.schema
"""

from ...web.forms import Field
from ..searchform import SEARCH_OPT_IS_EQUAL
from ..schema.syntaxes import (
    XmlValue,
    UUID,
    DynamicValueSelectList,
    syntax_registry,
)


syntax_registry.reg_at(
    UUID.oid, [
        '1.3.6.1.4.1.63.1000.1.1.1.1.20', # apple-generateduid
    ]
)


class UUIDReference(DynamicValueSelectList, UUID):
    oid: str = 'UUIDReference-oid'
    ldap_url = 'ldap:///_?apple-generateduid,entryDN?sub?(apple-generateduid=*)'

    def display(self, valueindex=0, commandbutton=False) -> str:
        value_disp = self._app.form.utf2display(self.av_u)
        return ' '.join((
            value_disp,
            self._app.anchor(
                'searchform', '&raquo;',
                (
                    ('dn', self._dn),
                    ('searchform_mode', u'adv'),
                    ('search_attr', u'apple-generateduid'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', value_disp),
                ),
                title=u'Search entry by UUID',
            )
        ))

    def input_field(self) -> Field:
        return DynamicValueSelectList.input_field(self)

syntax_registry.reg_at(
    UUIDReference.oid, [
        '1.3.6.1.4.1.63.1000.1.1.1.14.7', # apple-group-memberguid
        '1.3.6.1.4.1.63.1000.1.1.1.14.10', # apple-ownerguid
    ]
)


syntax_registry.reg_at(
    XmlValue.oid, [
        '1.3.6.1.4.1.63.1000.1.1.1.19.6', # apple-serviceinfo
        '1.3.6.1.4.1.63.1000.1.1.1.17.1', # apple-xmlplist
        '1.3.6.1.4.1.63.1000.1.1.1.14.8', # apple-group-services
        '1.3.6.1.4.1.63.1000.1.1.1.1.9', # apple-user-mailattribute
        '1.3.6.1.4.1.63.1000.1.1.1.1.10', # apple-mcxflags
        '1.3.6.1.4.1.63.1000.1.1.1.1.16', # apple-mcxsettings, apple-mcxsettings2
        '1.3.6.1.4.1.63.1000.1.1.1.1.13', # apple-user-printattribute
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
