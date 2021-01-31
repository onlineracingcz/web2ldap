# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined eduPerson

See http://middleware.internet2.edu/eduperson/
"""

import re
from typing import Dict

from web2ldap.app.schema.syntaxes import IA5String, SelectList, DynamicDNSelectList, syntax_registry


class EduPersonAffiliation(SelectList):
    oid: str = 'EduPersonAffiliation-oid'
    desc: str = 'Affiliation (see eduPerson)'

    attr_value_dict: Dict[str, str] = {
        '': '',
        'faculty': 'faculty',
        'student': 'student',
        'staff': 'staff',
        'alum': 'alum',
        'member': 'member',
        'affiliate': 'affiliate',
        'employee': 'employee',
        'library-walk-in': 'library-walk-in',
    }

syntax_registry.reg_at(
    EduPersonAffiliation.oid, [
        '1.3.6.1.4.1.5923.1.1.1.1', # eduPersonAffiliation
        '1.3.6.1.4.1.5923.1.1.1.5', # eduPersonPrimaryAffiliation
    ]
)


class EduPersonScopedAffiliation(IA5String):
    oid: str = 'EduPersonScopedAffiliation-oid'
    desc: str = 'Scoped affiliation (see eduPerson)'
    reObj = re.compile('^(faculty|student|staff|alum|member|affiliate|employee|library-walk-in)@[a-zA-Z0-9.-]+$')

syntax_registry.reg_at(
    EduPersonScopedAffiliation.oid, [
        '1.3.6.1.4.1.5923.1.1.1.9', # eduPersonScopedAffiliation
    ]
)


class EduPersonOrgUnitDN(DynamicDNSelectList):
    oid: str = 'EduPersonOrgUnitDN-oid'
    desc: str = 'DN of associated organizational unit entry (see eduPerson)'
    ldap_url = 'ldap:///_??sub?(objectClass=organizationalUnit)'

syntax_registry.reg_at(
    EduPersonOrgUnitDN.oid, [
        '1.3.6.1.4.1.5923.1.1.1.4', # eduPersonOrgUnitDN
        '1.3.6.1.4.1.5923.1.1.1.8', # eduPersonPrimaryOrgUnitDN
    ]
)


class EduPersonOrgDN(DynamicDNSelectList):
    oid: str = 'EduPersonOrgDN-oid'
    desc: str = 'DN of associated organization entry (see eduPerson)'
    ldap_url = 'ldap:///_??sub?(objectClass=organization)'

syntax_registry.reg_at(
    EduPersonOrgDN.oid, [
        '1.3.6.1.4.1.5923.1.1.1.3', # eduPersonOrgDN
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
