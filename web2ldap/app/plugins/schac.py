# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined in SCHAC

See https://www.terena.org/activities/tf-emc2/schac.html
"""

import re
import datetime

from ..schema.syntaxes import (
    DateOfBirth,
    DirectoryString,
    IA5String,
    NumericString,
    CountryString,
    DNSDomain,
    syntax_registry,
)
from .msperson import Gender


syntax_registry.reg_at(
    CountryString.oid, [
        '1.3.6.1.4.1.25178.1.2.5',  # schacCountryOfCitizenship
        '1.3.6.1.4.1.25178.1.2.11', # schacCountryOfResidence
    ]
)

syntax_registry.reg_at(
    DNSDomain.oid, [
        '1.3.6.1.4.1.25178.1.2.9', # schacHomeOrganization
    ]
)

class SchacMotherTongue(IA5String):
    oid: str = 'SchacMotherTongue-oid'
    desc: str = 'Language tag of the language a person learns first (see RFC 3066).'
    pattern = re.compile('^[a-zA-Z]{2,8}(-[a-zA-Z0-9]{2,8})*$')

syntax_registry.reg_at(
    SchacMotherTongue.oid, [
        '1.3.6.1.4.1.25178.1.2.1', # schacMotherTongue
    ]
)


syntax_registry.reg_at(
    Gender.oid, [
        '1.3.6.1.4.1.25178.1.2.2', # schacGender
    ]
)


class SchacDateOfBirth(DateOfBirth):
    oid: str = 'SchacDateOfBirth-oid'
    desc: str = 'Date of birth: syntax YYYYMMDD'
    storageFormat = '%Y%m%d'

syntax_registry.reg_at(
    SchacDateOfBirth.oid, [
        '1.3.6.1.4.1.25178.1.2.3', # schacDateOfBirth
    ]
)


class SchacYearOfBirth(NumericString):
    oid: str = 'SchacYearOfBirth-oid'
    desc: str = 'Year of birth: syntax YYYY'
    max_len: str = 4
    input_pattern: str = '^[0-9]{4}$'
    pattern = re.compile(input_pattern)

    def _validate(self, attr_value: bytes) -> bool:
        try:
            birth_year = int(attr_value)
        except ValueError:
            return False
        return birth_year <= datetime.date.today().year

syntax_registry.reg_at(
    SchacYearOfBirth.oid, [
        '1.3.6.1.4.1.25178.1.0.2.3', # schacYearOfBirth
    ]
)


class SchacUrn(DirectoryString):
    oid: str = 'SchacUrn-oid'
    desc: str = 'Generic URN for SCHAC'
    input_pattern: str = '^urn:mace:terena.org:schac:.+$'
    pattern = re.compile(input_pattern)

syntax_registry.reg_at(
    SchacUrn.oid, [
        '1.3.6.1.4.1.25178.1.2.10', # schacHomeOrganizationType
        '1.3.6.1.4.1.25178.1.2.13', # schacPersonalPosition
        '1.3.6.1.4.1.25178.1.2.14', # schacPersonalUniqueCode
        '1.3.6.1.4.1.25178.1.2.15', # schacPersonalUniqueID
        '1.3.6.1.4.1.25178.1.2.19', # schacUserStatus
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
