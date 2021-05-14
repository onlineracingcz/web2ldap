# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for msPerson
"""

import re
import os.path

# try to import vatnumber module
try:
    import vatnumber
except ImportError:
    VATNUMBER_AVAIL = False
else:
    VATNUMBER_AVAIL = True

from ... import ETC_DIR
from ..schema.syntaxes import (
    DateOfBirth,
    DirectoryString,
    IA5String,
    PropertiesSelectList,
    syntax_registry,
)


class Gender(PropertiesSelectList):
    """
    Plugin for reading ISO 5218 standard representation of gender
    from configured properties file
    """
    oid: str = 'Gender-oid'
    desc: str = 'Representation of human sex (see ISO 5218)'
    properties_pathname = os.path.join(
        ETC_DIR, 'properties', 'attribute_select_gender.properties'
    )

syntax_registry.reg_at(
    Gender.oid, [
        '1.3.6.1.4.1.5427.1.389.4.7', # gender (defined for msPerson)
    ]
)


syntax_registry.reg_at(
    DateOfBirth.oid, [
        '1.3.6.1.4.1.5427.1.389.4.2', # dateOfBirth
    ]
)


class LabeledBICandIBAN(DirectoryString):
    """
    More information:
    https://de.wikipedia.org/wiki/International_Bank_Account_Number
    http://www.pruefziffernberechnung.de/I/IBAN.shtml
    """
    oid: str = 'LabeledBICandIBAN-oid'
    desc: str = 'International bank account number (IBAN) syntax (see ISO 13616:1997)'

syntax_registry.reg_at(
    LabeledBICandIBAN.oid, [
        '1.3.6.1.4.1.5427.1.389.4.13', # labeledBICandIBAN
    ]
)


class EuVATId(IA5String):
    """
    More information:
    http://www.bzst.de/DE/Steuern_International/USt_Identifikationsnummer/Merkblaetter/Aufbau_USt_IdNr.pdf
    https://de.wikipedia.org/wiki/Umsatzsteuer-Identifikationsnummer
    """
    oid: str = 'EuVATId-oid'
    desc: str = 'Value Added Tax Ident Number of organizations within European Union'
    pattern = re.compile((
        '^('
        '(AT)?U[0-9]{8}|'
        '(BE)?[0-9]{10}|'
        '(BG)?[0-9]{9,10}|'
        '(CY)?[0-9]{8}L|'
        '(CZ)?[0-9]{8,10}|'
        '(DE)?[0-9]{9}|'
        '(DK)?[0-9]{8}|'
        '(EE)?[0-9]{9}|'
        '(EL|GR)?[0-9]{9}|'
        '(ES)?[0-9A-Z][0-9]{7}[0-9A-Z]|'
        '(FI)?[0-9]{8}|'
        '(FR)?[0-9A-Z]{2}[0-9]{9}|'
        '(GB)?([0-9]{9}([0-9]{3})?|[A-Z]{2}[0-9]{3})|'
        '(HU)?[0-9]{8}|'
        '(IE)?[0-9]S[0-9]{5}L|'
        '(IT)?[0-9]{11}|'
        '(LT)?([0-9]{9}|[0-9]{12})|'
        '(LU)?[0-9]{8}|'
        '(LV)?[0-9]{11}|'
        '(MT)?[0-9]{8}|'
        '(NL)?[0-9]{9}B[0-9]{2}|'
        '(PL)?[0-9]{10}|'
        '(PT)?[0-9]{9}|'
        '(RO)?[0-9]{2,10}|'
        '(SE)?[0-9]{12}|'
        '(SI)?[0-9]{8}|'
        '(SK)?[0-9]{10}'
        ')$'
    ))

    def _validate(self, attr_value: bytes) -> bool:
        if VATNUMBER_AVAIL:
            try:
                av_u = self._app.ls.uc_decode(attr_value)[0]
            except UnicodeDecodeError:
                return False
            return vatnumber.check_vat(av_u)
        return IA5String._validate(self, attr_value)

    def sanitize(self, attr_value: bytes) -> bytes:
        return attr_value.upper().replace(b' ', b'')

syntax_registry.reg_at(
    EuVATId.oid, [
        '1.3.6.1.4.1.5427.1.389.4.11', # euVATId
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
