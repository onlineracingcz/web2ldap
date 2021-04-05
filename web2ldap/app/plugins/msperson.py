# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for msPerson
"""

import re
import os.path

import web2ldapcnf

from web2ldap.app.schema.syntaxes import \
    DateOfBirth, \
    DirectoryString, \
    IA5String, \
    PropertiesSelectList, \
    syntax_registry

# try to import vatnumber module
try:
    import vatnumber
except ImportError:
    VATNUMBER_AVAIL = False
else:
    VATNUMBER_AVAIL = True


class Gender(PropertiesSelectList):
    oid: str = 'Gender-oid'
    desc: str = 'Representation of human sex (see ISO 5218)'
    properties_pathname = os.path.join(
        web2ldapcnf.etc_dir, 'properties', 'attribute_select_gender.properties'
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
    pattern = re.compile(
        r'^((AT)?U[0-9]{8}|' +
        r'(BE)?[0-9]{10}|' +
        r'(BG)?[0-9]{9,10}|' +
        r'(CY)?[0-9]{8}L|' +
        r'(CZ)?[0-9]{8,10}|' +
        r'(DE)?[0-9]{9}|' +
        r'(DK)?[0-9]{8}|' +
        r'(EE)?[0-9]{9}|' +
        r'(EL|GR)?[0-9]{9}|' +
        r'(ES)?[0-9A-Z][0-9]{7}[0-9A-Z]|' +
        r'(FI)?[0-9]{8}|' +
        r'(FR)?[0-9A-Z]{2}[0-9]{9}|' +
        r'(GB)?([0-9]{9}([0-9]{3})?|[A-Z]{2}[0-9]{3})|' +
        r'(HU)?[0-9]{8}|' +
        r'(IE)?[0-9]S[0-9]{5}L|' +
        r'(IT)?[0-9]{11}|' +
        r'(LT)?([0-9]{9}|[0-9]{12})|' +
        r'(LU)?[0-9]{8}|' +
        r'(LV)?[0-9]{11}|' +
        r'(MT)?[0-9]{8}|' +
        r'(NL)?[0-9]{9}B[0-9]{2}|' +
        r'(PL)?[0-9]{10}|' +
        r'(PT)?[0-9]{9}|' +
        r'(RO)?[0-9]{2,10}|' +
        r'(SE)?[0-9]{12}|' +
        r'(SI)?[0-9]{8}|' +
        r'(SK)?[0-9]{10})$'
    )

    def _validate(self, attr_value: bytes) -> bool:
        if VATNUMBER_AVAIL:
            return vatnumber.check_vat(attr_value)
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
