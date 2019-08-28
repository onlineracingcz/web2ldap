"""
vendorext.py - classes for vendor specific X.509v3 extensions

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

# Pisces
from web2ldap.pisces import asn1


class EntrustVersInfo(asn1.OctetString):
    """
    entrustVersInfo EXTENSION ::= {
            SYNTAX EntrustVersInfoSyntax
            IDENTIFIED BY { id-nsn-ext 0}
    }

    EntrustVersInfoSyntax ::= OCTET STRING
    """
    def __init__(self, val):
        asn1.OctetString.__init__(self, val)
        self.val = val

    def __str__(self):
        return str(self.val[0])+repr(self.val[1])
