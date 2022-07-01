# -*- coding: ascii -*-
"""
web2ldap plugin classes for attributes defined for PowerDNS' LDAP backend

https://doc.powerdns.com/authoritative/backends/ldap.html
"""

from typing import Dict

from ..schema.syntaxes import (
    IPHostAddress,
    SelectList,
    syntax_registry,
)


syntax_registry.reg_at(
    IPHostAddress.oid, [
        '1.3.6.1.4.1.27080.2.1.4',  # PdnsDomainMaster
    ]
)


class PdnsDomainType(SelectList):
    oid: str = 'PdnsDomainType-oid'
    desc: str = 'PowerDNS: Type of zone'

    attr_value_dict: Dict[str, str] = {
        '': '',
        'master': 'master',
        'slave': 'slave',
        'native': 'native',
    }

syntax_registry.reg_at(
    PdnsDomainType.oid, [
        '1.3.6.1.4.1.27080.2.1.5',  # PdnsDomainType
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
