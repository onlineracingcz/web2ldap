# -*- coding: ascii -*-
"""
web2ldap plugin classes for dNSDomain/dNSDomain2 schema

http://bind-dlz.sourceforge.net/ldap_driver.html
"""

from ..schema.syntaxes import (
    DNSDomain,
    DomainComponent,
    syntax_registry,
)


DNSZONE_OBJECTCLASS_OIDS = [
    '1.3.6.1.4.1.2428.20.3', # dNSZone
]


class RelativeDomainName(DomainComponent):
    oid: str = 'RelativeDomainName-oid'
    desc: str = 'Left-most DNS label'

syntax_registry.reg_at(
    RelativeDomainName.oid, [
        '1.3.6.1.4.1.2428.20.0.3', # relativeDomainName
    ],
    structural_oc_oids=DNSZONE_OBJECTCLASS_OIDS,
)


class ZoneName(DNSDomain):
    oid: str = 'ZoneName-oid'
    desc: str = 'Zone DNS name'

syntax_registry.reg_at(
    ZoneName.oid, [
        '1.3.6.1.4.1.2428.20.0.2', # zoneName
    ],
    structural_oc_oids=DNSZONE_OBJECTCLASS_OIDS,
)
