# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for DHCP service

See https://datatracker.ietf.org/doc/html/draft-ietf-dhc-ldap-schema
"""

import ipaddress
import re
from typing import Dict

import web2ldapcnf

from ..searchform import (
    SEARCH_OPT_IS_EQUAL,
    SEARCH_OPT_BEGINS_WITH,
)
from ..schema.syntaxes import (
    MultilineText,
    IA5String,
    SelectList,
    Integer,
    BitArrayInteger,
    MacAddress,
    DynamicDNSelectList,
    DNSDomain,
    syntax_registry,
)


class DHCPConfigStatement(MultilineText):
    oid: str = 'DHCPConfigStatement-oid'
    desc: str = 'DHCP configuration statement'
    lineSep = b''

    def display(self, vidx, links) -> str:
        res = ['<code>%s</code>' % (
            MultilineText.display(self, vidx, links)
        )]
        if links:
            try:
                dhcp_type, dhcp_value = self.av_u.split(' ', 1)
            except ValueError:
                dhcp_type, dhcp_value = self.av_u, ''
            dhcp_type = dhcp_type.lower().strip()
            dhcp_value = dhcp_value.replace('"', '').strip()
            if dhcp_type == 'host-name':
                host_name = dhcp_value.lower().split('.', 1)[0]
                res.append(self._app.anchor(
                    'search', 'DNS RR',
                    (
                        ('dn', str(self._app.naming_context)),
                        ('searchform_mode', 'adv'),
                        ('search_mode', '(|%s)'),
                        ('search_attr', 'dc'),
                        ('search_option', SEARCH_OPT_IS_EQUAL),
                        ('search_string', host_name),
                        ('search_attr', 'pTRRecord'),
                        ('search_option', SEARCH_OPT_BEGINS_WITH),
                        ('search_string', host_name+'.'),
                        ('search_attr', 'associatedDomain'),
                        ('search_option', SEARCH_OPT_BEGINS_WITH),
                        ('search_string', host_name+'.'),
                    ),
                    title='Search related DNS RR entry',
                ))
            elif dhcp_type == 'fixed-address':
                search_params = [
                    ('dn', str(self._app.naming_context)),
                    ('searchform_mode', 'adv'),
                    ('search_mode', '(|%s)'),
                    ('search_attr', 'aRecord'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', dhcp_value),
                    ('search_attr', 'aAAARecord'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', dhcp_value),
                ]
                try:
                    reverse_dns = ipaddress.ip_address(dhcp_value).reverse_pointer
                except ValueError:
                    pass
                else:
                    search_params.extend((
                        ('search_attr', 'associatedDomain'),
                        ('search_option', SEARCH_OPT_IS_EQUAL),
                        ('search_string', reverse_dns),
                    ))
                res.append(
                    self._app.anchor(
                        'search', 'DNS RRs',
                        search_params,
                        title='Search related DNS RR entries',
                    )
                )
        return web2ldapcnf.command_link_separator.join(res)

syntax_registry.reg_at(
    DHCPConfigStatement.oid, [
        '2.16.840.1.113719.1.203.4.3', # dhcpStatements
        '2.16.840.1.113719.1.203.6.9', # dhcpOptions
        '2.16.840.1.113719.1.203.4.7', # dhcpOption
    ]
)


class DHCPServerDN(DynamicDNSelectList):
    oid: str = 'DHCPServerDN-oid'
    desc: str = 'DN of DHCP server entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpServer)'

syntax_registry.reg_at(
    DHCPServerDN.oid, [
        '2.16.840.1.113719.1.203.4.1', # dhcpPrimaryDN
        '2.16.840.1.113719.1.203.4.2', # dhcpSecondaryDN
        '2.16.840.1.113719.1.203.4.54', # dhcpFailOverPeerDN
    ]
)


class DHCPOptionsDN(DynamicDNSelectList):
    oid: str = 'DHCPOptionsDN-oid'
    desc: str = 'DN of DHCP option object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpOptions)'

syntax_registry.reg_at(
    DHCPOptionsDN.oid, [
        '2.16.840.1.113719.1.203.4.9', # dhcpOptionsDN
    ]
)


class DHCPHostDN(DynamicDNSelectList):
    oid: str = 'DHCPHostDN-oid'
    desc: str = 'DN of DHCP host object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpHost)'

syntax_registry.reg_at(
    DHCPHostDN.oid, [
        '2.16.840.1.113719.1.203.4.10', # dhcpHostDN
        '2.16.840.1.113719.1.203.4.31', # dhcpReservedForClient
        '2.16.840.1.113719.1.203.4.32', # dhcpAssignedToClient
    ]
)


class DHCPPoolDN(DynamicDNSelectList):
    oid: str = 'DHCPPoolDN-oid'
    desc: str = 'DN of DHCP pool object'
    ldap_url = 'ldap:///_??sub?(objectClass=dhcpPool)'

syntax_registry.reg_at(
    DHCPPoolDN.oid, [
        '2.16.840.1.113719.1.203.4.11', # dhcpPoolDN
    ]
)


class DHCPGroupDN(DynamicDNSelectList):
    oid: str = 'DHCPGroupDN-oid'
    desc: str = 'DN of DHCP group object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpGroup)'

syntax_registry.reg_at(
    DHCPGroupDN.oid, [
        '2.16.840.1.113719.1.203.4.12', # dhcpGroupDN
    ]
)


class DHCPSubnetDN(DynamicDNSelectList):
    oid: str = 'DHCPSubnetDN-oid'
    desc: str = 'DN of DHCP subnet object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpSubnet)'

syntax_registry.reg_at(
    DHCPSubnetDN.oid, [
        '2.16.840.1.113719.1.203.4.13', # dhcpSubnetDN
    ]
)


class DHCPLeasesDN(DynamicDNSelectList):
    oid: str = 'DHCPLeasesDN-oid'
    desc: str = 'DN of DHCP leases object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpLeases)'

syntax_registry.reg_at(
    DHCPLeasesDN.oid, [
        '2.16.840.1.113719.1.203.4.14', # dhcpLeaseDN
        '2.16.840.1.113719.1.203.4.15', # dhcpLeasesDN
    ]
)


class DHCPClassesDN(DynamicDNSelectList):
    oid: str = 'DHCPClassesDN-oid'
    desc: str = 'DN of DHCP classes object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpClass)'

syntax_registry.reg_at(
    DHCPClassesDN.oid, [
        '2.16.840.1.113719.1.203.4.16', # dhcpClassesDN
    ]
)


class DHCPSubclassesDN(DynamicDNSelectList):
    oid: str = 'DHCPSubclassesDN-oid'
    desc: str = 'DN of DHCP Subclasses object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpSubclass)'

syntax_registry.reg_at(
    DHCPSubclassesDN.oid, [
        '2.16.840.1.113719.1.203.4.17', # dhcpSubclassesDN
    ]
)


class DHCPSharedNetworkDN(DynamicDNSelectList):
    oid: str = 'DHCPSharedNetworkDN-oid'
    desc: str = 'DN of DHCP shared network object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpSharedNetwork)'

syntax_registry.reg_at(
    DHCPSharedNetworkDN.oid, [
        '2.16.840.1.113719.1.203.4.18', # dhcpSharedNetworkDN
    ]
)


class DHCPServiceDN(DynamicDNSelectList):
    oid: str = 'DHCPServiceDN-oid'
    desc: str = 'DN of DHCP service object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpService)'

syntax_registry.reg_at(
    DHCPServiceDN.oid, [
        '2.16.840.1.113719.1.203.4.19', # dhcpServiceDN
    ]
)


class DHCPHWAddress(MacAddress):
    oid: str = 'DHCPHWAddress-oid'
    desc: str = 'Network classifier and MAC address'
    max_len: str = 26
    pattern = re.compile(r'^(ethernet|token-ring|fddi) ([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$')

    def sanitize(self, attr_value: bytes) -> bytes:
        attr_value = attr_value.strip()
        if len(attr_value) == 17:
            return b'ethernet %s' % attr_value
        return attr_value

syntax_registry.reg_at(
    DHCPHWAddress.oid, [
        '2.16.840.1.113719.1.203.4.34', # dhcpHWAddress
    ]
)


class DHCPNetMask(Integer):
    oid: str = 'DHCPNetMask-oid'
    desc: str = 'Network address mask bits'
    min_value = 0
    max_value = 32
    input_size = 15

    def _maxlen(self, fval):
        return self.input_size

syntax_registry.reg_at(
    DHCPNetMask.oid, [
        '2.16.840.1.113719.1.203.4.6', # dhcpNetMask
    ]
)


class DHCPRange(IA5String):
    oid: str = 'DHCPRange-oid'
    desc: str = 'Network address range'

    def _get_ipnetwork(self):
        name = self._entry['cn'][0].strip().decode('ascii')
        net_mask = self._entry['dhcpNetMask'][0].strip().decode('ascii')
        return ipaddress.ip_network(('%s/%s' % (name, net_mask)), strict=False)

    def form_value(self) -> str:
        fval = IA5String.form_value(self)
        if not fval:
            try:
                ipv4_hosts = self._get_ipnetwork().hosts()
                first_address = next(ipv4_hosts)
                try:
                    while True:
                        last_address = next(ipv4_hosts)
                except StopIteration:
                    pass
                fval = '{0} {1}'.format(first_address, last_address)
            except ipaddress.AddressValueError:
                pass
        return fval

    def sanitize(self, attr_value: bytes) -> bytes:
        return attr_value.strip().replace(b'  ', b' ').replace(b'-', b' ').replace(b'..', b' ')

    def _validate(self, attr_value: bytes) -> bool:
        try:
            l_s, h_s = attr_value.decode(self._app.ls.charset).split(' ', 1)
        except (IndexError, ValueError):
            return False
        try:
            l_a = ipaddress.ip_address(l_s)
            h_a = ipaddress.ip_address(h_s)
        except Exception:
            return False
        if l_a > h_a:
            return False
        try:
            ipv4_network = self._get_ipnetwork()
        except Exception:
            # Let's simply ignore all parsing issues with network address data here
            return True
        return l_a in ipv4_network and h_a in ipv4_network


syntax_registry.reg_at(
    DHCPRange.oid, [
        '2.16.840.1.113719.1.203.4.4', # dhcpRange
    ]
)


class DHCPAddressState(SelectList):
    oid: str = 'DHCPAddressState-oid'
    desc: str = 'DHCP address state'

    attr_value_dict: Dict[str, str] = {
        '': '',
        'FREE': 'FREE',
        'ACTIVE': 'ACTIVE',
        'EXPIRED': 'EXPIRED',
        'RELEASED': 'RELEASED',
        'RESET': 'RESET',
        'ABANDONED': 'ABANDONED',
        'BACKUP': 'BACKUP',
        'UNKNOWN': 'UNKNOWN',
        'RESERVED': 'RESERVED (address managed by DHCP that is reserved for a specific client)',
        'RESERVED-ACTIVE': 'RESERVED-ACTIVE (same as reserved, but address is currently in use)',
        'ASSIGNED': 'ASSIGNED (assigned manually or by some other mechanism)',
        'UNASSIGNED': 'UNASSIGNED',
        'NOTASSIGNABLE': 'NOTASSIGNABLE',
    }


class DHCPDnsStatus(BitArrayInteger):
    """
    0 (C): name to address (such as A RR) update successfully completed
    1 (A): Server is controlling A RR on behalf of the client
    2 (D): address to name (such as PTR RR) update successfully completed (Done)
    3 (P): Server is controlling PTR RR on behalf of the client
    4-15 : Must be zero
    """
    oid: str = 'DHCPDnsStatus-oid'
    flag_desc_table = (
        ('(C): name to address (such as A RR) update successfully completed', 0x0001),
        ('(A): Server is controlling A RR on behalf of the client', 0x0002),
        ('(D): address to name (such as PTR RR) update successfully completed (Done)', 0x0004),
        ('(P): Server is controlling PTR RR on behalf of the client', 0x0008),
    )

syntax_registry.reg_at(
    DHCPDnsStatus.oid, [
        '2.16.840.1.113719.1.203.4.28', # dhcpDnsStatus
    ]
)


syntax_registry.reg_at(
    DNSDomain.oid, [
        '2.16.840.1.113719.1.203.4.27', # dhcpDomainName
    ]
)


syntax_registry.reg_at(
    DHCPAddressState.oid, [
        '2.16.840.1.113719.1.203.4.22', # dhcpAddressState
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
