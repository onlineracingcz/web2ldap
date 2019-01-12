# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for attributes defined for DHCP service

See http://tools.ietf.org/draft/draft-ietf-dhc-ldap-schema/
"""

from __future__ import absolute_import

import re

import ipaddress

import web2ldapcnf

import web2ldap.app.searchform
from web2ldap.app.schema.syntaxes import \
    MultilineText, \
    IA5String, \
    SelectList, \
    Integer, \
    BitArrayInteger, \
    MacAddress, \
    DynamicDNSelectList, \
    DNSDomain, \
    syntax_registry


class DHCPConfigStatement(MultilineText):
    oid = 'DHCPConfigStatement-oid'
    desc = 'DHCP configuration statement'
    lineSep = u''
    whitespace_cleaning = False

    def displayValue(self, valueindex=0, commandbutton=False):
        r = ['<code>%s</code>' % (
            MultilineText.displayValue(self, valueindex, commandbutton)
        )]
        if commandbutton:
            try:
                dhcp_type, dhcp_value = self.attrValue.split(' ', 1)
            except ValueError:
                dhcp_type, dhcp_value = self.attrValue, ''
            dhcp_type = self._ls.uc_decode(dhcp_type.lower().strip())[0]
            dhcp_value = self._ls.uc_decode(dhcp_value.replace('"', '').strip())[0]
            if dhcp_type == 'host-name':
                host_name = dhcp_value.lower()
                r.append(self._form.applAnchor(
                    'search', 'DNS RR', self._sid,
                    (
                        ('dn', self._ls.getSearchRoot(self._ls.uc_decode(self._dn)[0])),
                        ('searchform_mode', u'adv'),
                        ('search_mode', u'(|%s)'),
                        ('search_attr', u'dc'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                        ('search_string', host_name),
                        ('search_attr', u'pTRRecord'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_BEGINS_WITH),
                        ('search_string', host_name+u'.'),
                        ('search_attr', u'associatedDomain'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_BEGINS_WITH),
                        ('search_string', host_name+u'.'),
                    ),
                    title=u'Search related DNS RR entry',
                ))
            elif dhcp_type == 'fixed-address':
                search_params = [
                    ('dn', self._ls.getSearchRoot(self._ls.uc_decode(self._dn)[0])),
                    ('searchform_mode', u'adv'),
                    ('search_mode', u'(|%s)'),
                    ('search_attr', u'aRecord'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', dhcp_value),
                    ('search_attr', u'aAAARecord'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', dhcp_value),
                ]
                try:
                    reverse_dns = ipaddress.ip_address(dhcp_value).reverse_pointer
                except:
                    pass
                else:
                    search_params.extend((
                        ('search_attr', u'associatedDomain'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                        ('search_string', self._ls.uc_decode(reverse_dns)[0][:-1]),
                    ))
                r.append(
                    self._form.applAnchor(
                        'search', 'DNS RRs', self._sid,
                        search_params,
                        title=u'Search related DNS RR entries',
                    )
                )
        return web2ldapcnf.command_link_separator.join(r)

syntax_registry.reg_at(
    DHCPConfigStatement.oid, [
        '2.16.840.1.113719.1.203.4.3', # dhcpStatements
        '2.16.840.1.113719.1.203.6.9', # dhcpOptions
        '2.16.840.1.113719.1.203.4.7', # dhcpOption
    ]
)


class DHCPServerDN(DynamicDNSelectList):
    oid = 'DHCPServerDN-oid'
    desc = 'DN of DHCP server entry'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpServer)'

syntax_registry.reg_at(
    DHCPServerDN.oid, [
        '2.16.840.1.113719.1.203.4.1', # dhcpPrimaryDN
        '2.16.840.1.113719.1.203.4.2', # dhcpSecondaryDN
        '2.16.840.1.113719.1.203.4.54', # dhcpFailOverPeerDN
    ]
)


class DHCPOptionsDN(DynamicDNSelectList):
    oid = 'DHCPOptionsDN-oid'
    desc = 'DN of DHCP option object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpOptions)'

syntax_registry.reg_at(
    DHCPOptionsDN.oid, [
        '2.16.840.1.113719.1.203.4.9', # dhcpOptionsDN
    ]
)


class DHCPHostDN(DynamicDNSelectList):
    oid = 'DHCPHostDN-oid'
    desc = 'DN of DHCP host object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpHost)'

syntax_registry.reg_at(
    DHCPHostDN.oid, [
        '2.16.840.1.113719.1.203.4.10', # dhcpHostDN
        '2.16.840.1.113719.1.203.4.31', # dhcpReservedForClient
        '2.16.840.1.113719.1.203.4.32', # dhcpAssignedToClient
    ]
)


class DHCPPoolDN(DynamicDNSelectList):
    oid = 'DHCPPoolDN-oid'
    desc = 'DN of DHCP pool object'
    ldap_url = 'ldap:///_??sub?(objectClass=dhcpPool)'

syntax_registry.reg_at(
    DHCPPoolDN.oid, [
        '2.16.840.1.113719.1.203.4.11', # dhcpPoolDN
    ]
)


class DHCPGroupDN(DynamicDNSelectList):
    oid = 'DHCPGroupDN-oid'
    desc = 'DN of DHCP group object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpGroup)'

syntax_registry.reg_at(
    DHCPGroupDN.oid, [
        '2.16.840.1.113719.1.203.4.12', # dhcpGroupDN
    ]
)


class DHCPSubnetDN(DynamicDNSelectList):
    oid = 'DHCPSubnetDN-oid'
    desc = 'DN of DHCP subnet object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpSubnet)'

syntax_registry.reg_at(
    DHCPSubnetDN.oid, [
        '2.16.840.1.113719.1.203.4.13', # dhcpSubnetDN
    ]
)


class DHCPLeasesDN(DynamicDNSelectList):
    oid = 'DHCPLeasesDN-oid'
    desc = 'DN of DHCP leases object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpLeases)'

syntax_registry.reg_at(
    DHCPLeasesDN.oid, [
        '2.16.840.1.113719.1.203.4.14', # dhcpLeaseDN
        '2.16.840.1.113719.1.203.4.15', # dhcpLeasesDN
    ]
)


class DHCPClassesDN(DynamicDNSelectList):
    oid = 'DHCPClassesDN-oid'
    desc = 'DN of DHCP classes object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpClass)'

syntax_registry.reg_at(
    DHCPClassesDN.oid, [
        '2.16.840.1.113719.1.203.4.16', # dhcpClassesDN
    ]
)


class DHCPSubclassesDN(DynamicDNSelectList):
    oid = 'DHCPSubclassesDN-oid'
    desc = 'DN of DHCP Subclasses object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpSubclass)'

syntax_registry.reg_at(
    DHCPSubclassesDN.oid, [
        '2.16.840.1.113719.1.203.4.17', # dhcpSubclassesDN
    ]
)


class DHCPSharedNetworkDN(DynamicDNSelectList):
    oid = 'DHCPSharedNetworkDN-oid'
    desc = 'DN of DHCP shared network object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpSharedNetwork)'

syntax_registry.reg_at(
    DHCPSharedNetworkDN.oid, [
        '2.16.840.1.113719.1.203.4.18', # dhcpSharedNetworkDN
    ]
)


class DHCPServiceDN(DynamicDNSelectList):
    oid = 'DHCPServiceDN-oid'
    desc = 'DN of DHCP service object'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=dhcpService)'

syntax_registry.reg_at(
    DHCPServiceDN.oid, [
        '2.16.840.1.113719.1.203.4.19', # dhcpServiceDN
    ]
)


class DHCPHWAddress(MacAddress):
    oid = 'DHCPHWAddress-oid'
    desc = 'Network classifier and MAC address'
    maxLen = 26
    reObj = re.compile(r'^(ethernet|token-ring|fddi) ([0-9a-fA-F]{2}\:){5}[0-9a-fA-F]{2}$')

    def sanitizeInput(self, attrValue):
        attrValue = attrValue.strip()
        if len(attrValue) == 17:
            return 'ethernet %s' % attrValue
        return attrValue

syntax_registry.reg_at(
    DHCPHWAddress.oid, [
        '2.16.840.1.113719.1.203.4.34', # dhcpHWAddress
    ]
)


class DHCPNetMask(Integer):
    oid = 'DHCPNetMask-oid'
    desc = 'Network address mask bits'
    maxValue = 0
    maxValue = 32
    inputSize = 15

    def _maxlen(self, form_value):
        return self.inputSize

syntax_registry.reg_at(
    DHCPNetMask.oid, [
        '2.16.840.1.113719.1.203.4.6', # dhcpNetMask
    ]
)


class DHCPRange(IA5String):
    oid = 'DHCPRange-oid'
    desc = 'Network address range'

    def _get_ipnetwork(self):
        cn = self._entry['cn'][0].strip()
        net_mask = self._entry['dhcpNetMask'][0].strip()
        return ipaddress.ip_network(('%s/%s' % (cn, net_mask)).decode('ascii'), strict=False)

    def formValue(self):
        form_value = IA5String.formValue(self)
        if not form_value:
          try:
            ipv4_network = self._get_ipnetwork().hosts()
            form_value = u' '.join((unicode(ipv4_network[0]), unicode(ipv4_network[-1])))
          except Exception:
            pass
        return form_value

    def sanitizeInput(self, attrValue):
        return attrValue.strip().replace('  ', ' ').replace('-', ' ').replace('..', ' ')

    def _validate(self, attrValue):
        try:
            l, h = attrValue.split(' ', 1)
        except (IndexError, ValueError):
            return False
        try:
            l_a = ipaddress.ip_address(l.decode(self._ls.charset))
            h_a = ipaddress.ip_address(h.decode(self._ls.charset))
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
    oid = 'DHCPAddressState-oid'
    desc = 'DHCP address state'

    attr_value_dict = {
        u'': u'',
        u'FREE': u'FREE',
        u'ACTIVE': u'ACTIVE',
        u'EXPIRED': u'EXPIRED',
        u'RELEASED': u'RELEASED',
        u'RESET': u'RESET',
        u'ABANDONED': u'ABANDONED',
        u'BACKUP': u'BACKUP',
        u'UNKNOWN': u'UNKNOWN',
        u'RESERVED': u'RESERVED (an address that is managed by DHCP that is reserved for a specific client)',
        u'RESERVED-ACTIVE': u'RESERVED-ACTIVE (same as reserved, but address is currently in use)',
        u'ASSIGNED': u'ASSIGNED (assigned manually or by some other mechanism)',
        u'UNASSIGNED': u'UNASSIGNED',
        u'NOTASSIGNABLE': u'NOTASSIGNABLE',
    }


class DHCPDnsStatus(BitArrayInteger):
    """
    0 (C): name to address (such as A RR) update successfully completed
    1 (A): Server is controlling A RR on behalf of the client
    2 (D): address to name (such as PTR RR) update successfully completed (Done)
    3 (P): Server is controlling PTR RR on behalf of the client
    4-15 : Must be zero
    """
    oid = 'DHCPDnsStatus-oid'
    flag_desc_table = (
        (u'(C): name to address (such as A RR) update successfully completed', 0x0001),
        (u'(A): Server is controlling A RR on behalf of the client', 0x0002),
        (u'(D): address to name (such as PTR RR) update successfully completed (Done)', 0x0004),
        (u'(P): Server is controlling PTR RR on behalf of the client', 0x0008),
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
