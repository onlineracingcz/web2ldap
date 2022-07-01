# -*- coding: ascii -*-
"""
web2ldap plugin classes for dNSDomain/dNSDomain2 schema

https://doc.powerdns.com/authoritative/backends/ldap.html#schemas
"""

import re
import hashlib

import ldap0
import ldap0.schema.models
from ldap0.dn import DNObj
from ldap0.res import SearchResultEntry
from ldap0.schema.models import AttributeType

import web2ldapcnf

from ..searchform import (
    SEARCH_OPT_ATTR_EXISTS,
    SEARCH_OPT_IS_EQUAL,
)
from ..schema.syntaxes import (
    IA5String,
    DNSDomain,
    DynamicValueSelectList,
    IPv4HostAddress,
    IPv6HostAddress,
    syntax_registry,
)


class AssociatedDomain(DNSDomain):
    oid: str = 'AssociatedDomain-oid'
    desc: str = 'Associated DNS domain name (see RFC 4524, section 2.1.)'

    def _validate(self, attr_value: bytes) -> bool:
        result = DNSDomain._validate(self, attr_value)
        ocs = self._entry.object_class_oid_set()
        if 'dNSDomain' in ocs or 'dNSDomain2' in ocs:
            try:
                dc_aval = self._entry['dc'][0]
            except KeyError:
                pass
            else:
                result = result and (attr_value == dc_aval or attr_value.startswith(dc_aval+b'.'))
        return result

    def _parent_domain(self):
        """
        Return the best matching domain entry for the given DN
        """
        if not self._dn:
            return None
        ldap_result = self._app.ls.l.search_s(
            str(self._app.ls.get_search_root(self._dn)),
            ldap0.SCOPE_SUBTREE,
            '(&(objectClass=dNSDomain)(|(sOARecord=*)(nSRecord=*))(associatedDomain=*))',
            attrlist=['associatedDomain'],
        )
        if not ldap_result:
            return None
        dn2domain = {
            DNObj.from_str(res.dn_s): res.entry_s['associatedDomain'][0]
            for res in ldap_result
            if isinstance(res, SearchResultEntry)
        }
        if not dn2domain:
            return None
        matched_dn = self.dn.match(dn2domain.keys())
        if not matched_dn:
            return None
        return dn2domain.get(matched_dn, None)
        # end of _parent_domain()

    def sanitize(self, attr_value: bytes) -> bytes:
        attr_value = DNSDomain.sanitize(self, attr_value)
        if not attr_value:
            parent_domain = (self._parent_domain() or '').encode(self._app.ls.charset)
            try:
                dc_value = self._entry['dc'][0]
            except (KeyError, IndexError):
                pass
            else:
                attr_value = DNSDomain.sanitize(self, b'.'.join((dc_value, parent_domain)))
        return attr_value

    def form_value(self) -> str:
        fval = DNSDomain.form_value(self)
        parent_domain = self._parent_domain() or ''
        if not fval:
            try:
                dc_value = self._entry['dc'][0].decode(self._app.ls.charset)
            except (KeyError, IndexError):
                pass
            else:
                fval = '.'.join((dc_value, parent_domain))
        return fval

    def display(self, vidx, links) -> str:
        res = [DNSDomain.display(self, vidx, links)]
        if links:
            aval = self.av_u.lower()
            res.append(self._app.anchor(
                'search', 'Ref. RRs',
                (
                    ('dn', str(self._app.naming_context)),
                    ('searchform_mode', 'adv'),
                    ('search_mode', '(|%s)'),
                    ('search_attr', 'cNAMERecord'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', aval),
                    ('search_attr', 'nSRecord'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', aval),
                    ('search_attr', 'pTRRecord'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', aval),
                ),
                title='Search referencing DNS RR entries',
            ))
            parent_domain = '.'.join(aval.strip().split('.')[1:])
            if parent_domain and 'sOARecord' not in self._entry:
                res.append(self._app.anchor(
                    'search', 'SOA RR',
                    (
                        ('dn', str(self._app.naming_context)),
                        ('searchform_mode', 'adv'),
                        ('search_attr', 'sOARecord'),
                        ('search_option', SEARCH_OPT_ATTR_EXISTS),
                        ('search_string', ''),
                        ('search_attr', 'associatedDomain'),
                        ('search_option', SEARCH_OPT_IS_EQUAL),
                        ('search_string', parent_domain),
                    ),
                    title='Search SOA RR entry of parent domain',
                ))
            if aval.endswith('.in-addr.arpa'):
                try:
                    ip_addr_u = '.'.join(
                        map(str, reversed(list(map(int, aval.split('.')[0:4]))))
                    )
                except ValueError:
                    pass
                else:
                    res.append(self._app.anchor(
                        'search', 'A RRs',
                        (
                            ('dn', str(self._app.naming_context)),
                            ('searchform_mode', 'adv'),
                            ('search_attr', 'aRecord'),
                            ('search_option', SEARCH_OPT_IS_EQUAL),
                            ('search_string', ip_addr_u),
                        ),
                        title='Search referencing DNS A RR entries',
                    ))
                    if '1.3.6.1.1.1.1.19' in self._schema.sed[AttributeType]:
                        res.append(self._app.anchor(
                            'search', 'IP host(s)',
                            (
                                ('dn', str(self._app.naming_context)),
                                ('searchform_mode', 'adv'),
                                ('search_attr', 'ipHostNumber'),
                                ('search_option', SEARCH_OPT_IS_EQUAL),
                                ('search_string', ip_addr_u),
                            ),
                            title='Search IP host(s) for this A address',
                        ))
                    if '2.16.840.1.113719.1.203.4.3' in self._schema.sed[AttributeType]:
                        res.append(self._app.anchor(
                            'search', 'DHCP host(s)',
                            (
                                ('dn', str(self._app.naming_context)),
                                ('searchform_mode', 'adv'),
                                ('search_attr', 'dhcpStatements'),
                                ('search_option', SEARCH_OPT_IS_EQUAL),
                                ('search_string', 'fixed-address %s' % ip_addr_u),
                            ),
                            title='Search DHCP host(s) for this A address',
                        ))
        return web2ldapcnf.command_link_separator.join(res)

syntax_registry.reg_at(
    AssociatedDomain.oid, [
        '0.9.2342.19200300.100.1.37', # associatedDomain
    ],
    #structural_oc_oids=[
    #    '0.9.2342.19200300.100.4.15', # dNSDomain
    #    '1.3.6.1.4.1.2428.20.2',      # dNSDomain2
    #],
)


class ResourceRecord(DNSDomain, DynamicValueSelectList):
    oid: str = 'ResourceRecord-oid'
    desc: str = 'A resource record pointing to another DNS RR'
    ldap_url = 'ldap:///_?associatedDomain,associatedDomain?sub?(objectClass=domainRelatedObject)'

    def __init__(self, app, dn: str, schema, attrType: str, attr_value: bytes, entry=None):
        DynamicValueSelectList.__init__(self, app, dn, schema, attrType, attr_value, entry)

    def display(self, vidx, links) -> str:
        return DynamicValueSelectList.display(self, vidx, links)

syntax_registry.reg_at(
    ResourceRecord.oid, [
        '1.3.6.1.4.1.2428.20.1.12',   # pTRRecord
        '0.9.2342.19200300.100.1.29', # nSRecord
    ]
)


class CNAMERecord(ResourceRecord):
    oid: str = 'CNAMERecord-oid'
    desc: str = 'A resource record used as alias (CNAME)'
    max_values = 1 # It's illegal to have multiple CNAME RR values

syntax_registry.reg_at(
    CNAMERecord.oid, [
        '0.9.2342.19200300.100.1.31', # cNAMERecord
    ]
)


class MXRecord(ResourceRecord):
    oid: str = 'MXRecord-oid'
    desc: str = 'A resource record pointing to a mail exchanger (MX)'
    pattern = re.compile(r'^[0-9]+[ ]+[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*$')

    def _search_ref(self, attr_value: str):
        try:
            _, hostname = attr_value.split(' ', 1)
        except ValueError:
            return None
        return ResourceRecord._search_ref(self, hostname.strip())

syntax_registry.reg_at(
    MXRecord.oid, [
        '0.9.2342.19200300.100.1.28', # mXRecord
    ]
)


class ARecord(IPv4HostAddress):
    oid: str = 'ARecord-oid'
    desc: str = 'A resource record pointing to IPv4 address'

    def display(self, vidx, links) -> str:
        res = [IPv4HostAddress.display(self, vidx, links)]
        if links:
            ip_addr = self.addr_class(self.av_u)
            res.append(self._app.anchor(
                'search', 'PTR RR',
                (
                    ('dn', str(self._app.naming_context)),
                    ('searchform_mode', 'adv'),
                    ('search_attr', 'associatedDomain'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', ip_addr.reverse_pointer),
                ),
                title='Search PTR RR for this A address',
            ))
            if '1.3.6.1.1.1.1.19' in self._schema.sed[AttributeType]:
                res.append(self._app.anchor(
                    'search', 'IP host(s)',
                    (
                        ('dn', str(self._app.naming_context)),
                        ('searchform_mode', 'adv'),
                        ('search_attr', 'ipHostNumber'),
                        ('search_option', SEARCH_OPT_IS_EQUAL),
                        ('search_string', str(ip_addr)),
                    ),
                    title='Search IP host(s) for this A address',
                ))
            if '2.16.840.1.113719.1.203.4.3' in self._schema.sed[AttributeType]:
                res.append(self._app.anchor(
                    'search', 'DHCP host(s)',
                    (
                        ('dn', str(self._app.naming_context)),
                        ('searchform_mode', 'adv'),
                        ('search_attr', 'dhcpStatements'),
                        ('search_option', SEARCH_OPT_IS_EQUAL),
                        ('search_string', 'fixed-address %s' % str(ip_addr)),
                    ),
                    title='Search DHCP host(s) for this A address',
                ))
        return web2ldapcnf.command_link_separator.join(res)

syntax_registry.reg_at(
    ARecord.oid, [
        '0.9.2342.19200300.100.1.26', # aRecord
    ]
)


class AAAARecord(IPv6HostAddress):
    oid: str = 'AAAARecord-oid'
    desc: str = 'AAAA resource record pointing to IPv6 address'

    def display(self, vidx, links) -> str:
        res = [IPv6HostAddress.display(self, vidx, links)]
        if links:
            ip_addr = self.addr_class(self.av_u)
            res.append(self._app.anchor(
                'search', 'PTR RR',
                (
                    ('dn', str(self._app.naming_context)),
                    ('searchform_mode', 'adv'),
                    ('search_attr', 'associatedDomain'),
                    ('search_option', SEARCH_OPT_IS_EQUAL),
                    ('search_string', ip_addr.reverse_pointer),
                ),
                title='Search PTR RR for this AAAA address',
            ))
        return web2ldapcnf.command_link_separator.join(res)

syntax_registry.reg_at(
    AAAARecord.oid, [
        '1.3.6.1.4.1.2428.20.1.28', # aAAARecord
    ]
)


class SSHFPRecord(IA5String):
    oid: str = 'SSHFPRecord-oid'
    desc: str = 'A resource record with SSH fingerprint (SSHFP)'
    pattern = re.compile('^[0-4]? [0-2]? [0-9a-fA-F]+$')
    key_algo_dict = {
        b'0': 'reserved',
        b'1': 'RSA',
        b'2': 'DSA',
        b'3': 'ECDSA',
        b'4': 'ED25519',
    }
    fp_algo_dict = {
        b'0': 'reserved',
        b'1': 'SHA-1',
        b'2': 'SHA-256',
    }
    fp_algo_len = {
        b'1': 2*hashlib.sha1().digest_size,
        b'2': 2*hashlib.sha256().digest_size,
    }

    def sanitize(self, attr_value: bytes) -> bytes:
        if not attr_value:
            return attr_value
        try:
            key_algo, fp_algo, fp_value = filter(
                None,
                map(bytes.strip, attr_value.lower().split(b' '))
            )
        except ValueError:
            return attr_value
        return b' '.join((key_algo, fp_algo, fp_value))

    def _validate(self, attr_value: bytes) -> bool:
        try:
            key_algo, fp_algo, fp_value = tuple(
                filter(None, map(bytes.strip, attr_value.split(b' ')))
            )
        except ValueError:
            return False
        else:
            result = key_algo in self.key_algo_dict and fp_algo in self.fp_algo_dict
            try:
                fp_algo_len = self.fp_algo_len[fp_algo]
            except KeyError:
                pass
            else:
                result = result and len(fp_value) == fp_algo_len
        return result

    def display(self, vidx, links) -> str:
        display_value = IA5String.display(self, vidx, links)
        try:
            key_algo, fp_algo, _ = tuple(filter(None, map(bytes.strip, self._av.split(b' '))))
        except ValueError:
            res = display_value
        else:
            try:
                key_algo_name = self.key_algo_dict[key_algo]
            except KeyError:
                key_algo_name = '?'
            try:
                fp_algo_name = self.fp_algo_dict[fp_algo]
            except KeyError:
                fp_algo_name = '?'
            res = (
                'key_algo={key_algo_name} '
                'fp_algo={fp_algo_name}:<br>'
                '<code>{display_value}</code>'
            ).format(
                key_algo_name=key_algo_name,
                fp_algo_name=fp_algo_name,
                display_value=display_value,
            )
        return res

syntax_registry.reg_at(
    SSHFPRecord.oid, [
        '1.3.6.1.4.1.2428.20.1.44', # sSHFPRecord
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
