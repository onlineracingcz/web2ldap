# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for DNS attributes

https://drift.uninett.no/nett/ip-nett/dnsattributes.schema
"""

import re
import hashlib

import ldap0
import ldap0.schema.models
from ldap0.dn import DNObj
from ldap0.res import SearchResultEntry

import web2ldapcnf

import web2ldap.app.searchform
from web2ldap.app.schema.syntaxes import \
    IA5String, \
    DNSDomain, \
    DynamicValueSelectList, \
    IPv4HostAddress, \
    IPv6HostAddress, \
    syntax_registry


class AssociatedDomain(DNSDomain):
    oid: str = 'AssociatedDomain-oid'
    desc: str = 'Associated DNS domain name (see RFC 4524, section 2.1.)'

    def _validate(self, attrValue: bytes) -> bool:
        result = DNSDomain._validate(self, attrValue)
        ocs = self._entry.object_class_oid_set()
        if 'dNSDomain' in ocs or 'dNSDomain2' in ocs:
            try:
                dc = self._entry['dc'][0]
            except KeyError:
                pass
            else:
                result = result and (attrValue == dc or attrValue.startswith(dc+b'.'))
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
        d = dict([
            (
                DNObj.from_str(r.dn_s),
                r.entry_s['associatedDomain'][0]
            )
            for r in ldap_result
            if isinstance(r, SearchResultEntry)
        ])
        if not d:
            return None
        return d[self.dn.match(d.keys())] or None
        # end of _parent_domain()

    def sanitize(self, attrValue: bytes) -> bytes:
        attrValue = DNSDomain.sanitize(self, attrValue)
        if not attrValue:
            parent_domain = (self._parent_domain() or u'').encode(self._app.ls.charset)
            try:
                dc_value = self._entry['dc'][0]
            except (KeyError, IndexError):
                pass
            else:
                attrValue = DNSDomain.sanitize(self, b'.'.join((dc_value, parent_domain)))
        return attrValue

    def formValue(self) -> str:
        form_value = DNSDomain.formValue(self)
        parent_domain = self._parent_domain() or u''
        if not form_value:
            try:
                dc_value = self._entry['dc'][0].decode(self._app.ls.charset)
            except (KeyError, IndexError):
                pass
            else:
                form_value = u'.'.join((dc_value, parent_domain))
        return form_value

    def display(self, valueindex=0, commandbutton=False) -> str:
        r = [DNSDomain.display(self, valueindex, commandbutton)]
        if commandbutton:
            av = self.av_u.lower()
            r.append(self._app.anchor(
                'search', 'Ref. RRs',
                (
                    ('dn', self._app.naming_context),
                    ('searchform_mode', u'adv'),
                    ('search_mode', u'(|%s)'),
                    ('search_attr', u'cNAMERecord'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', av),
                    ('search_attr', u'nSRecord'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', av),
                    ('search_attr', u'pTRRecord'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', av),
                ),
                title=u'Search referencing DNS RR entries',
            ))
            parent_domain = u'.'.join(av.strip().split(u'.')[1:])
            if parent_domain and 'sOARecord' not in self._entry:
                r.append(self._app.anchor(
                    'search', 'SOA RR',
                    (
                        ('dn', self._app.naming_context),
                        ('searchform_mode', u'adv'),
                        ('search_attr', u'sOARecord'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS),
                        ('search_string', u''),
                        ('search_attr', u'associatedDomain'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                        ('search_string', parent_domain),
                    ),
                    title=u'Search SOA RR entry of parent domain',
                ))
            if av.endswith(u'.in-addr.arpa'):
                try:
                    ip_addr_u = u'.'.join(
                        map(str, reversed(list(map(int, av.split(u'.')[0:4]))))
                    )
                except ValueError:
                    pass
                else:
                    r.append(self._app.anchor(
                        'search', 'A RRs',
                        (
                            ('dn', self._app.naming_context),
                            ('searchform_mode', u'adv'),
                            ('search_attr', u'aRecord'),
                            ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                            ('search_string', ip_addr_u),
                        ),
                        title=u'Search referencing DNS A RR entries',
                    ))
                    if '1.3.6.1.1.1.1.19' in self._schema.sed[ldap0.schema.models.AttributeType]:
                        r.append(self._app.anchor(
                            'search', 'IP host(s)',
                            (
                                ('dn', self._app.naming_context),
                                ('searchform_mode', u'adv'),
                                ('search_attr', u'ipHostNumber'),
                                ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                                ('search_string', ip_addr_u),
                            ),
                            title=u'Search IP host(s) for this A address',
                        ))
                    if '2.16.840.1.113719.1.203.4.3' in self._schema.sed[ldap0.schema.models.AttributeType]:
                        r.append(self._app.anchor(
                            'search', 'DHCP host(s)',
                            (
                                ('dn', self._app.naming_context),
                                ('searchform_mode', u'adv'),
                                ('search_attr', u'dhcpStatements'),
                                ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                                ('search_string', u'fixed-address %s' % ip_addr_u),
                            ),
                            title=u'Search DHCP host(s) for this A address',
                        ))
        return web2ldapcnf.command_link_separator.join(r)

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

    def __init__(self, app, dn: str, schema, attrType: str, attrValue: bytes, entry=None):
        DynamicValueSelectList.__init__(self, app, dn, schema, attrType, attrValue, entry)

    def display(self, valueindex=0, commandbutton=False) -> str:
        return DynamicValueSelectList.display(self, valueindex, commandbutton)

syntax_registry.reg_at(
    ResourceRecord.oid, [
        '1.3.6.1.4.1.2428.20.1.12',   # pTRRecord
        '0.9.2342.19200300.100.1.29', # nSRecord
    ]
)


class CNAMERecord(ResourceRecord):
    oid: str = 'CNAMERecord-oid'
    desc: str = 'A resource record used as alias (CNAME)'
    maxValues = 1 # It's illegal to have multiple CNAME RR values

syntax_registry.reg_at(
    CNAMERecord.oid, [
        '0.9.2342.19200300.100.1.31', # cNAMERecord
    ]
)


class MXRecord(ResourceRecord):
    oid: str = 'MXRecord-oid'
    desc: str = 'A resource record pointing to a mail exchanger (MX)'
    reObj = re.compile(r'^[0-9]+[ ]+[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*$')

    def _search_ref(self, attrValue: str):
        try:
            _, hostname = attrValue.split(' ', 1)
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

    def display(self, valueindex=0, commandbutton=False) -> str:
        r = [IPv4HostAddress.display(self, valueindex, commandbutton)]
        if commandbutton:
            ip_addr = self.addr_class(self.av_u)
            r.append(self._app.anchor(
                'search', 'PTR RR',
                (
                    ('dn', self._app.naming_context),
                    ('searchform_mode', u'adv'),
                    ('search_attr', u'associatedDomain'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', ip_addr.reverse_pointer),
                ),
                title=u'Search PTR RR for this A address',
            ))
            if '1.3.6.1.1.1.1.19' in self._schema.sed[ldap0.schema.models.AttributeType]:
                r.append(self._app.anchor(
                    'search', 'IP host(s)',
                    (
                        ('dn', self._app.naming_context),
                        ('searchform_mode', u'adv'),
                        ('search_attr', u'ipHostNumber'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                        ('search_string', str(ip_addr)),
                    ),
                    title=u'Search IP host(s) for this A address',
                ))
            if '2.16.840.1.113719.1.203.4.3' in self._schema.sed[ldap0.schema.models.AttributeType]:
                r.append(self._app.anchor(
                    'search', 'DHCP host(s)',
                    (
                        ('dn', self._app.naming_context),
                        ('searchform_mode', u'adv'),
                        ('search_attr', u'dhcpStatements'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                        ('search_string', u'fixed-address %s' % str(ip_addr)),
                    ),
                    title=u'Search DHCP host(s) for this A address',
                ))
        return web2ldapcnf.command_link_separator.join(r)

syntax_registry.reg_at(
    ARecord.oid, [
        '0.9.2342.19200300.100.1.26', # aRecord
    ]
)


class AAAARecord(IPv6HostAddress):
    oid: str = 'AAAARecord-oid'
    desc: str = 'AAAA resource record pointing to IPv6 address'

    def display(self, valueindex=0, commandbutton=False) -> str:
        r = [IPv6HostAddress.display(self, valueindex, commandbutton)]
        if commandbutton:
            ip_addr = self.addr_class(self.av_u)
            try:
                ip_addr.reverse_dns
            except AttributeError:
                pass
            else:
                r.append(self._app.anchor(
                    'search', 'PTR RR',
                    (
                        ('dn', self._app.naming_context),
                        ('searchform_mode', u'adv'),
                        ('search_attr', u'associatedDomain'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                        ('search_string', self._app.ls.uc_decode(ip_addr.reverse_dns)[0][:-1]),
                    ),
                    title=u'Search PTR RR for this AAAA address',
                ))
        return web2ldapcnf.command_link_separator.join(r)

syntax_registry.reg_at(
    AAAARecord.oid, [
        '1.3.6.1.4.1.2428.20.1.28', # aAAARecord
    ]
)


class SSHFPRecord(IA5String):
    oid: str = 'SSHFPRecord-oid'
    desc: str = 'A resource record with SSH fingerprint (SSHFP)'
    reObj = re.compile('^[0-4]? [0-2]? [0-9a-fA-F]+$')
    key_algo_dict = {
        '0': 'reserved',
        '1': 'RSA',
        '2': 'DSA',
        '3': 'ECDSA',
        '4': 'ED25519',
    }
    fp_algo_dict = {
        '0': 'reserved',
        '1': 'SHA-1',
        '2': 'SHA-256',
    }
    fp_algo_len = {
        '1': 2*hashlib.sha1().digest_size,
        '2': 2*hashlib.sha256().digest_size,
    }

    def sanitize(self, attrValue: bytes) -> bytes:
        if not attrValue:
            return attrValue
        try:
            key_algo, fp_algo, fp_value = [
                i.encode('ascii')
                for i in filter(None, map(str.strip, attrValue.lower().split(' ')))
            ]
        except ValueError:
            return attrValue
        return ' '.join((key_algo, fp_algo, fp_value))

    def _validate(self, attrValue: bytes) -> bool:
        try:
            key_algo, fp_algo, fp_value = tuple(filter(None, map(str.strip, attrValue.split(' '))))
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

    def display(self, valueindex=0, commandbutton=False) -> str:
        display_value = IA5String.display(self, valueindex, commandbutton)
        try:
            key_algo, fp_algo, _ = tuple(filter(None, map(str.strip, self._av.split(' '))))
        except ValueError:
            r = display_value
        else:
            try:
                key_algo_name = self.key_algo_dict[key_algo]
            except KeyError:
                key_algo_name = '?'
            try:
                fp_algo_name = self.fp_algo_dict[fp_algo]
            except KeyError:
                fp_algo_name = '?'
            r = 'key_algo={key_algo_name} fp_algo={fp_algo_name}:<br><code>{display_value}</code>'.format(
                key_algo_name=key_algo_name,
                fp_algo_name=fp_algo_name,
                display_value=display_value,
            )
        return r

syntax_registry.reg_at(
    SSHFPRecord.oid, [
        '1.3.6.1.4.1.2428.20.1.44', # sSHFPRecord
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
