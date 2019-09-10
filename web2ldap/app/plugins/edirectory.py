# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for Novell eDirectory/DirXML
(see draft-sermersheim-nds-ldap-schema)
"""

import uuid
from binascii import hexlify

import ldap0.filter

import web2ldapcnf

from web2ldap.app.schema.syntaxes import \
    Binary, \
    BitArrayInteger, \
    DirectoryString, \
    DynamicDNSelectList, \
    Integer, \
    MultilineText, \
    NullTerminatedDirectoryString, \
    OctetString, \
    OID, \
    PostalAddress, \
    PreformattedMultilineText, \
    PrintableString, \
    SelectList, \
    XmlValue, \
    syntax_registry
from web2ldap.app.plugins.x509 import Certificate, CertificateList


# FIX ME! Disabled this because of double OID which eDirectory is famous for. :-(
#class CaseIgnoreList(PostalAddress):
#  oid = '2.16.840.1.113719.1.1.5.1.6'
#  desc = 'Case Ignore List'


class TaggedData(OctetString):
    oid = '2.16.840.1.113719.1.1.5.1.12'
    desc = 'Tagged Data'


class OctetList(OctetString):
    oid = '2.16.840.1.113719.1.1.5.1.13'
    desc = 'Octet List'


class TaggedString(DirectoryString):
    oid = '2.16.840.1.113719.1.1.5.1.14'
    desc = 'Tagged String'


class DollarSeparatedMultipleLines(PostalAddress):
    oid = '2.16.840.1.113719.1.1.5.1.6'
    desc = '$-separated string'


class OctetStringGUID(OctetString):
    oid = 'OctetStringGUID-oid'
    desc = 'GUID of eDirectory entries represented as 16 byte octet string'

    def _validate(self, attrValue: bytes) -> bool:
        return len(attrValue) == 16

    @staticmethod
    def _guid2association(s):
        """
        format association like Edir2Edir driver: {60445C8E-D8DB-d801-808C-0008028B1EF9}
        """
        s1 = hexlify(s).upper()
        return '{%s}' % (
            '-'.join((
                ''.join((s1[6:8], s1[4:6], s1[2:4], s1[0:2])),
                ''.join((s1[10:12], s1[8:10])),
                ''.join((s1[14:16].lower(), s1[12:14].lower())),
                s1[16:20],
                s1[20:32],
            ))
        )

    @staticmethod
    def _guid2assoc(s):
        """
        format association like entitlement driver: {8E5C4460-DBD8-01D8-808C-0008028B1EF9}
        """
        s1 = hexlify(s).upper()
        return '{%s}' % ('-'.join((
            s1[0:8],
            s1[8:12],
            s1[12:16],
            s1[16:20],
            s1[20:32],
        )))

    @staticmethod
    def _guid2assoc_c1(s):
        """
        format association like C1 and iManager: 60445C8E-D8DB-d801-808C-0008028B1EF9
        """
        s1 = hexlify(s).upper()
        return ''.join((
            s1[6:8],
            s1[4:6],
            s1[2:4],
            s1[0:2],
            s1[10:12],
            s1[8:10],
            s1[14:16],
            s1[12:14],
            s1[16:32],
        ))

    def display(self, valueindex=0, commandbutton=False):
        if self._at == u'GUID':
            # GUID of an entry is displayed in several variants
            return """
            <table summary="GUID representation variants">
              <tr><td>Octet String</td><td>%s</td></tr>
              <tr><td>UUID</td><td>%s</td></tr>
              <tr><td>Edir2Edir driver</td><td>%s</td></tr>
              <tr><td>entitlement driver</td><td>%s</td></tr>
              <tr><td>C1/iManager assoc.</td><td>%s</td></tr>
            </table>
            """ % (
                OctetString.display(self, valueindex, commandbutton),
                str(uuid.UUID(bytes=self._av)),
                self._guid2association(self._av),
                self._guid2assoc(self._av),
                self._guid2assoc_c1(self._av),
            )
        # GUID of an referenced entry is just displayed as in Console 1 / iManager
        # with a link for searching the entry
        return web2ldapcnf.command_link_separator.join((
            self._guid2assoc_c1(self._av),
            self._app.anchor(
                'searchform', '&raquo;',
                [
                    ('dn', self._dn),
                    ('filterstr', ldap0.filter.escape_str(self._av)),
                    ('searchform_mode', u'exp'),
                ],
                title=u'Search entry with this GUID',
            )
        ))


syntax_registry.reg_at(
    OctetStringGUID.oid, [
        '2.16.840.1.113719.1.1.4.1.501',   # GUID
        '2.16.840.1.113719.1.280.4.931.1', # ASAM-inputGUID
        '2.16.840.1.113719.1.14.4.1.50',   # DirXML-ServerGUID
        '2.16.840.1.113719.1.1.4.1.502',   # otherGUID
    ]
)


class IndexDefinition(DollarSeparatedMultipleLines):
    """
    Version: 0 (reserved for future use)
    Name: description of index
    State: 0-suspend, 1-bringing, 2-online, 3-pending
    Matching Rule: 0-value, 1-presence, 2-substring
    Type: 0-user defined
    Value State: 1-added from server
    NDS Attribute Name
    """
    oid = 'IndexDefinition-oid'
    desc = 'Index Definition'

    def display(self, valueindex=0, commandbutton=False):
        try:
            (
                version,
                index_name,
                state,
                matching_rule,
                index_type,
                value_state,
                nds_attribute_name,
            ) = self._av.split('$')
            version = int(version)
            index_name = self._app.ls.uc_decode(index_name)[0]
            state = int(state)
            matching_rule = int(matching_rule)
            index_type = int(index_type)
            value_state = int(value_state)
            nds_attribute_name = self._app.ls.uc_decode(nds_attribute_name)[0]
        except (ValueError, UnicodeDecodeError):
            return DollarSeparatedMultipleLines.display(self, valueindex, commandbutton)
        return """
          <table>
            <tr><td>Version:</td><td>%s</td></tr>
            <tr><td>Name:</td><td>%s</td></tr>
            <tr><td>State:</td><td>%s</td></tr>
            <tr><td>Matching Rule:</td><td>%s</td></tr>
            <tr><td>Type:</td><td>%s</td></tr>
            <tr><td>Value State:</td><td>%s</td></tr>
            <tr><td>NDS Attribute Name</td><td>%s</td></tr>
          </table>""" % (
              version,
              index_name.encode(self._app.form.accept_charset),
              {0:'suspend', 1:'bringing', 2:'online', 3:'pending'}.get(state, str(state)),
              {0:'value', 1:'presence', 2:'substring'}.get(matching_rule, str(matching_rule)),
              {0:'user defined'}.get(index_type, str(index_type)),
              {1:'added from server'}.get(value_state, str(value_state)),
              nds_attribute_name.encode(self._app.form.accept_charset),
          )

syntax_registry.reg_at(
    IndexDefinition.oid, [
        '2.16.840.1.113719.1.1.4.1.512', # indexDefinition
    ]
)


class TaggedNameAndString(DirectoryString, OctetString):
    oid = '2.16.840.1.113719.1.1.5.1.15'
    desc = 'Tagged Name And String'

    def display(self, valueindex=0, commandbutton=False):
        try:
            ind2 = self._av.rindex('#')
            ind1 = self._av.rindex('#', 0, ind2-1)
        except ValueError:
            return DirectoryString.display(self, valueindex, commandbutton)
        dn = self._app.ls.uc_decode(self._av[0:ind1])[0]
        number = self._av[ind1+1:ind2]
        dstring = self._av[ind2+1:]
        try:
            dstring.decode('utf8')
        except UnicodeError:
            dstring_disp = OctetString.display(self, valueindex, commandbutton)
        else:
            dstring_disp = DirectoryString.display(self, valueindex, commandbutton)
        return (
            '<dl>'
            '<dt>name:</dt><dd>%s</dd>'
            '<dt>number:</dt><dd>%s</dd>'
            '<dt>dstring:</dt><dd><code>%s</code></dd>'
            '</dl>'
        ) % (
            self._app.display_dn(dn, commandbutton=commandbutton),
            number,
            dstring_disp,
        )


class NDSReplicaPointer(OctetString):
    oid = '2.16.840.1.113719.1.1.5.1.16'
    desc = 'NDS Replica Pointer'


class NDSACL(DirectoryString):
    oid = '2.16.840.1.113719.1.1.5.1.17'
    desc = 'NDS ACL'


class NDSTimestamp(PrintableString):
    oid = '2.16.840.1.113719.1.1.5.1.19'
    desc = 'NDS Timestamp'


class Counter(Integer):
    oid = '2.16.840.1.113719.1.1.5.1.22'
    desc = 'Counter (NDS)'


class TaggedName(DirectoryString):
    oid = '2.16.840.1.113719.1.1.5.1.23'
    desc = 'Tagged Name'


class TypedName(DirectoryString):
    oid = '2.16.840.1.113719.1.1.5.1.25'
    desc = 'Typed Name'


class EntryFlags(BitArrayInteger):
    """
    See
    """
    oid = 'EntryFlags-oid'
    flag_desc_table = (
        (u'DS_ALIAS_ENTRY', 0x0001),
        (u'DS_PARTITION_ROOT', 0x0002),
        (u'DS_CONTAINER_ENTRY', 0x0004),
        (u'DS_CONTAINER_ALIAS', 0x0008),
        (u'DS_MATCHES_LIST_FILTER', 0x0010),
        (u'DS_REFERENCE_ENTRY', 0x0020),
        (u'DS_40X_REFERENCE_ENTRY', 0x0040),
        (u'DS_BACKLINKED', 0x0080),
        (u'DS_NEW_ENTRY', 0x0100),
        (u'DS_TEMPORARY_REFERENCE', 0x0200),
        (u'DS_AUDITED', 0x0400),
        (u'DS_ENTRY_NOT_PRESENT', 0x0800),
        (u'DS_ENTRY_VERIFY_CTS', 0x1000),
        (u'DS_ENTRY_DAMAGED', 0x2000),
    )

syntax_registry.reg_at(
    EntryFlags.oid, [
        '2.16.840.1.113719.1.27.4.48', # entryFlags
    ]
)


class NspmConfigurationOptions(BitArrayInteger):
    """
    See http://ldapwiki.willeke.com/wiki/UniversalPasswordSecretBits
    """
    oid = 'NspmConfigurationOptions-oid'
    flag_desc_table = (
        (u'On set password request the NDS password hash will be removed by SPM', 0x01),
        (u'On set password request the NDS password hash will not be set by SPM', 0x02),
        (u'On set password request the Simple password will not be set by SPM', 0x04),
        (u'Reserved 0x08', 0x08),
        (u'Allow password retrieval by self (User)', 0x10),
        (u'Allow password retrieval by admin', 0x20),
        (u'Allow password retrieval by password agents (trusted app)', 0x40),
        (u'Reserved 0x80', 0x80),
        (u'Password enabled', 0x100),
        (u'Advanced password policy enabled', 0x200),
    )

syntax_registry.reg_at(
    NspmConfigurationOptions.oid, [
        '2.16.840.1.113719.1.39.43.4.100', # nspmConfigurationOptions
    ]
)


class SnmpTrapDescription(MultilineText):
    oid = 'SnmpTrapDescription-oid'
    desc = 'SNMP Trap Description'
    lineSep = b'\x00'
    cols = 30

syntax_registry.reg_at(
    SnmpTrapDescription.oid, [
        '2.16.840.1.113719.1.6.4.4', # snmpTrapDescription
    ]
)


class SASVendorSupport(PreformattedMultilineText):
    oid = 'SASVendorSupport-oid'
    desc = 'SAS Vendor Support'
    cols = 50

syntax_registry.reg_at(
    SASVendorSupport.oid, [
        '2.16.840.1.113719.1.39.42.1.0.12', # sASVendorSupport
    ]
)


class NspmPasswordPolicyDN(DynamicDNSelectList):
    oid = 'NspmPasswordPolicyDN-oid'
    desc = 'DN of the nspmPasswordPolicy entry'
    ldap_url = 'ldap:///cn=Password Policies,cn=Security?cn?sub?(objectClass=nspmPasswordPolicy)'

syntax_registry.reg_at(
    NspmPasswordPolicyDN.oid, [
        '2.16.840.1.113719.1.39.43.4.6', # nspmPasswordPolicyDN
    ]
)

class DirXMLDriverStartOption(SelectList):
    oid = 'DirXML-DriverStartOption-oid'
    desc = 'Start option for a DirXML driver'
    attr_value_dict = {
        u'0': u'disabled',
        u'1': u'manual',
        u'2': u'auto',
    }

syntax_registry.reg_at(
    DirXMLDriverStartOption.oid, [
        '2.16.840.1.113719.1.14.4.1.13', # DirXML-DriverStartOption
    ]
)


class DirXMLState(SelectList):
    oid = 'DirXML-State-DriverStartOption-oid'
    desc = 'Current state of a DirXML driver'
    attr_value_dict = {
        u'0': u'stopped',
        u'1': u'starting',
        u'2': u'running',
        u'3': u'stopping',
    }

syntax_registry.reg_at(
    DirXMLState.oid, [
        '2.16.840.1.113719.1.14.4.1.14', # DirXML-State
    ]
)

# Workarounds for eDirectory

syntax_registry.reg_at(
    Certificate.oid, [
        '2.16.840.1.113719.1.48.4.1.3', # nDSPKIPublicKeyCertificate
    ]
)

syntax_registry.reg_at(
    CertificateList.oid, [
        # certificateRevocationList in Novell eDirectory
        '2.16.840.1.113719.1.48.4.1.34',
    ]
)

syntax_registry.reg_at(
    OID.oid,
    [
        'supportedGroupingTypes',
    ]
)

syntax_registry.reg_at(
    NullTerminatedDirectoryString.oid, [
        '2.16.840.1.113719.1.27.4.42', # extensionInfo
    ]
)

syntax_registry.reg_at(
    Binary.oid, [
        '2.16.840.1.113719.1.48.4.1.4',  # nDSPKICertificateChain
        '2.16.840.1.113719.1.48.4.1.2',  # nDSPKIPrivateKey
        '2.16.840.1.113719.1.48.4.1.1',  # nDSPKIPublicKey
        '2.16.840.1.113719.1.14.4.1.42', # DirXML-Act3
        '2.16.840.1.113719.1.200.4.1',   # bhConfig
        '2.16.840.1.113719.1.200.4.2',   # bhConfigRW
        '2.16.840.1.113719.1.200.4.3',   # bhConfigSecretStore
        '2.16.840.1.113719.1.1.4.1.84',  # publicKey
    ]
)

syntax_registry.reg_at(
    XmlValue.oid, [
        '2.16.840.1.113719.1.1.4.1.295', # emboxConfig
        '2.16.840.1.113719.1.14.4.1.3',  # XmlData
        '2.16.840.1.113719.1.14.4.1.8',  # DirXML-ShimConfigInfo
        '2.16.840.1.113719.1.14.4.1.11', # DirXML-DriverFilter
        '2.16.840.1.113719.1.14.4.1.24', # DirXML-DriverCacheLimit
        '2.16.840.1.113719.1.14.4.1.29', # DirXML-ApplicationSchema
        '2.16.840.1.113719.1.14.4.1.54', # DirXML-ConfigValues
        '2.16.840.1.113719.1.14.4.1.56', # DirXML-ConfigManifest
        '2.16.840.1.113719.1.14.4.1.58', # DirXML-EngineControlValues
        '2.16.840.1.113719.1.14.4.1.82', # DirXML-PersistentData
        '2.16.840.1.113719.1.39.44.4.1', # nsimRequiredQuestions
        '2.16.840.1.113719.1.39.44.4.2', # nsimRandomQuestions
        '2.16.840.1.113719.1.39.44.4.7', # nsimForgottenAction
        '2.16.840.1.113719.1.347.4.1',   # NAuditConfiguration
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
