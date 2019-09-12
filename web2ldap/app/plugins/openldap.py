# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for OpenLDAP
"""

import re
import binascii

from pyasn1.codec.ber import decoder as ber_decoder

import ldap0.ldapurl
import ldap0.controls
import ldap0.openldap
from ldap0.controls import KNOWN_RESPONSE_CONTROLS

import web2ldapcnf

import web2ldap.app.gui
from web2ldap.app.schema.syntaxes import \
    AuthzDN, \
    BindDN, \
    DirectoryString, \
    DistinguishedName, \
    DynamicDNSelectList, \
    IA5String, \
    Integer, \
    LDAPUrl, \
    LDAPv3ResultCode, \
    MultilineText, \
    NotBefore, \
    OctetString, \
    SelectList, \
    Uri, \
    UUID, \
    syntax_registry
from web2ldap.ldaputil.oidreg import OID_REG
from web2ldap.app.plugins.quirks import NamingContexts

#---------------------------------------------------------------------------
# slapo-syncprov
#---------------------------------------------------------------------------

# see https://www.openldap.org/faq/data/cache/1145.html
class CSNSid(IA5String):
    oid = '1.3.6.1.4.1.4203.666.11.2.4'
    desc = 'change sequence number SID (CSN SID)'
    minLen = 3
    maxLen = 3
    reObj = re.compile('^[a-fA-F0-9]{3}$')


# see https://www.openldap.org/faq/data/cache/1145.html
class CSN(IA5String):
    oid = '1.3.6.1.4.1.4203.666.11.2.1'
    desc = 'change sequence number (CSN)'
    minLen = 40
    maxLen = 40
    reObj = re.compile('^[0-9]{14}\\.[0-9]{6}Z#[a-fA-F0-9]{6}#[a-fA-F0-9]{3}#[a-fA-F0-9]{6}$')

syntax_registry.reg_at(
    CSN.oid, [
        '1.3.6.1.4.1.4203.666.1.25', # contextCSN
        '1.3.6.1.4.1.4203.666.1.7',  # entryCSN
        '1.3.6.1.4.1.4203.666.1.13', # namingCSN
        # also register by name in case OpenLDAP was built without -DSLAP_SCHEMA_EXPOSE
        'contextCSN', 'entryCSN', 'namingCSN',
    ]
)

#---------------------------------------------------------------------------
# back-config
#---------------------------------------------------------------------------

syntax_registry.reg_at(
    NamingContexts.oid, [
        '1.3.6.1.4.1.4203.1.12.2.3.2.0.10', # olcSuffix
    ]
)


class OlcDbIndex(DirectoryString):
    oid = 'OlcDbIndex-oid'
    desc = 'OpenLDAP indexing directive'
    reObj = re.compile("^[a-zA-Z]?[a-zA-Z0-9.,;-]* (pres|eq|sub)(,(pres|eq|sub))*$")

syntax_registry.reg_at(
    OlcDbIndex.oid, [
        '1.3.6.1.4.1.4203.1.12.2.3.2.0.2', # olcDbIndex
    ]
)


class OlcSubordinate(SelectList):
    oid = 'OlcSubordinate-oid'
    desc = 'Indicates whether backend is subordinate'
    attr_value_dict = {
        u'': u'-/- (FALSE)',
        u'TRUE': u'TRUE',
        u'advertise': u'advertise',
    }

syntax_registry.reg_at(
    OlcSubordinate.oid, [
        '1.3.6.1.4.1.4203.1.12.2.3.2.0.15', # olcSubordinate
    ]
)


class OlcRootDN(BindDN):
    oid = 'OlcRootDN-oid'
    desc = 'The rootdn in the database'
    default_rdn = u'cn=admin'

    def formValue(self) -> str:
        form_value = BindDN.formValue(self)
        try:
            olc_suffix = self._entry['olcSuffix'][0].decode()
        except KeyError:
            pass
        else:
            if not form_value or not form_value.endswith(olc_suffix):
                try:
                    form_value = u','.join((self.default_rdn, olc_suffix))
                except KeyError:
                    pass
        return form_value

syntax_registry.reg_at(
    OlcRootDN.oid, [
        '1.3.6.1.4.1.4203.1.12.2.3.2.0.8', # olcRootDN
    ]
)


class OlcMultilineText(MultilineText):
    oid = 'OlcMultilineText-oid'
    desc = 'OpenLDAP multiline configuration strings'
    cols = 90
    minInputRows = 3

    def display(self, valueindex=0, commandbutton=False):
        return '<code>%s</code>' % MultilineText.display(self, valueindex, commandbutton)

syntax_registry.reg_at(
    OlcMultilineText.oid, [
        '1.3.6.1.4.1.4203.1.12.2.3.0.1', # olcAccess
        '1.3.6.1.4.1.4203.1.12.2.3.0.6', # olcAuthIDRewrite
        '1.3.6.1.4.1.4203.1.12.2.3.0.8', # olcAuthzRegexp
    ]
)

class OlcSyncRepl(OlcMultilineText, LDAPUrl):
    oid = 'OlcSyncRepl-oid'
    desc = 'OpenLDAP syncrepl directive'
    minInputRows = 5

    def __init__(self, app, dn, schema, attrType, attrValue, entry=None):
        OlcMultilineText.__init__(self, app, dn, schema, attrType, attrValue, entry)

    def display(self, valueindex=0, commandbutton=False):
        if not commandbutton or not self._av:
            return OlcMultilineText.display(self, valueindex, commandbutton)
        srd = ldap0.openldap.SyncReplDesc(self._av)
        return ' '.join((
            OlcMultilineText.display(self, valueindex, commandbutton),
            web2ldap.app.gui.ldap_url_anchor(
                self._app,
                srd.ldap_url(),
            ),
        ))

syntax_registry.reg_at(
    OlcSyncRepl.oid, [
        '1.3.6.1.4.1.4203.1.12.2.3.2.0.11', # olcSyncrepl
    ]
)


class OlmSeeAlso(DynamicDNSelectList):
    oid = 'OlmSeeAlso-oid'
    desc = 'DN of a overlase or database object in back-monitor'
    ldap_url = (
        'ldap:///_?monitoredInfo?sub?'
        '(&'
        '(objectClass=monitoredObject)'
        '(|'
        '(entryDN:dnOneLevelMatch:=cn=Databases,cn=Monitor)'
        '(entryDN:dnOneLevelMatch:=cn=Overlays,cn=Monitor)'
        '(entryDN:dnOneLevelMatch:=cn=Backends,cn=Monitor)'
        ')'
        ')'
    )

syntax_registry.reg_at(
    OlmSeeAlso.oid, [
        '2.5.4.34', # seeAlso
    ],
    structural_oc_oids=['1.3.6.1.4.1.4203.666.3.16.8'], # monitoredObject
)


class OlcPPolicyDefault(DynamicDNSelectList, DistinguishedName):
    oid = 'OlcPPolicyDefault-oid'
    desc = 'DN of a pwdPolicy object for uncustomized objects'
    ldap_url = 'ldap:///_?cn?sub?(objectClass=pwdPolicy)'

    def __init__(self, app, dn, schema, attrType, attrValue, entry=None):
        DynamicDNSelectList.__init__(self, app, dn, schema, attrType, attrValue, entry)

    def _validate(self, attrValue: bytes) -> bool:
        return DynamicDNSelectList._validate(self, attrValue)

syntax_registry.reg_at(
    OlcPPolicyDefault.oid, [
        '1.3.6.1.4.1.4203.1.12.2.3.3.12.1', # olcPPolicyDefault
    ]
)


class OlcMemberOfDangling(SelectList):
    oid = 'OlcMemberOfDangling-oid'
    desc = 'Behavior in case of dangling references during modification'
    attr_value_dict = {
        u'': u'-/-',
        u'ignore': u'ignore',
        u'drop': u'drop',
        u'error': u'error',
    }

syntax_registry.reg_at(
    OlcMemberOfDangling.oid, [
        '1.3.6.1.4.1.4203.1.12.2.3.3.18.1', # olcMemberOfDangling
    ]
)


#---------------------------------------------------------------------------
# slapo-accesslog
#---------------------------------------------------------------------------


syntax_registry.reg_at(
    NotBefore.oid, [
        '1.3.6.1.4.1.4203.666.11.5.1.2', 'reqStart',
        '1.3.6.1.4.1.4203.666.11.5.1.3', 'reqEnd',
    ]
)


class AuditContext(NamingContexts):
    oid = 'AuditContext'
    desc = 'OpenLDAP DN pointing to audit naming context'

    def display(self, valueindex=0, commandbutton=False):
        r = [DistinguishedName.display(self, valueindex, commandbutton)]
        if commandbutton:
            r.extend([
                self._app.anchor(
                    'searchform', 'Search',
                    [
                        ('dn', self._av),
                        ('scope', str(ldap0.SCOPE_ONELEVEL)),
                    ],
                    title=u'Go to search form for audit log',
                ),
                self._app.anchor(
                    'search', 'List all',
                    [
                        ('dn', self._av),
                        ('filterstr', u'(objectClass=auditObject)'),
                        ('scope', str(ldap0.SCOPE_ONELEVEL)),
                    ],
                    title=u'List audit log entries of all operations',
                ),
                self._app.anchor(
                    'search', 'List writes',
                    [
                        ('dn', self._av),
                        ('filterstr', u'(objectClass=auditWriteObject)'),
                        ('scope', str(ldap0.SCOPE_ONELEVEL)),
                    ],
                    title=u'List audit log entries of all write operations',
                ),
            ])
        return web2ldapcnf.command_link_separator.join(r)

syntax_registry.reg_at(
    AuditContext.oid,
    [
        '1.3.6.1.4.1.4203.666.11.5.1.30', 'auditContext',
        '1.3.6.1.4.1.4203.1.12.2.3.3.4.1',  # olcAccessLogDB
    ]
)


class ReqResult(LDAPv3ResultCode):
    oid = 'ReqResult-oid'

syntax_registry.reg_at(
    ReqResult.oid, [
        '1.3.6.1.4.1.4203.666.11.5.1.7', 'reqResult', # reqResult
    ]
)


class ReqMod(OctetString, DirectoryString):
    oid = 'ReqMod-oid'
    desc = 'List of modifications/old values'
    known_modtypes = {b'+', b'-', b'=', b'#', b''}

    def display(self, valueindex=0, commandbutton=False):
        if self._av == b':':
            # magic value used for fixing OpenLDAP ITS#6545
            return ':'
        try:
            mod_attr_type, mod_attr_rest = self._av.split(b':', 1)
            mod_type = mod_attr_rest[0:1].strip()
        except (ValueError, IndexError):
            return OctetString.display(self, valueindex, commandbutton)
        if not mod_type in self.known_modtypes:
            return OctetString.display(self, valueindex, commandbutton)
        if len(mod_attr_rest) > 1:
            try:
                mod_type, mod_attr_value = mod_attr_rest.split(b' ', 1)
            except ValueError:
                return OctetString.display(self, valueindex, commandbutton)
        else:
            mod_attr_value = b''
        mod_attr_type_u = mod_attr_type.decode(self._app.ls.charset)
        mod_type_u = mod_type.decode(self._app.ls.charset)
        try:
            mod_attr_value.decode(self._app.ls.charset)
        except UnicodeDecodeError:
            return '%s:%s<br>\n<code>\n%s\n</code>\n' % (
                self._app.form.utf2display(mod_attr_type_u),
                self._app.form.utf2display(mod_type_u),
                mod_attr_value.hex().upper(),
            )
        else:
            return DirectoryString.display(self, valueindex, commandbutton)
        raise ValueError

syntax_registry.reg_at(
    ReqMod.oid, [
        '1.3.6.1.4.1.4203.666.11.5.1.16', 'reqMod',
        '1.3.6.1.4.1.4203.666.11.5.1.17', 'reqOld',
    ]
)


class ReqControls(IA5String):
    oid = '1.3.6.1.4.1.4203.666.11.5.3.1'
    desc = 'List of LDAPv3 extended controls sent along with a request'

    def display(self, valueindex=0, commandbutton=False):
        result_lines = [IA5String.display(self, valueindex, commandbutton)]
        # Eliminate X-ORDERED prefix
        _, rest = self.av_u.strip().split('}{', 1)
        # check whether it ends with }
        if rest.endswith('}'):
            result_lines.append('Extracted:')
            # consume } and split tokens
            ctrl_tokens = list(filter(
                None,
                [t.strip() for t in rest[:-1].split(' ')]
            ))
            ctrl_type = ctrl_tokens[0]
            try:
                ctrl_name, _, _ = OID_REG[ctrl_type]
            except (KeyError, ValueError):
                try:
                    ctrl_name = KNOWN_RESPONSE_CONTROLS.get(ctrl_type).__class__.__name__
                except KeyError:
                    ctrl_name = None
            if ctrl_name:
                result_lines.append(self._app.form.utf2display(ctrl_name))
            # Extract criticality
            try:
                ctrl_criticality = {
                    'TRUE': True,
                    'FALSE': False,
                }[ctrl_tokens[ctrl_tokens.index('criticality')+1].upper()]
            except (KeyError, ValueError, IndexError):
                ctrl_criticality = False
            result_lines.append('criticality %s' % str(ctrl_criticality).upper())
            # Extract controlValue
            try:
                ctrl_value = binascii.unhexlify(ctrl_tokens[ctrl_tokens.index('controlValue')+1].upper()[1:-1])
            except (KeyError, ValueError, IndexError):
                pass
            else:
                try:
                    decoded_control_value = ber_decoder.decode(ctrl_value)
                except Exception:
                    decoded_control_value = ctrl_value
                result_lines.append(
                    'controlValue %s' % (
                        self._app.form.utf2display(
                            repr(decoded_control_value)
                        ).replace('\n', '<br>')
                    )
                )
        return '<br>'.join(result_lines)

syntax_registry.reg_at(
    ReqControls.oid, [
        '1.3.6.1.4.1.4203.666.11.5.1.10', 'reqControls',
        '1.3.6.1.4.1.4203.666.11.5.1.11', 'reqRespControls',
    ]
)


class ReqEntryUUID(UUID):
    oid = 'ReqEntryUUID-oid'

    def display(self, valueindex=0, commandbutton=False):
        display_value = UUID.display(self, valueindex, commandbutton)
        if not commandbutton:
            return display_value
        return web2ldapcnf.command_link_separator.join((
            display_value,
            self._app.anchor(
                'search', 'Search target',
                (
                    ('dn', self._dn),
                    (
                        'filterstr',
                        u'(entryUUID=%s)' % (self.av_u),
                    ),
                    (
                        'search_root',
                        self._app.ls.get_search_root(self._app.ls.uc_decode(self._entry['reqDN'][0])[0]),
                    ),
                ),
                title=u'Search entry by UUID',
            )
        ))

syntax_registry.reg_at(
    ReqEntryUUID.oid, [
        '1.3.6.1.4.1.4203.666.11.5.1.31', 'reqEntryUUID', # reqEntryUUID
    ]
)


class ReqSession(Integer):
    oid = 'ReqSession-oid'

    def display(self, valueindex=0, commandbutton=False):
        display_value = Integer.display(self, valueindex, commandbutton)
        if not commandbutton:
            return display_value
        return web2ldapcnf.command_link_separator.join((
            display_value,
            self._app.anchor(
                'search', '&raquo;',
                (
                    ('dn', self._dn),
                    ('search_root', self._app.naming_context),
                    ('searchform_mode', u'adv'),
                    ('search_attr', u'reqSession'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                    ('search_string', self.av_u),
                ),
                title=u'Search all audit entries with same session number',
            )
        ))

syntax_registry.reg_at(
    ReqSession.oid, [
        '1.3.6.1.4.1.4203.666.11.5.1.5', 'reqSession', # reqSession
    ]
)


#---------------------------------------------------------------------------
# General
#---------------------------------------------------------------------------


class Authz(DirectoryString):
    oid = '1.3.6.1.4.1.4203.666.2.7'
    desc = 'OpenLDAP authz'


syntax_registry.reg_at(
    AuthzDN.oid, [
        'monitorConnectionAuthzDN',
        '1.3.6.1.4.1.4203.666.1.55.7', # monitorConnectionAuthzDN
        'reqAuthzID',
        '1.3.6.1.4.1.4203.666.11.5.1.6', # reqAuthzID
    ]
)


class OpenLDAPACI(DirectoryString):
    oid = '1.3.6.1.4.1.4203.666.2.1'
    desc = 'OpenLDAP ACI'


class OpenLDAPSpecialBackendSuffix(NamingContexts):
    oid = 'OpenLDAPSpecialBackendSuffix-oid'
    desc = 'OpenLDAP special backend suffix'

    def _config_link(self):
        attr_type_u = self._at[:-7]
        try:
            config_context = self._app.ls.uc_decode(self._app.ls.rootDSE['configContext'][0])[0]
        except KeyError:
            return None
        return self._app.anchor(
            'search', 'Config',
            (
                ('dn', config_context),
                ('scope', web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
                (
                    'filterstr',
                    u'(&(objectClass=olcDatabaseConfig)(olcDatabase=%s))' % (attr_type_u),
                ),
            ),
            title=u'Search for configuration entry below %s' % (config_context),
        )

syntax_registry.reg_at(
    OpenLDAPSpecialBackendSuffix.oid,
    [
        'monitorContext', '1.3.6.1.4.1.4203.666.1.10',
        'configContext', '1.3.6.1.4.1.4203.1.12.2.1',
    ]
)


syntax_registry.reg_at(
    Uri.oid, ['monitorConnectionListener']
)


syntax_registry.reg_at(
    DistinguishedName.oid, [
        'entryDN',
        'reqDN',
    ]
)

# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
