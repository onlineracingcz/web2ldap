# -*- coding: utf-8 -*-
"""
web2ldap.app.form: class for web2ldap input form handling

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import http.cookies

import ldap0.ldif
import ldap0.schema
from ldap0.pw import random_string

import web2ldapcnf

from ..ldapsession import CONTROL_TREEDELETE
from ..web import HTML_ESCAPE_MAP
from ..ldaputil import rdn_pattern, attr_type_pattern
from ..ldaputil.oidreg import OID_REG
from ..ldaputil.passwd import AVAIL_USERPASSWORD_SCHEMES
from .gui import host_pattern, HIDDEN_FIELD
from .searchform import (
    SEARCH_OPTIONS,
    SEARCH_SCOPE_OPTIONS,
    SEARCH_SCOPE_STR_SUBTREE,
)
from ..web.forms import (
    Input,
    Field,
    Textarea,
    BytesInput,
    Select,
    Checkbox,
    Form,
    InvalidValueFormat,
)
from ..ldapsession import AVAILABLE_BOOLEAN_CONTROLS, CONTROL_TREEDELETE
from ..web.session import SESSION_ID_CHARS, SESSION_ID_LENGTH, SESSION_ID_REGEX


# Work around https://bugs.python.org/issue29613
http.cookies.Morsel._reserved['samesite'] = 'SameSite'

class Web2LDAPForm(Form):
    """
    Form sub-class for a web2ldap use-case

    more sub-classes define forms for different URL commands
    """
    command = None
    cookie_length = web2ldapcnf.cookie_length or 2 * 42
    cookie_max_age = web2ldapcnf.cookie_max_age
    cookie_domain = web2ldapcnf.cookie_domain
    cookie_name_prefix = 'web2ldap_'

    def __init__(self, inf, env):
        Form.__init__(self, inf, env)
        # Cookie handling
        try:
            self.cookies = http.cookies.SimpleCookie(self.env['HTTP_COOKIE'])
        except KeyError:
            self.cookies = http.cookies.SimpleCookie()
        self.next_cookie = http.cookies.SimpleCookie()

    @staticmethod
    def s2d(
            value,
            tab_identiation='',
            sp_entity='&nbsp;&nbsp;',
            lf_entity='\n'
        ):
        assert isinstance(value, str), \
            TypeError('Argument value must be str, was %r' % (value,))
        value = value or ''
        translate_map = dict(HTML_ESCAPE_MAP.items())
        translate_map.update({
            9: tab_identiation,
            10: lf_entity,
        })
        return value.translate(translate_map).replace('  ', sp_entity)

    def unset_cookie(self, cki):
        if cki is not None:
            assert len(cki) == 1, \
                ValueError(
                    'More than one Morsel cookie instance in cki: %d objects found' % (len(cki))
                )
            cookie_name = list(cki.keys())[0]
            cki[cookie_name] = ''
            cki[cookie_name]['max-age'] = 0
            self.next_cookie.update(cki)
        # end of unset_cookie()

    def get_cookie_domain(self):
        if self.cookie_domain:
            cookie_domain = self.cookie_domain
        elif 'SERVER_NAME' in self.env or 'HTTP_HOST' in self.env:
            cookie_domain = self.env.get('HTTP_HOST', self.env['SERVER_NAME']).split(':')[0]
        return cookie_domain

    def set_cookie(self, name_suffix):
        # Generate a randomized key and value
        cookie_key = random_string(
            alphabet=SESSION_ID_CHARS,
            length=self.cookie_length,
        )
        cookie_name = ''.join((self.cookie_name_prefix, name_suffix))
        cki = http.cookies.SimpleCookie({
            cookie_name: cookie_key,
        })
        cki[cookie_name]['path'] = self.script_name
        cki[cookie_name]['domain'] = self.get_cookie_domain()
        cki[cookie_name]['max-age'] = str(self.cookie_max_age)
        cki[cookie_name]['httponly'] = True
        cki[cookie_name]['samesite'] = 'Strict'
        if self.env.get('HTTPS', None) == 'on':
            cki[cookie_name]['secure'] = True
        self.next_cookie.update(cki)
        return cki # set_cookie()

    def fields(self):
        return [
            Input(
                'delsid',
                'Old SID to be deleted',
                SESSION_ID_LENGTH,
                1,
                SESSION_ID_REGEX,
            ),
            Input('who', 'Bind DN/AuthcID', 1000, 1, '.*', size=40),
            Input('cred', 'with Password', 200, 1, '.*', size=15),
            Select(
                'login_authzid_prefix',
                'SASL AuthzID',
                1,
                options=[('', '- no prefix -'), ('u:', 'user-ID'), ('dn:', 'DN')],
                default=None
            ),
            Input('login_authzid', 'SASL AuthzID', 1000, 1, '.*', size=20),
            Input('login_realm', 'SASL Realm', 1000, 1, '.*', size=20),
            AuthMechSelect('login_mech', 'Authentication mechanism'),
            Input('ldapurl', 'LDAP Url', 1024, 1, '[ ]*ldap(|i|s)://.*', size=30),
            Input(
                'host', 'Host:Port',
                255, 1,
                '(%s|[a-zA-Z0-9/._-]+)' % host_pattern,
                size=30,
            ),
            DistinguishedNameInput('dn', 'Distinguished Name'),
            Select(
                'scope', 'Scope', 1,
                options=SEARCH_SCOPE_OPTIONS,
                default=SEARCH_SCOPE_STR_SUBTREE,
            ),
            DistinguishedNameInput('login_search_root', 'Login search root'),
            Select(
                'conntype', 'Connection type', 1,
                options=[
                    ('0', 'LDAP clear-text connection'),
                    ('1', 'LDAP with StartTLS ext.op.'),
                    ('2', 'LDAP over separate SSL port (LDAPS)'),
                    ('3', 'LDAP over Unix domain socket (LDAPI)')
                ],
                default='0',
            )
        ]

    def action_url(self, command, sid):
        return '%s/%s%s' % (
            self.script_name,
            command,
            {False:'/%s' % sid, True:''}[sid is None],
        )

    def begin_form(
            self,
            command,
            sid,
            method,
            target=None,
            enctype='application/x-www-form-urlencoded',
        ):
        target = {
            False:'target="%s"' % (target),
            True:'',
        }[target is None]
        return """
          <form
            action="%s"
            method="%s"
            %s
            enctype="%s"
            accept-charset="%s"
          >
          """  % (
              self.action_url(command, sid),
              method,
              target,
              enctype,
              self.accept_charset
          )

    def hidden_field_html(self, name, value, desc):
        return HIDDEN_FIELD % (
            name,
            self.s2d(value, sp_entity='  '),
            self.s2d(desc, sp_entity='&nbsp;&nbsp;'),
        )

    def hidden_input_html(self, ignoreFieldNames=None):
        """
        Return all input parameters as hidden fields in one HTML string.

        ignoreFieldNames
            Names of parameters to be excluded.
        """
        ignoreFieldNames = set(ignoreFieldNames or [])
        result = []
        for f in [
                self.field[p]
                for p in self.input_field_names
                if not p in ignoreFieldNames
            ]:
            for val in f.value:
                if not isinstance(val, str):
                    val = self.uc_decode(val)[0]
                result.append(self.hidden_field_html(f.name, val, ''))
        return '\n'.join(result) # hiddenInputFieldString()


class SearchAttrs(Input):

    def __init__(self, name='search_attrs', text='Attributes to be read'):
        Input.__init__(self, name, text, 1000, 1, '[@*+0-9.\\w,_;-]+')

    def set_value(self, value):
        value = ','.join(
            filter(
                None,
                map(str.strip, value.replace(' ', ',').split(','))
            )
        )
        Input.set_value(self, value)


class Web2LDAPFormSearchform(Web2LDAPForm):
    command = 'searchform'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.extend([
            Input(
                'search_submit', 'Search form submit button',
                6, 1,
                '(Search|[+-][0-9]+)',
            ),
            Select(
                'searchform_mode',
                'Search form mode',
                1,
                options=[('base', 'Base'), ('adv', 'Advanced'), ('exp', 'Expert')],
                default='base',
            ),
            DistinguishedNameInput('search_root', 'Search root'),
            Input(
                'filterstr',
                'Search filter string',
                1200,
                1,
                '.*',
                size=90,
            ),
            Input(
                'searchform_template',
                'Search form template name',
                60,
                web2ldapcnf.max_searchparams,
                '[a-zA-Z0-9. ()_-]+',
            ),
            Select(
                'search_resnumber', 'Number of results to display', 1,
                options=[
                    ('0', 'unlimited'), ('10', '10'), ('20', '20'),
                    ('50', '50'), ('100', '100'), ('200', '200'),
                ],
                default='10'
            ),
            Select(
                'search_lastmod', 'Interval of last creation/modification', 1,
                options=[
                    ('-1', '-'),
                    ('10', '10 sec.'),
                    ('60', '1 min.'),
                    ('600', '10 min.'),
                    ('3600', '1 hour'),
                    ('14400', '4 hours'),
                    ('43200', '12 hours'),
                    ('86400', '24 hours'),
                    ('172800', '2 days'),
                    ('604800', '1 week'),
                    ('2419200', '4 weeks'),
                    ('6048000', '10 weeks'),
                    ('31536000', '1 year'),
                ],
                default='-1'
            ),
            InclOpAttrsCheckbox(default='yes', checked=False),
            Select('search_mode', 'Search Mode', 1, options=['(&%s)', '(|%s)']),
            Input(
                'search_attr',
                'Attribute(s) to be searched',
                100,
                web2ldapcnf.max_searchparams,
                '[\\w,_;-]+',
            ),
            Input(
                'search_mr', 'Matching Rule',
                100,
                web2ldapcnf.max_searchparams,
                '[\\w,_;-]+',
            ),
            Select(
                'search_option', 'Search option',
                web2ldapcnf.max_searchparams,
                options=SEARCH_OPTIONS,
            ),
            Input(
                'search_string', 'Search string',
                600,
                web2ldapcnf.max_searchparams,
                '.*',
                size=60,
            ),
            SearchAttrs(),
            ExportFormatSelect(),
        ])
        return res


class Web2LDAPFormSearch(Web2LDAPFormSearchform):
    command = 'search'

    def fields(self):
        res = Web2LDAPFormSearchform.fields(self)
        res.extend([
            Input(
                'search_resminindex',
                'Minimum index of search results',
                10, 1,
                '[0-9]+',
            ),
            Input(
                'search_resnumber',
                'Number of results to display',
                3, 1,
                '[0-9]+',
            ),
        ])
        return res


class Web2LDAPFormConninfo(Web2LDAPForm):
    command = 'conninfo'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.append(
            Select(
                'conninfo_flushcaches',
                'Flush caches',
                1,
                options=('0', '1'),
                default='0',
            )
        )
        return res


class Web2LDAPFormParams(Web2LDAPForm):
    command = 'params'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.extend([
            Select(
                'params_all_controls',
                'List all controls',
                1,
                options=('0', '1'),
                default='0',
            ),
            Input(
                'params_enable_control',
                'Enable LDAPv3 Boolean Control',
                50, 1,
                '([0-9]+.)*[0-9]+',
            ),
            Input(
                'params_disable_control',
                'Disable LDAPv3 Boolean Control',
                50, 1,
                '([0-9]+.)*[0-9]+',
            ),
            Select(
                'ldap_deref',
                'Dereference aliases',
                maxValues=1,
                default=str(ldap0.DEREF_NEVER),
                options=[
                    (str(ldap0.DEREF_NEVER), 'never'),
                    (str(ldap0.DEREF_SEARCHING), 'searching'),
                    (str(ldap0.DEREF_FINDING), 'finding'),
                    (str(ldap0.DEREF_ALWAYS), 'always'),
                ]
            ),
        ])
        return res


class Web2LDAPFormInput(Web2LDAPForm):

    """Base class for entry data input not directly used"""
    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.extend([
            Input('in_oc', 'Object classes', 60, 40, '[a-zA-Z0-9.-]+'),
            Select(
                'in_ft', 'Type of input form',
                1,
                options=('Template', 'Table', 'LDIF', 'OC'),
                default='Template',
            ),
            Input(
                'in_mr',
                'Add/del row',
                8, 1,
                '(Template|Table|LDIF|[+-][0-9]+)',
            ),
            Select(
                'in_oft', 'Type of input form',
                1,
                options=('Template', 'Table', 'LDIF'),
                default='Template',
            ),
            AttributeType('in_at', 'Attribute type', web2ldapcnf.input_maxattrs),
            AttributeType('in_avi', 'Value index', web2ldapcnf.input_maxattrs),
            BytesInput(
                'in_av', 'Attribute Value',
                web2ldapcnf.input_maxfieldlen,
                web2ldapcnf.input_maxattrs,
                None
            ),
            LDIFTextArea('in_ldif', 'LDIF data'),
            Select(
                'in_ocf', 'Object class form mode', 1,
                options=[
                    ('tmpl', 'LDIF templates'),
                    ('exp', 'Object class selection')
                ],
                default='tmpl',
            ),
        ])
        return res


class Web2LDAPFormAdd(Web2LDAPFormInput):
    command = 'add'

    def fields(self):
        res = Web2LDAPFormInput.fields(self)
        res.extend([
            Input('add_rdn', 'RDN of new entry', 255, 1, '.*', size=50),
            DistinguishedNameInput('add_clonedn', 'DN of template entry'),
            Input(
                'add_template', 'LDIF template name',
                60,
                web2ldapcnf.max_searchparams,
                '.+',
            ),
            Input('add_basedn', 'Base DN of new entry', 1024, 1, '.*', size=50),
        ])
        return res


class Web2LDAPFormModify(Web2LDAPFormInput):
    command = 'modify'

    def fields(self):
        res = Web2LDAPFormInput.fields(self)
        res.extend([
            AttributeType(
                'in_oldattrtypes',
                'Old attribute types',
                web2ldapcnf.input_maxattrs,
            ),
            AttributeType(
                'in_wrtattroids',
                'Writeable attribute types',
                web2ldapcnf.input_maxattrs,
            ),
            Input(
                'in_assertion',
                'Assertion filter string',
                2000,
                1,
                '.*',
                required=False,
            ),
        ])
        return res


class Web2LDAPFormDds(Web2LDAPForm):
    command = 'dds'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.extend([
            Input(
                'dds_renewttlnum',
                'Request TTL number',
                12, 1,
                '[0-9]+',
                default=None,
            ),
            Select(
                'dds_renewttlfac',
                'Request TTL factor',
                1,
                options=(
                    ('1', 'seconds'),
                    ('60', 'minutes'),
                    ('3600', 'hours'),
                    ('86400', 'days'),
                ),
                default='1'
            ),
        ])
        return res


class Web2LDAPFormBulkmod(Web2LDAPForm):
    command = 'bulkmod'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        bulkmod_ctrl_options = [
            (control_oid, OID_REG.get(control_oid, (control_oid,))[0])
            for control_oid, control_spec in AVAILABLE_BOOLEAN_CONTROLS.items()
            if (
                '**all**' in control_spec[0]
                or '**write**' in control_spec[0]
                or 'modify' in control_spec[0]
            )
        ]
        res.extend([
            Input(
                'bulkmod_submit',
                'Search form submit button',
                6, 1,
                '(Next>>|<<Back|Apply|Cancel|[+-][0-9]+)',
            ),
            Select(
                'bulkmod_ctrl',
                'Extended controls',
                len(bulkmod_ctrl_options),
                options=bulkmod_ctrl_options,
                default=None,
                size=min(8, len(bulkmod_ctrl_options)),
                multiSelect=1,
            ),
            Input(
                'filterstr',
                'Search filter string for searching entries to be deleted',
                1200, 1,
                '.*',
            ),
            Input(
                'bulkmod_modrow',
                'Add/del row',
                8, 1,
                '(Template|Table|LDIF|[+-][0-9]+)',
            ),
            AttributeType('bulkmod_at', 'Attribute type', web2ldapcnf.input_maxattrs),
            Select(
                'bulkmod_op',
                'Modification type',
                web2ldapcnf.input_maxattrs,
                options=(
                    ('', ''),
                    (str(ldap0.MOD_ADD), 'add'),
                    (str(ldap0.MOD_DELETE), 'delete'),
                    (str(ldap0.MOD_REPLACE), 'replace'),
                    (str(ldap0.MOD_INCREMENT), 'increment'),
                ),
                default=None,
            ),
            BytesInput(
                'bulkmod_av', 'Attribute Value',
                web2ldapcnf.input_maxfieldlen,
                web2ldapcnf.input_maxattrs,
                None,
                size=30,
            ),
            DistinguishedNameInput('bulkmod_newsuperior', 'New superior DN'),
            Checkbox('bulkmod_cp', 'Copy entries', 1, default='yes', checked=False),
        ])
        return res


class Web2LDAPFormDelete(Web2LDAPForm):
    command = 'delete'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        delete_ctrl_options = [
            (control_oid, OID_REG.get(control_oid, (control_oid,))[0])
            for control_oid, control_spec in AVAILABLE_BOOLEAN_CONTROLS.items()
            if (
                '**all**' in control_spec[0]
                or '**write**' in control_spec[0]
                or 'delete' in control_spec[0]
            )
        ]
        delete_ctrl_options.append((CONTROL_TREEDELETE, 'Tree Deletion'))
        res.extend([
            Select(
                'delete_confirm', 'Confirmation',
                1,
                options=('yes', 'no'),
                default='no',
            ),
            Select(
                'delete_ctrl',
                'Extended controls',
                len(delete_ctrl_options),
                options=delete_ctrl_options,
                default=None,
                size=min(8, len(delete_ctrl_options)),
                multiSelect=1,
            ),
            Input(
                'filterstr',
                'Search filter string for searching entries to be deleted',
                1200, 1,
                '.*',
            ),
            Input('delete_attr', 'Attribute to be deleted', 255, 100, '[\\w_;-]+'),
        ])
        return res


class Web2LDAPFormRename(Web2LDAPForm):
    command = 'rename'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.extend([
            Input(
                'rename_newrdn',
                'New RDN',
                255, 1,
                rdn_pattern,
                size=50,
            ),
            DistinguishedNameInput('rename_newsuperior', 'New superior DN'),
            Checkbox('rename_delold', 'Delete old', 1, default='yes', checked=True),
            Input(
                'rename_newsupfilter',
                'Filter string for searching new superior entry', 300, 1, '.*',
                default='(|(objectClass=organization)(objectClass=organizationalUnit))',
                size=50,
            ),
            DistinguishedNameInput(
                'rename_searchroot',
                'Search root under which to look for new superior entry.',
            ),
            Input(
                'rename_supsearchurl',
                'LDAP URL for searching new superior entry',
                100, 1,
                '.*',
                size=30,
            ),
        ])
        return res


class Web2LDAPFormPasswd(Web2LDAPForm):
    command = 'passwd'
    passwd_actions = (
        (
            'passwdextop',
            'Server-side',
            'Password modify extended operation',
        ),
        (
            'setuserpassword',
            'Modify password attribute',
            'Set the password attribute with modify operation'
        ),
    )

    @staticmethod
    def passwd_fields():
        """
        return list of Field instances needed for a password change input form
        """
        return [
            Select(
                'passwd_action', 'Password action', 1,
                options=[
                    (action, short_desc)
                    for action, short_desc, _ in Web2LDAPFormPasswd.passwd_actions
                ],
                default='setuserpassword'
            ),
            DistinguishedNameInput('passwd_who', 'Password DN'),
            Field('passwd_oldpasswd', 'Old password', 100, 1, '.*'),
            Field('passwd_newpasswd', 'New password', 100, 2, '.*'),
            Select(
                'passwd_scheme', 'Password hash scheme', 1,
                options=AVAIL_USERPASSWORD_SCHEMES.items(),
                default=None,
            ),
            Checkbox(
                'passwd_ntpasswordsync',
                'Sync ntPassword for Samba',
                1,
                default='yes',
                checked=True,
            ),
            Checkbox(
                'passwd_settimesync',
                'Sync password setting times',
                1,
                default='yes',
                checked=True,
            ),
            Checkbox(
                'passwd_forcechange',
                'Force password change',
                1,
                default='yes',
                checked=False,
            ),
            Checkbox(
                'passwd_inform',
                'Password change inform action',
                1,
                default="display_url",
                checked=False,
            ),
        ]

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.extend(self.passwd_fields())
        return res


class Web2LDAPFormRead(Web2LDAPForm):
    command = 'read'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.extend([
            Input(
                'filterstr',
                'Search filter string when reading single entry',
                1200, 1,
                '.*',
            ),
            Select(
                'read_nocache', 'Force fresh read',
                1,
                options=['0', '1'],
                default='0',
            ),
            Input('read_attr', 'Read attribute', 255, 100, '[\\w_;-]+'),
            Input('read_attrindex', 'Read attribute', 255, 1, '[0-9]+'),
            Input('read_attrmimetype', 'MIME type', 255, 1, '[\\w.-]+/[\\w.-]+'),
            Select(
                'read_output', 'Read output format',
                1,
                options=('table', 'vcard', 'template'),
                default='template',
            ),
            SearchAttrs(),
            Input('read_expandattr', 'Attributes to be read', 1000, 50, '[*+\\w,_;-]+'),
        ])
        return res


class Web2LDAPFormGroupadm(Web2LDAPForm):
    command = 'groupadm'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.extend([
            DistinguishedNameInput('groupadm_searchroot', 'Group search root'),
            Input('groupadm_name', 'Group name', 100, 1, '.*', size=30),
            DistinguishedNameInput('groupadm_add', 'Add to group', 300),
            DistinguishedNameInput('groupadm_remove', 'Remove from group', 300),
            Select(
                'groupadm_view',
                'Group list view',
                1,
                options=(
                    ('0', 'none of the'),
                    ('1', 'only member'),
                    ('2', 'all'),
                ),
                default='1',
            ),
        ])
        return res


class Web2LDAPFormLogin(Web2LDAPForm):
    command = 'login'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.append(
            DistinguishedNameInput('login_who', 'Bind DN')
        )
        return res


class Web2LDAPFormLocate(Web2LDAPForm):
    command = 'locate'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.append(
            Input('locate_name', 'Location name', 500, 1, '.*', size=25)
        )
        return res


class Web2LDAPFormOid(Web2LDAPForm):
    command = 'oid'

    def fields(self):
        res = Web2LDAPForm.fields(self)
        res.extend([
            OIDInput('oid', 'OID'),
            Select(
                'oid_class',
                'Schema element class',
                1,
                options=ldap0.schema.SCHEMA_ATTRS,
                default='',
            ),
        ])
        return res


class Web2LDAPFormDit(Web2LDAPForm):
    command = 'dit'


class DistinguishedNameInput(Input):
    """Input field class for LDAP DNs."""

    def __init__(self, name='dn', text='DN', maxValues=1, required=False, default=''):
        Input.__init__(
            self, name, text, 1024, maxValues, None,
            size=70, required=required, default=default
        )

    def _validate_format(self, value):
        if value and not ldap0.dn.is_dn(value):
            raise InvalidValueFormat(self.name, self.text, value)


class LDIFTextArea(Textarea):
    """A single multi-line input field for LDIF data"""

    def __init__(
            self,
            name='in_ldif',
            text='LDIF data',
            required=False,
            max_entries=1
        ):
        Textarea.__init__(
            self,
            name,
            text,
            web2ldapcnf.ldif_maxbytes,
            1,
            '^.*$',
            required=required,
        )
        self._max_entries = max_entries

    @property
    def ldif_records(self):
        if self.value:
            return list(
                ldap0.ldif.LDIFParser.frombuf(
                    '\n'.join(self.value).encode(self.charset),
                    ignored_attr_types=[],
                    process_url_schemes=web2ldapcnf.ldif_url_schemes
                ).parse(max_entries=self._max_entries)
            )
        return []


class OIDInput(Input):

    def __init__(self, name, text, default=None):
        Input.__init__(
            self, name, text,
            512, 1, '[a-zA-Z0-9_.;*-]+',
            default=default,
            required=False,
            size=30,
        )


class ObjectClassSelect(Select):
    """Select field class for choosing the object class(es)"""

    def __init__(
            self,
            name='in_oc',
            text='Object classes',
            options=None,
            default=None,
            required=False,
            accesskey='',
            size=12, # Size of displayed select field
        ):
        select_default = default or []
        select_default.sort(key=str.lower)
        additional_options = [
            opt
            for opt in options or []
            if not opt in select_default
        ]
        additional_options.sort(key=str.lower)
        select_options = select_default[:]
        select_options.extend(additional_options)
        Select.__init__(
            self,
            name, text,
            maxValues=200,
            required=required,
            options=select_options,
            default=select_default,
            accesskey=accesskey,
            size=size,
            ignoreCase=1,
            multiSelect=1
        )
        self.setRegex('[\\w]+')
        self.maxLen = 200
        # end of ObjectClassSelect()


class ExportFormatSelect(Select):
    """Select field class for choosing export format"""

    def __init__(
            self,
            default='ldif1',
            required=False,
        ):
        Select.__init__(
            self,
            'search_output',
            'Export format',
            1,
            options=(
                ('table', 'Table/template'),
                ('raw', 'Raw DN list'),
                ('print', 'Printable'),
                ('ldif', 'LDIF (Umich)'),
                ('ldif1', 'LDIFv1 (RFC2849)'),
                ('csv', 'CSV'),
                ('excel', 'Excel'),
            ),
            default=default,
            required=required,
            size=1,
        )


class AttributeType(Input):
    """
    Input field for an LDAP attribute type
    """
    def __init__(self, name, text, maxValues):
        Input.__init__(
            self,
            name,
            text,
            500,
            maxValues,
            attr_type_pattern,
            required=False,
            size=30
        )


class InclOpAttrsCheckbox(Checkbox):

    def __init__(self, default='yes', checked=False):
        Checkbox.__init__(
            self,
            'search_opattrs',
            'Request operational attributes',
            1,
            default=default,
            checked=checked
        )


class AuthMechSelect(Select):
    """Select field class for choosing the bind mech"""

    supported_bind_mechs = {
        '': 'Simple Bind',
        'DIGEST-MD5': 'SASL Bind: DIGEST-MD5',
        'CRAM-MD5': 'SASL Bind: CRAM-MD5',
        'PLAIN': 'SASL Bind: PLAIN',
        'LOGIN': 'SASL Bind: LOGIN',
        'GSSAPI': 'SASL Bind: GSSAPI',
        'EXTERNAL': 'SASL Bind: EXTERNAL',
        'OTP': 'SASL Bind: OTP',
        'NTLM': 'SASL Bind: NTLM',
        'SCRAM-SHA-1': 'SASL Bind: SCRAM-SHA-1',
        'SCRAM-SHA-256': 'SASL Bind: SCRAM-SHA-256',
    }

    def __init__(
            self,
            name='login_mech',
            text='Authentication mechanism',
            default=None,
            required=False,
            accesskey='',
            size=1,
        ):
        Select.__init__(
            self,
            name, text, maxValues=1,
            required=required,
            options=None,
            default=default or [],
            accesskey=accesskey,
            size=size,
            ignoreCase=0,
            multiSelect=0
        )

    def setOptions(self, options):
        options_dict = {}
        options_dict[''] = self.supported_bind_mechs['']
        for o in options or self.supported_bind_mechs.keys():
            o_upper = o.upper()
            if o_upper in self.supported_bind_mechs:
                options_dict[o_upper] = self.supported_bind_mechs[o_upper]
        Select.setOptions(self, options_dict.items())
