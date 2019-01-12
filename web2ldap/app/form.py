# -*- coding: utf-8 -*-
"""
web2ldap.app.form: class for web2ldap input form handling

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import urllib
import codecs
import re
import Cookie

import ldap0.ldif
import ldap0.schema
from ldap0.pw import random_string

import web2ldapcnf

import web2ldap.web.forms
from web2ldap.web import escape_html
import web2ldap.ldaputil.base
from web2ldap.ldaputil.oidreg import OID_REG
import web2ldap.ldapsession
import web2ldap.ldaputil.passwd
import web2ldap.app.core
import web2ldap.app.gui
import web2ldap.app.passwd
import web2ldap.app.searchform
import web2ldap.app.ldapparams
import web2ldap.app.session
from web2ldap.app.session import session_store


class Web2LDAPForm(web2ldap.web.forms.Form):
    command = None
    cookie_length = web2ldapcnf.cookie_length or 2 * 42
    cookie_max_age = web2ldapcnf.cookie_max_age
    cookie_domain = web2ldapcnf.cookie_domain
    cookie_name_prefix = 'web2ldap_'

    def __init__(self, inf, env):
        web2ldap.web.forms.Form.__init__(self, inf, env)
        self._set_charset()
        self._add_fields()
        # Cookie handling
        try:
            self.cookies = Cookie.SimpleCookie(self.env['HTTP_COOKIE'])
        except KeyError:
            self.cookies = Cookie.SimpleCookie()
        self.next_cookie = Cookie.SimpleCookie()

    def utf2display(
            self,
            value,
            tab_identiation='',
            sp_entity='&nbsp;&nbsp;',
            lf_entity='\n'
        ):
        assert isinstance(value, unicode), \
            TypeError('Argument value must be unicode, was %r' % (value))
        value = value or u''
        return escape_html(
            self.uc_encode(value, 'replace')[0]
        ).replace('\n', lf_entity).replace('\t', tab_identiation).replace('  ', sp_entity)

    def unsetCookie(self, cki):
        if cki is not None:
            assert len(cki) == 1, \
                ValueError(
                    'More than one Morsel cookie instance in cki: %d objects found' % (len(cki))
                )
            cookie_name = cki.keys()[0]
            cki[cookie_name] = ''
            cki[cookie_name]['max-age'] = 0
            self.next_cookie.update(cki)
        return # unsetCookie()

    def get_cookie_domain(self):
        if self.cookie_domain:
            cookie_domain = self.cookie_domain
        elif 'SERVER_NAME' in self.env or 'HTTP_HOST' in self.env:
            cookie_domain = self.env.get('HTTP_HOST', self.env['SERVER_NAME']).split(':')[0]
        return cookie_domain

    def setNewCookie(self, name_suffix):
        # Generate a randomized key and value
        cookie_key = random_string(
            alphabet=web2ldap.web.session.SESSION_ID_CHARS,
            length=self.cookie_length,
        )
        cookie_name = ''.join((self.cookie_name_prefix, name_suffix))
        cki = Cookie.SimpleCookie({
            cookie_name: cookie_key,
        })
        cki[cookie_name]['path'] = self.script_name
        cki[cookie_name]['domain'] = self.get_cookie_domain()
        cki[cookie_name]['max-age'] = str(self.cookie_max_age)
        cki[cookie_name]['httponly'] = None
        if self.env.get('HTTPS', None) == 'on':
            cki[cookie_name]['secure'] = None
        self.next_cookie.update(cki)
        return cki # setNewCookie()

    def _set_charset(self):
        self.accept_charset = 'utf-8'
        form_codec = codecs.lookup(self.accept_charset)
        self.uc_encode, self.uc_decode = form_codec[0], form_codec[1]
        return # _set_charset()

    def _add_fields(self):
        self.addField(web2ldap.web.forms.Input(
            'delsid',
            u'Old SID to be deleted',
            session_store.session_id_len,
            1,
            session_store.session_id_re.pattern
        ))
        self.addField(web2ldap.web.forms.Input('who', u'Bind DN/AuthcID', 1000, 1, u'.*', size=40))
        self.addField(web2ldap.web.forms.Input('cred', u'with Password', 200, 1, u'.*', size=15))
        self.addField(web2ldap.web.forms.Select('login_authzid_prefix', u'SASL AuthzID', 1, options=[(u'', u'- no prefix -'), ('u:', u'user-ID'), ('dn:', u'DN')], default=None))
        self.addField(web2ldap.web.forms.Input('login_authzid', u'SASL AuthzID', 1000, 1, u'.*', size=20))
        self.addField(web2ldap.web.forms.Input('login_realm', u'SASL Realm', 1000, 1, u'.*', size=20))
        self.addField(AuthMechSelect('login_mech', u'Authentication mechanism'))
        self.addField(web2ldap.web.forms.Input('ldapurl', u'LDAP Url', 1024, 1, '[ ]*ldap(|i|s)://.*', size=30))
        self.addField(web2ldap.web.forms.Input('host', u'Host:Port', 255, 1, '(%s|[a-zA-Z0-9/._-]+)' % web2ldap.app.gui.host_pattern, size=30))
        self.addField(DistinguishedNameInput('dn', 'Distinguished Name'))
        self.addField(web2ldap.web.forms.Select(
            'scope', 'Scope', 1,
            options=web2ldap.app.searchform.SEARCH_SCOPE_OPTIONS,
            default=web2ldap.app.searchform.SEARCH_SCOPE_STR_SUBTREE,
        ))
        self.addField(DistinguishedNameInput('login_search_root', 'Login search root'))
        self.addField(web2ldap.web.forms.Input('login_filterstr', u'Login search filter string', 300, 1, '.*'))
        self.addField(web2ldap.web.forms.Select(
            'conntype', 'Connection type', 1,
            options=[
                (u'0', u'LDAP clear-text connection'),
                (u'1', u'LDAP with StartTLS ext.op.'),
                (u'2', u'LDAP over separate SSL port (LDAPS)'),
                (u'3', u'LDAP over Unix domain socket (LDAPI)')
            ],
            default=u'0',
        ))

    def actionUrlHTML(self, command, sid):
        return '%s/%s%s' % (
            self.script_name,
            command,
            {False:'/%s' % sid, True:''}[sid is None],
        )

    def beginFormHTML(
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
              self.actionUrlHTML(command, sid),
              method,
              target,
              enctype,
              self.accept_charset
          )

    def hiddenFieldHTML(self, name, value, desc):
        return web2ldap.app.gui.HIDDEN_FIELD % (
            name,
            self.utf2display(value, sp_entity='  '),
            self.utf2display(desc, sp_entity='&nbsp;&nbsp;'),
        )

    def hiddenInputHTML(self, ignoreFieldNames=None):
        """
        Return all input parameters as hidden fields in one HTML string.

        ignoreFieldNames
            Names of parameters to be excluded.
        """
        ignoreFieldNames = set(ignoreFieldNames or [])
        result = []
        for f in [
                self.field[p]
                for p in self.inputFieldNames
                if not p in ignoreFieldNames
            ]:
            for val in f.value:
                if not isinstance(val, unicode):
                    val = self.uc_decode(val)[0]
                result.append(self.hiddenFieldHTML(f.name, val, u''))
        return '\n'.join(result) # hiddenInputFieldString()

    def formHTML(
            self,
            command,
            submitstr,
            sid,
            method,
            form_parameters,
            extrastr='',
            target=None
        ):
        """
        Build the HTML text of a submit form
        """
        form_str = [self.beginFormHTML(command, sid, method, target)]
        for param_name, param_value in form_parameters:
            form_str.append(self.hiddenFieldHTML(param_name, param_value, u''))
        form_str.append(
            '<p><input type="submit" value="%s">%s</p></form>' % (
                submitstr,
                extrastr,
            )
        )
        return '\n'.join(form_str)

    def applAnchor(
            self,
            command,
            anchor_text,
            sid,
            form_parameters,
            target=None,
            title=None,
            anchor_id=None,
        ):
        """
        Build the HTML text of a anchor with form parameters
        """
        assert isinstance(command, str), TypeError('command must be string, but was %r', command)
        assert isinstance(anchor_text, str), TypeError('anchor_text must be string, but was %r', anchor_text)
        assert sid is None or isinstance(sid, str), TypeError('sid must be None or string, but was %r', sid)
        assert anchor_id is None or isinstance(anchor_id, unicode), TypeError('anchor_id must be None or unicode, but was %r', anchor_id)
        assert target is None or isinstance(target, str), TypeError('target must be None or string, but was %r', target)
        assert title is None or isinstance(title, unicode), TypeError('title must be None or unicode, but was %r', title)
        target_attr = ''
        if target:
            target_attr = ' target="%s"' % (target)
        title_attr = ''
        if title:
            title_attr = ' title="%s"' % (self.utf2display(title).replace(' ', '&nbsp;'))
        if anchor_id:
            anchor_id = '#%s' % (self.utf2display(anchor_id))
        res = '<a class="CommandLink"%s%s href="%s?%s%s">%s</a>' % (
            target_attr,
            title_attr,
            self.actionUrlHTML(command, sid),
            '&amp;'.join([
                '%s=%s' % (param_name, urllib.quote(self.uc_encode(param_value)[0]))
                for param_name, param_value in form_parameters
            ]),
            anchor_id or '',
            anchor_text,
        )
        assert isinstance(res, bytes), TypeError('res must be bytes, was %r', res)
        return res


class SearchAttrs(web2ldap.web.forms.Input):

    def __init__(self, name='search_attrs', text=u'Attributes to be read'):
        web2ldap.web.forms.Input.__init__(self, name, text, 1000, 1, ur'[@*+0-9.\w,_;-]+')

    def setValue(self, value):
        value = ','.join(
            filter(
                None,
                map(
                    str.strip,
                    value.replace(' ', ',').split(',')
                )
            )
        )
        web2ldap.web.forms.Input.setValue(self, value)


class Web2LDAPForm_searchform(Web2LDAPForm):
    command = 'searchform'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(web2ldap.web.forms.Input('search_submit', u'Search form submit button', 6, 1, '(Search|[+-][0-9]+)'))
        self.addField(web2ldap.web.forms.Select('searchform_mode', u'Search form mode', 1, options=[(u'base', u'Base'), (u'adv', u'Advanced'), (u'exp', u'Expert')], default=u'base'))
        self.addField(DistinguishedNameInput('search_root', 'Search root'))
        self.addField(web2ldap.web.forms.Input(
            'filterstr',
            u'Search filter string',
            1200,
            1,
            '.*',
            size=90,
        ))
        self.addField(
            web2ldap.web.forms.Input(
                'searchform_template',
                u'Search form template name',
                60,
                web2ldapcnf.max_searchparams,
                u'[a-zA-Z0-9. ()_-]+',
            )
        )
        self.addField(
            web2ldap.web.forms.Select(
                'search_resnumber', u'Number of results to display', 1,
                options=[
                    (u'0', u'unlimited'), (u'10', u'10'), (u'20', u'20'),
                    (u'50', u'50'), (u'100', u'100'), (u'200', u'200'),
                ],
                default=u'10'
            )
        )
        self.addField(
            web2ldap.web.forms.Select(
                'search_lastmod', u'Interval of last creation/modification', 1,
                options=[
                    (u'-1', u'-'),
                    (u'10', u'10 sec.'),
                    (u'60', u'1 min.'),
                    (u'600', u'10 min.'),
                    (u'3600', u'1 hour'),
                    (u'14400', u'4 hours'),
                    (u'43200', u'12 hours'),
                    (u'86400', u'24 hours'),
                    (u'172800', u'2 days'),
                    (u'604800', u'1 week'),
                    (u'2419200', u'4 weeks'),
                    (u'6048000', u'10 weeks'),
                    (u'31536000', u'1 year'),
                ],
                default=u'-1'
            )
        )
        self.addField(InclOpAttrsCheckbox('search_opattrs', u'Request operational attributes', default=u'yes', checked=0))
        self.addField(web2ldap.web.forms.Select('search_mode', u'Search Mode', 1, options=[ur'(&%s)', ur'(|%s)']))
        self.addField(web2ldap.web.forms.Input('search_attr', u'Attribute(s) to be searched', 100, web2ldapcnf.max_searchparams, ur'[\w,_;-]+'))
        self.addField(web2ldap.web.forms.Input('search_mr', u'Matching Rule', 100, web2ldapcnf.max_searchparams, ur'[\w,_;-]+'))
        self.addField(web2ldap.web.forms.Select('search_option', u'Search option', web2ldapcnf.max_searchparams, options=web2ldap.app.searchform.search_options))
        self.addField(web2ldap.web.forms.Input('search_string', u'Search string', 600, web2ldapcnf.max_searchparams, u'.*', size=60))
        self.addField(SearchAttrs())
        self.addField(ExportFormatSelect('search_output'))


class Web2LDAPForm_search(Web2LDAPForm_searchform):
    command = 'search'

    def _add_fields(self):
        Web2LDAPForm_searchform._add_fields(self)
        self.addField(
            web2ldap.web.forms.Input(
                'search_resminindex',
                u'Minimum index of search results',
                10, 1,
                u'[0-9]+',
            )
        )
        self.addField(
            web2ldap.web.forms.Input(
                'search_resnumber',
                u'Number of results to display',
                3, 1,
                u'[0-9]+',
            )
        )


class Web2LDAPForm_conninfo(Web2LDAPForm):
    command = 'conninfo'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(
            web2ldap.web.forms.Select(
                'conninfo_flushcaches',
                u'Flush caches',
                1,
                options=(u'0', u'1'),
                default=u'0',
            )
        )

class Web2LDAPForm_ldapparams(Web2LDAPForm):
    command = 'ldapparams'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(
            web2ldap.web.forms.Select(
                'ldapparam_all_controls',
                u'List all controls',
                1,
                options=(u'0', u'1'),
                default=u'0',
            )
        )
        self.addField(
            web2ldap.web.forms.Input(
                'ldapparam_enable_control',
                u'Enable LDAPv3 Boolean Control',
                50, 1,
                u'([0-9]+.)*[0-9]+',
            )
        )
        self.addField(
            web2ldap.web.forms.Input(
                'ldapparam_disable_control',
                u'Disable LDAPv3 Boolean Control',
                50, 1,
                u'([0-9]+.)*[0-9]+',
            )
        )
        self.addField(
            web2ldap.web.forms.Select(
                'ldap_deref',
                u'Dereference aliases',
                maxValues=1,
                default=unicode(ldap0.DEREF_NEVER),
                options=[
                    (unicode(ldap0.DEREF_NEVER), u'never'),
                    (unicode(ldap0.DEREF_SEARCHING), u'searching'),
                    (unicode(ldap0.DEREF_FINDING), u'finding'),
                    (unicode(ldap0.DEREF_ALWAYS), u'always'),
                ]
            )
        )


class AttributeValueInput(web2ldap.web.forms.Input):
    def _encodeValue(self, value):
        return value


class Web2LDAPForm_input(Web2LDAPForm):

    """Base class for entry data input not directly used"""
    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(web2ldap.web.forms.Input('in_oc', u'Object classes', 60, 40, u'[a-zA-Z0-9.-]+'))
        self.addField(web2ldap.web.forms.Select('in_ft', u'Type of input form', 1, options=[u'Template', u'Table', u'LDIF', u'OC'], default=u'Template'))
        self.addField(web2ldap.web.forms.Input(
            'in_mr',
            u'Add/del row',
            8, 1,
            '(Template|Table|LDIF|[+-][0-9]+)',
        ))
        self.addField(web2ldap.web.forms.Select('in_oft', u'Type of input form', 1, options=[u'Template', u'Table', u'LDIF'], default=u'Template'))
        self.addField(AttributeType('in_at', u'Attribute type', web2ldapcnf.input_maxattrs))
        self.addField(AttributeType('in_avi', u'Value index', web2ldapcnf.input_maxattrs))
        self.addField(
            AttributeValueInput(
                'in_av', u'Attribute Value',
                web2ldapcnf.input_maxfieldlen,
                web2ldapcnf.input_maxattrs,
                ('.*', re.U|re.M|re.S)
            )
        )
        self.addField(LDIFTextArea('in_ldif', u'LDIF data'))


class Web2LDAPForm_add(Web2LDAPForm_input):
    command = 'add'

    def _add_fields(self):
        Web2LDAPForm_input._add_fields(self)
        self.addField(web2ldap.web.forms.Input('add_rdn', u'RDN of new entry', 255, 1, u'.*', size=50))
        self.addField(DistinguishedNameInput('add_clonedn', u'DN of template entry'))
        self.addField(web2ldap.web.forms.Input('add_template', u'LDIF template name', 60, web2ldapcnf.max_searchparams, u'.+'))
        self.addField(web2ldap.web.forms.Input('add_basedn', u'Base DN of new entry', 1024, 1, u'.*', size=50))
        self.addField(web2ldap.web.forms.Select(
            'in_ocf', u'Object class form mode', 1,
            options=[
                (u'tmpl', u'LDIF templates'),
                (u'exp', u'Object class selection')
            ],
            default=u'tmpl'
        ))


class Web2LDAPForm_modify(Web2LDAPForm_input):
    command = 'modify'

    def _add_fields(self):
        Web2LDAPForm_input._add_fields(self)
        self.addField(AttributeType('in_oldattrtypes', u'Old attribute types', web2ldapcnf.input_maxattrs))
        self.addField(AttributeType('in_wrtattroids', u'Writeable attribute types', web2ldapcnf.input_maxattrs))
        self.addField(web2ldap.web.forms.Input('in_assertion', u'Assertion filter string', 2000, 1, '.*', required=False))


class Web2LDAPForm_dds(Web2LDAPForm):
    command = 'dds'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(web2ldap.web.forms.Input('dds_renewttlnum', u'Request TTL number', 12, 1, '[0-9]+', default=None))
        self.addField(web2ldap.web.forms.Select(
            'dds_renewttlfac',
            u'Request TTL factor',
            1,
            options=(
                (u'1', u'seconds'),
                (u'60', u'minutes'),
                (u'3600', u'hours'),
                (u'86400', u'days'),
            ),
            default=u'1'
        ))


class Web2LDAPForm_bulkmod(Web2LDAPForm):
    command = 'bulkmod'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(web2ldap.web.forms.Input('bulkmod_submit', u'Search form submit button', 6, 1, u'(Next>>|<<Back|Apply|Cancel|[+-][0-9]+)'))
        bulkmod_ctrl_options = [
            (control_oid, OID_REG.get(control_oid, (control_oid,))[0])
            for control_oid, control_spec in web2ldap.app.ldapparams.AVAILABLE_BOOLEAN_CONTROLS.items()
            if '**all**' in control_spec[0] or '**write**' in control_spec[0] or 'modify' in control_spec[0]
        ]
        self.addField(
            web2ldap.web.forms.Select(
                'bulkmod_ctrl',
                u'Extended controls',
                len(bulkmod_ctrl_options),
                options=bulkmod_ctrl_options,
                default=None,
                size=min(8, len(bulkmod_ctrl_options)),
                multiSelect=1,
            )
        )
        self.addField(web2ldap.web.forms.Input('filterstr', u'Search filter string for searching entries to be deleted', 1200, 1, '.*'))
        self.addField(web2ldap.web.forms.Input(
            'bulkmod_modrow',
            u'Add/del row',
            8, 1,
            '(Template|Table|LDIF|[+-][0-9]+)',
        ))
        self.addField(AttributeType('bulkmod_at', u'Attribute type', web2ldapcnf.input_maxattrs))
        self.addField(
            web2ldap.web.forms.Select(
                'bulkmod_op',
                u'Modification type',
                web2ldapcnf.input_maxattrs,
                options=(
                    (u'', u''),
                    (unicode(ldap0.MOD_ADD), u'add'),
                    (unicode(ldap0.MOD_DELETE), u'delete'),
                    (unicode(ldap0.MOD_REPLACE), u'replace'),
                    (unicode(ldap0.MOD_INCREMENT), u'increment'),
                ),
                default=None,
            )
        )
        self.addField(
            AttributeValueInput(
                'bulkmod_av', u'Attribute Value',
                web2ldapcnf.input_maxfieldlen,
                web2ldapcnf.input_maxattrs,
                ('.*', re.U|re.M|re.S),
                size=30,
            )
        )
        self.addField(DistinguishedNameInput('bulkmod_newsuperior', u'New superior DN'))
        self.addField(web2ldap.web.forms.Checkbox('bulkmod_cp', u'Copy entries', 1, default=u'yes', checked=0))


class Web2LDAPForm_delete(Web2LDAPForm):
    command = 'delete'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(web2ldap.web.forms.Select('delete_confirm', u'Confirmation', 1, options=['yes', 'no'], default=u'no'))
        delete_ctrl_options = [
            (control_oid, OID_REG.get(control_oid, (control_oid,))[0])
            for control_oid, control_spec in web2ldap.app.ldapparams.AVAILABLE_BOOLEAN_CONTROLS.items()
            if '**all**' in control_spec[0] or '**write**' in control_spec[0] or 'delete' in control_spec[0]
        ]
        delete_ctrl_options.append((web2ldap.ldapsession.CONTROL_TREEDELETE, u'Tree Deletion'))
        self.addField(
            web2ldap.web.forms.Select(
                'delete_ctrl',
                u'Extended controls',
                len(delete_ctrl_options),
                options=delete_ctrl_options,
                default=None,
                size=min(8, len(delete_ctrl_options)),
                multiSelect=1,
            )
        )
        self.addField(web2ldap.web.forms.Input('filterstr', u'Search filter string for searching entries to be deleted', 1200, 1, '.*'))
        self.addField(web2ldap.web.forms.Input('delete_attr', u'Attribute to be deleted', 255, 100, ur'[\w_;-]+'))


class Web2LDAPForm_rename(Web2LDAPForm):
    command = 'rename'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(web2ldap.web.forms.Input('rename_newrdn', u'New RDN', 255, 1, web2ldap.ldaputil.base.rdn_pattern, size=50))
        self.addField(DistinguishedNameInput('rename_newsuperior', u'New superior DN'))
        self.addField(web2ldap.web.forms.Checkbox('rename_delold', u'Delete old', 1, default=u'yes', checked=1))
        self.addField(
            web2ldap.web.forms.Input(
                'rename_newsupfilter',
                u'Filter string for searching new superior entry', 300, 1, '.*',
                default=u'(|(objectClass=organization)(objectClass=organizationalUnit))',
                size=50,
            )
        )
        self.addField(DistinguishedNameInput('rename_searchroot', u'Search root under which to look for new superior entry.'))
        self.addField(web2ldap.web.forms.Input('rename_supsearchurl', u'LDAP URL for searching new superior entry', 100, 1, '.*', size=30))


class Web2LDAPForm_passwd(Web2LDAPForm):
    command = 'passwd'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        for field in web2ldap.app.passwd.passwd_fields():
            self.addField(field)


class Web2LDAPForm_read(Web2LDAPForm):
    command = 'read'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(web2ldap.web.forms.Input('filterstr', u'Search filter string when reading single entry', 1200, 1, '.*'))
        self.addField(web2ldap.web.forms.Select('read_nocache', u'Force fresh read', 1, options=[u'0', u'1'], default=u"0"))
        self.addField(web2ldap.web.forms.Input('read_attr', u'Read attribute', 255, 100, ur'[\w_;-]+'))
        self.addField(web2ldap.web.forms.Select('read_attrmode', u'Read attribute', 1, options=[u'view', u'load']))
        self.addField(web2ldap.web.forms.Input('read_attrindex', u'Read attribute', 255, 1, u'[0-9]+'))
        self.addField(web2ldap.web.forms.Input('read_attrmimetype', u'MIME type', 255, 1, ur'[\w.-]+/[\w.-]+'))
        self.addField(web2ldap.web.forms.Select('read_output', u'Read output format', 1, options=[u'table', u'vcard', u'template'], default=u'template'))
        self.addField(SearchAttrs())
        self.addField(web2ldap.web.forms.Input('read_expandattr', u'Attributes to be read', 1000, 1, ur'[*+\w,_;-]+'))


class Web2LDAPForm_groupadm(Web2LDAPForm):
    command = 'groupadm'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(DistinguishedNameInput('groupadm_searchroot', u'Group search root'))
        self.addField(web2ldap.web.forms.Input('groupadm_name', u'Group name', 100, 1, u'.*', size=30))
        self.addField(DistinguishedNameInput('groupadm_add', u'Add to group', 300))
        self.addField(DistinguishedNameInput('groupadm_remove', u'Remove from group', 300))
        self.addField(
            web2ldap.web.forms.Select(
                'groupadm_view',
                u'Group list view',
                1,
                options=[('0', 'none of the'), ('1', 'only member'), ('2', 'all')],
                default=u'1',
            )
        )


class Web2LDAPForm_login(Web2LDAPForm):
    command = 'login'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(DistinguishedNameInput('login_who', u'Bind DN'))


class Web2LDAPForm_locate(Web2LDAPForm):
    command = 'locate'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(
            web2ldap.web.forms.Input('locate_name', u'Location name', 500, 1, u'.*', size=25)
        )


class Web2LDAPForm_oid(Web2LDAPForm):
    command = 'oid'

    def _add_fields(self):
        Web2LDAPForm._add_fields(self)
        self.addField(OIDInput('oid', u'OID'))
        self.addField(
            web2ldap.web.forms.Select(
                'oid_class',
                u'Schema element class',
                1,
                options=ldap0.schema.SCHEMA_ATTRS,
                default=u'',
            )
        )


class Web2LDAPForm_dit(Web2LDAPForm):
    command = 'dit'


class DistinguishedNameInput(web2ldap.web.forms.Input):
    """Input field class for LDAP DNs."""

    def __init__(self, name='dn', text='DN', maxValues=1, required=False, default=u''):
        web2ldap.web.forms.Input.__init__(
            self, name, text, 1024, maxValues, '',
            size=70, required=required, default=default
        )

    def _validateFormat(self, value):
        if value and not web2ldap.ldaputil.base.is_dn(value):
            raise web2ldap.web.forms.InvalidValueFormat(
                self.name,
                self.text.encode(self.charset),
                value.encode(self.charset)
            )


class LDIFTextArea(web2ldap.web.forms.Textarea):
    """A single multi-line input field for LDIF data"""

    def __init__(
            self,
            name='in_ldif',
            text='LDIF data',
            required=False,
            max_entries=1
        ):
        web2ldap.web.forms.Textarea.__init__(
            self,
            name,
            text,
            web2ldapcnf.ldif_maxbytes,
            1,
            '^.*$',
            required=required,
        )
        self._max_entries = max_entries
        self.allRecords = []

    def getLDIFRecords(self):
        if self.value:
            return list(
                ldap0.ldif.LDIFParser.fromstring(
                    '\n'.join(self.value).encode(self.charset),
                    ignored_attr_types=[],
                    process_url_schemes=web2ldapcnf.ldif_url_schemes
                ).parse(max_entries=self._max_entries)
            )
        return []


class OIDInput(web2ldap.web.forms.Input):

    def __init__(self, name, text, default=None):
        web2ldap.web.forms.Input.__init__(
            self, name, text,
            512, 1, u'[a-zA-Z0-9_.;*-]+',
            default=default,
            required=False,
            size=30,
        )


class ObjectClassSelect(web2ldap.web.forms.Select):
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
        web2ldap.web.forms.Select.__init__(
            self,
            name, text,
            maxValues=200,
            required=required,
            options=select_options,
            default=select_default,
            accessKey=accesskey,
            size=size,
            ignoreCase=1,
            multiSelect=1
        )
        self.setRegex(ur'[\w]+')
        self.maxLen = 200
        return # end of ObjectClassSelect()


class DateTime(web2ldap.web.forms.Input):
    """
    <input type="datetime"> and friends
    """

    def __init__(
            self,
            name,
            text,
            maxLen,
            maxValues,
            pattern,
            required=False,
            default=None,
            accessKey='',
            inputType='datetime',
            step='60',
        ):
        self.inputType = inputType
        self.size = maxLen
        self.step = step
        web2ldap.web.forms.Input.__init__(
            self, name, text, maxLen, maxValues, pattern, required, default, accessKey,
        )

    def inputHTML(self, default=None, id_value=None, title=None):
        return self.inputHTMLTemplate % (
            '<input type="%s" %stitle="%s" name="%s" %s maxlength="%d" size="%d" step="%d" value="%s">' % (
                self.inputType,
                self.idAttrStr(id_value),
                self.titleHTML(title),
                self.name,
                self._accessKeyAttr(),
                self.maxLen,
                self.size,
                self.step,
                self._defaultHTML(default),
            )
        )


class ExportFormatSelect(web2ldap.web.forms.Select):
    """Select field class for choosing export format"""

    def __init__(
            self,
            name='search_output',
            text=u'Export format',
            options=None,
            default=u'ldif1',
            required=False,
        ):
        default_options = [
            (u'table', u'Table/template'),
            (u'raw', u'Raw DN list'),
            (u'print', u'Printable'),
            (u'ldif', u'LDIF (Umich)'),
            (u'ldif1', u'LDIFv1 (RFC2849)'),
            (u'csv', u'CSV'),
            (u'excel', u'Excel'),
        ]
        web2ldap.web.forms.Select.__init__(
            self,
            name, text, 1,
            options=options or default_options,
            default=default,
            required=required,
            size=1,
        )


class AttributeType(web2ldap.web.forms.Input):

    def __init__(self, name, text, maxValues):
        web2ldap.web.forms.Input.__init__(
            self,
            name,
            text,
            500,
            maxValues,
            web2ldap.ldaputil.base.attr_type_pattern,
            required=False,
            size=30
        )


class InclOpAttrsCheckbox(web2ldap.web.forms.Checkbox):

    def __init__(self, name, text, default=u'yes', checked=0):
        web2ldap.web.forms.Checkbox.__init__(self, name, text, 1, default=default, checked=checked)


class AuthMechSelect(web2ldap.web.forms.Select):
    """Select field class for choosing the bind mech"""

    supported_bind_mechs = {
        u'': u'Simple Bind',
        u'DIGEST-MD5': u'SASL Bind: DIGEST-MD5',
        u'CRAM-MD5': u'SASL Bind: CRAM-MD5',
        u'PLAIN': u'SASL Bind: PLAIN',
        u'LOGIN': u'SASL Bind: LOGIN',
        u'GSSAPI': u'SASL Bind: GSSAPI',
        u'EXTERNAL': u'SASL Bind: EXTERNAL',
        u'OTP': u'SASL Bind: OTP',
        u'NTLM': u'SASL Bind: NTLM',
        u'SCRAM-SHA-1': u'SASL Bind: SCRAM-SHA-1',
        u'SCRAM-SHA-256': u'SASL Bind: SCRAM-SHA-256',
    }

    def __init__(
            self,
            name='login_mech',
            text=u'Authentication mechanism',
            default=None,
            required=False,
            accesskey='',
            size=1,
        ):
        web2ldap.web.forms.Select.__init__(
            self,
            name, text, maxValues=1,
            required=required,
            options=None,
            default=default or [],
            accessKey=accesskey,
            size=size,
            ignoreCase=0,
            multiSelect=0
        )

    def setOptions(self, options):
        options_dict = {}
        options_dict[u''] = self.supported_bind_mechs[u'']
        for o in options or self.supported_bind_mechs.keys():
            o_upper = o.upper()
            if self.supported_bind_mechs.has_key(o_upper):
                options_dict[o_upper] = self.supported_bind_mechs[o_upper]
        web2ldap.web.forms.Select.setOptions(self, options_dict.items())
