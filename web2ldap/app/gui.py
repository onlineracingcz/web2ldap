# -*- coding: utf-8 -*-
"""
web2ldap.app.gui: basic functions for GUI elements

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time
import os
from hashlib import md5

import ldap0
import ldap0.ldapurl
from ldap0.ldapurl import LDAPUrl
from ldap0.filter import escape_filter_chars

import web2ldapcnf

import web2ldap.web.forms
from web2ldap.web import escape_html
import web2ldap.__about__
import web2ldap.ldaputil
import web2ldap.msbase
import web2ldap.app.core
import web2ldap.app.cnf
import web2ldap.app.schema.syntaxes
import web2ldap.app.searchform
from web2ldap.msbase import GrabKeys
import web2ldap.ldaputil.base
from web2ldap.ldaputil.base import \
    explode_dn, logdb_filter


#---------------------------------------------------------------------------
# Constants
#---------------------------------------------------------------------------

host_pattern = r'[a-zA-Z0-9_.:\[\]-]+'

HIDDEN_FIELD = '<input type="hidden" name="%s" value="%s">%s\n'

HTML_FOOTER = """
  <p class="ScrollLink">
    <a href="#web2ldap_top">&uarr; TOP</a>
  </p>
  <a id="web2ldap_bottom"></a>
</div>
<div id="Footer">
  <footer>
  </footer>
</div>
</body>
</html>
"""


def GetVariantFilename(pathname, variantlist):
    """
    returns variant filename
    """
    checked_set = set()
    for v in variantlist:
        # Strip subtags
        v = v.lower().split('-', 1)[0]
        if v == 'en':
            variant_filename = pathname
        else:
            variant_filename = '.'.join((pathname, v))
        if not v in checked_set and os.path.isfile(variant_filename):
            break
        else:
            checked_set.add(v)
    else:
        variant_filename = pathname
    return variant_filename


def ReadTemplate(app, config_key, form_desc=u'', tmpl_filename=None):
    if not tmpl_filename:
        tmpl_filename = app.cfg_param(config_key, None)
    if not tmpl_filename:
        raise web2ldap.app.core.ErrorExit(u'No template specified for %s.' % (form_desc))
    tmpl_filename = web2ldap.app.gui.GetVariantFilename(tmpl_filename, app.form.accept_language)
    try:
        # Read template from file
        tmpl_str = open(tmpl_filename, 'r').read()
    except IOError:
        raise web2ldap.app.core.ErrorExit(u'I/O error during reading %s template file.' % (form_desc))
    return tmpl_str # ReadTemplate()


def dn_anchor_hash(dn):
    return unicode(md5(dn.strip().lower().encode('utf-8')).hexdigest())


def ts2repr(time_divisors, ts_sep, ts_value):
    rest = long(ts_value)
    result = []
    for desc, divisor in time_divisors:
        mult = rest / divisor
        rest = rest % divisor
        if mult > 0:
            result.append(u'%d %s' % (mult, desc))
        if rest == 0:
            break
    return ts_sep.join(result)


def repr2ts(time_divisors, ts_sep, value):
    l1 = [v.strip().split(u' ') for v in value.split(ts_sep)]
    l2 = [(int(v), d.strip()) for v, d in l1]
    time_divisors_dict = dict(time_divisors)
    result = 0
    for value, desc in l2:
        try:
            result += value*time_divisors_dict[desc]
        except KeyError:
            raise ValueError
        else:
            del time_divisors_dict[desc]
    return result


def DisplayDN(app, dn, commandbutton=False):
    """Display a DN as LDAP URL with or without button"""
    assert isinstance(dn, unicode), TypeError("Argument 'dn' must be unicode, was %r" % (dn))
    dn_str = app.form.utf2display(dn or u'- World -')
    if commandbutton:
        command_buttons = [
            dn_str,
            app.anchor('read', 'Read', [('dn', dn)])
        ]
        return web2ldapcnf.command_link_separator.join(command_buttons)
    return dn_str


def command_div(
        commandlist,
        div_id='CommandDiv',
        separator=' ',
        semantic_tag='nav',
    ):
    if semantic_tag:
        start_tag = '<%s>' % semantic_tag
        end_tag = '<%s>' % semantic_tag
    else:
        start_tag = ''
        end_tag = ''
    if commandlist:
        return '%s<p id="%s" class="CommandTable">\n%s\n</p>%s\n' % (
            start_tag,
            div_id,
            (separator).join(commandlist),
            end_tag,
        )
    return '' # command_div()


def simple_main_menu(app):
    main_menu = [app.anchor('', 'Connect', [])]
    if web2ldap.app.handler.check_access(app.env, 'monitor'):
        main_menu.append(app.anchor('monitor', 'Monitor', []))
    if web2ldap.app.handler.check_access(app.env, 'locate'):
        main_menu.append(app.anchor('locate', 'DNS lookup', []))
    return main_menu


def ContextMenuSingleEntry(app, vcard_link=0, dds_link=0, entry_uuid=None):
    """
    Output the context menu for a single entry
    """
    dn_disp = app.dn or u'Root DSE'
    result = [
        app.anchor(
            'read', 'Raw',
            [
                ('dn', app.dn),
                ('read_output', 'table'),
                ('read_expandattr', '*')
            ],
            title=u'Display entry\r\n%s\r\nas raw attribute type/value list' % (dn_disp)
        ),
    ]
    if app.dn:
        ldap_url_obj = app.ls.ldapUrl('', add_login=False)
        result.extend([
            app.anchor(
                'login', 'Bind as',
                [
                    ('ldapurl', str(ldap_url_obj).decode('ascii')),
                    ('dn', app.dn),
                    ('login_who', app.dn),
                ],
                title=u'Connect and bind new session as\r\n%s' % (app.dn)
            ),
            app.anchor('modify', 'Modify', [('dn', app.dn)], title=u'Modify entry\r\n%s' % (app.dn)),
            app.anchor('rename', 'Rename', [('dn', app.dn)], title=u'Rename/move entry\r\n%s' % (app.dn)),
            app.anchor('delete', 'Delete', [('dn', app.dn)], title=u'Delete entry and/or subtree\r\n%s' % (app.dn)),
            app.anchor('passwd', 'Password', [('dn', app.dn), ('passwd_who', app.dn)], title=u'Set password for entry\r\n%s' % (app.dn)),
            app.anchor('groupadm', 'Groups', [('dn', app.dn)], title=u'Change group membership of entry\r\n%s' % (app.dn)),
            app.anchor(
                'add', 'Clone',
                [
                    ('dn', app.parent_dn),
                    ('add_clonedn', app.dn),
                    ('in_ft', u'Template'),
                ],
                title=u'Clone entry\r\n%s\r\nbeneath %s' % (app.dn, app.parent_dn)
            ),
        ])

    if vcard_link:
        result.append(
            app.anchor(
                'read', 'vCard',
                [('dn', app.dn), ('read_output', 'vcard')],
                title=u'Export entry\r\n%s\r\nas vCard' % (dn_disp)
            )
        )

    if dds_link:
        result.append(
            app.anchor(
                'dds', 'Refresh',
                [('dn', app.dn)],
                title=u'Refresh dynamic entry %s' % (dn_disp)
            )
        )

    if app.audit_context:
        accesslog_any_filterstr = logdb_filter(u'auditObject', app.dn, entry_uuid)
        accesslog_write_filterstr = logdb_filter(u'auditWriteObject', app.dn, entry_uuid)
        result.extend([
            app.anchor(
                'search', 'Audit access',
                [
                    ('dn', app.audit_context),
                    ('filterstr', accesslog_any_filterstr),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title=u'Complete audit trail for entry\r\n%s' % (app.dn),
            ),
            app.anchor(
                'search', 'Audit writes',
                [
                    ('dn', app.audit_context),
                    ('filterstr', accesslog_write_filterstr),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title=u'Audit trail of write access to entry\r\n%s' % (app.dn),
            ),
        ])

    try:
        changelog_dn = app.ls.rootDSE['changelog'][0].decode(app.ls.charset)
    except KeyError:
        pass
    else:
        changelog_filterstr = logdb_filter(u'changeLogEntry', app.dn, entry_uuid)
        result.append(
            app.anchor(
                'search', 'Change log',
                [
                    ('dn', changelog_dn),
                    ('filterstr', changelog_filterstr),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title=u'Audit trail of write access to current entry',
            )
        )

    try:
        monitor_context_dn = app.ls.rootDSE['monitorContext'][0]
    except KeyError:
        pass
    else:
        result.append(app.anchor(
            'search', 'User conns',
            [
                ('dn', monitor_context_dn),
                (
                    'filterstr',
                    '(&(objectClass=monitorConnection)(monitorConnectionAuthzDN=%s))' % (
                        escape_filter_chars(app.dn),
                    ),
                ),
                ('scope', str(ldap0.SCOPE_SUBTREE)),
            ],
            title=u'Find connections of this user in monitor database',
        ))

    return result # ContextMenuSingleEntry()


def WhoAmITemplate(app, who=None, entry=None):
    if who is None:
        if hasattr(app.ls, 'who') and app.ls.who:
            who = app.ls.who
            entry = app.ls.userEntry
        else:
            return 'anonymous'
    if web2ldap.ldaputil.base.is_dn(who):
        # Fall-back is to display the DN
        result = DisplayDN(app, who, commandbutton=False)
        # Determine relevant templates dict
        bound_as_templates = ldap0.cidict.cidict(app.cfg_param('boundas_template', {}))
        # Read entry if necessary
        if entry is None:
            read_attrs = set(['objectClass'])
            for oc in bound_as_templates.keys():
                read_attrs.update(GrabKeys(bound_as_templates[oc]).keys)
            try:
                entry = app.ls.l.read_s(who.encode(app.ls.charset), attrlist=list(read_attrs))
            except ldap0.LDAPError:
                entry = None
        if entry:
            display_entry = web2ldap.app.read.DisplayEntry(app, app.dn, app.schema, entry, 'readSep', True)
            user_structural_oc = display_entry.entry.get_structural_oc()
            for oc in bound_as_templates.keys():
                if app.schema.getoid(ldap0.schema.models.ObjectClass, oc) == user_structural_oc:
                    try:
                        result = bound_as_templates[oc] % display_entry
                    except KeyError:
                        pass
    else:
        result = app.form.utf2display(who)
    return result # WhoAmITemplate()



def main_menu(app):
    """
    Returns list of main menu items
    """
    cl = []

    if app.ls is not None and app.ls.uri is not None:

        if app.dn:
            cl.append(
                app.anchor(
                    'search', 'Up',
                    (
                        ('dn', app.parent_dn),
                        ('scope', web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
                        ('searchform_mode', u'adv'),
                        ('search_attr', u'objectClass'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS),
                        ('search_string', ''),
                    ),
                    title=u'List direct subordinates of %s' % (app.parent_dn or u'Root DSE'),
                )
            )

        cl.extend((
            app.anchor(
                'search', 'Down',
                (
                    ('dn', app.dn),
                    ('scope', web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
                    ('searchform_mode', u'adv'),
                    ('search_attr', u'objectClass'),
                    ('search_option', web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS),
                    ('search_string', u''),
                ),
                title=u'List direct subordinates of %s' % (app.dn or u'Root DSE'),
            ),
            app.anchor(
                'searchform', 'Search',
                (('dn', app.dn),),
                title=u'Enter search criteria in input form',
            ),
        ))

        cl.append(
            app.anchor(
                'dit', 'Tree',
                [('dn', app.dn)],
                title=u'Display tree around %s' % (app.dn or u'Root DSE'),
                anchor_id=dn_anchor_hash(app.dn)
            ),
        )

        cl.append(
            app.anchor(
                'read', 'Read',
                [('dn', app.dn), ('read_nocache', u'1')],
                title=u'Display entry %s' % (app.dn or u'Root DSE'),
            ),
        )

        cl.extend((
            app.anchor(
                'add', 'New entry',
                [('dn', app.dn)],
                title=u'Add a new entry below of %s' % (app.dn or u'Root DSE')
            ),
            app.anchor('conninfo', 'ConnInfo', [('dn', app.dn)], title=u'Show information about HTTP and LDAP connections'),
            app.anchor('ldapparams', 'Params', [('dn', app.dn)], title=u'Tweak parameters used for LDAP operations (controls etc.)'),
            app.anchor('login', 'Bind', [('dn', app.dn)], title=u'Login to directory'),
            app.anchor('oid', 'Schema', [('dn', app.dn)], title=u'Browse/view subschema'),
        ))

        cl.append(app.anchor('disconnect', 'Disconnect', [], title=u'Disconnect from LDAP server'))

    else:

        cl.append(app.anchor('', 'Connect', None, [], title=u'New connection to LDAP server'))

    return cl # main_menu()


def DITNavigationList(app):
    dn_list = explode_dn(app.dn)
    result = [
        app.anchor(
            'read',
            app.form.utf2display(dn_list[i] or '[Root DSE]'),
            [('dn', ','.join(dn_list[i:]))],
            title=u'Jump to %s' % (u','.join(dn_list[i:])),
        )
        for i in range(len(dn_list))
    ]
    result.append(
        app.anchor(
            'read', '[Root DSE]',
            [('dn', '')],
            title=u'Jump to root DSE',
        )
    )
    return result # DITNavigationList()


def TopSection(
        app,
        title,
        main_menu_list,
        context_menu_list=[],
        main_div_id='Message',
    ):

    # First send the HTTP header
    Header(app, 'text/html', app.form.accept_charset)

    # Read the template file for TopSection
    top_template_str = web2ldap.app.gui.ReadTemplate(app, 'top_template', u'top section')

    script_name = escape_html(app.form.script_name)

    template_dict = {
        'main_div_id': main_div_id,
        'accept_charset': app.form.accept_charset,
        'refresh_time': str(web2ldapcnf.session_remove+10),
        'sid': app.sid or '',
        'title_text': title,
        'script_name': script_name,
        'web2ldap_version': escape_html(web2ldap.__about__.__version__),
        'command': app.command,
        'ldap_url': '',
        'ldap_uri': '-/-',
        'description': '',
        'who': '-/-',
        'dn': '-/-',
        'dit_navi': '-/-',
        'main_menu': command_div(main_menu_list, div_id='MainMenu', separator='\n', semantic_tag=None),
        'context_menu': command_div(context_menu_list, div_id='ContextMenu', separator='\n', semantic_tag=None),
    }
    template_dict.update([(k, escape_html(str(v))) for k, v in app.env.items()])

    if app.ls is not None and app.ls.uri is not None:

        # Only output something meaningful if valid connection
        template_dict.update({
            'ldap_url': app.ls.ldapUrl(app.dn),
            'ldap_uri': app.form.utf2display(app.ls.uri.decode('ascii')),
            'description': escape_html(app.cfg_param('description', u'').encode(app.form.accept_charset)),
            'dit_navi': ',\n'.join(DITNavigationList(app)),
            'dn': app.form.utf2display(app.dn),
        })
        template_dict['who'] = WhoAmITemplate(app)

    app.outf.write(top_template_str.format(**template_dict))

    return # TopSection()


def SimpleMessage(
        app,
        title=u'',
        message=u'',
        main_div_id='Message',
        main_menu_list=[],
        context_menu_list=[],
    ):
    TopSection(
        app,
        title,
        main_menu_list,
        context_menu_list=context_menu_list,
        main_div_id=main_div_id,
    )
    app.outf.write(message)
    web2ldap.app.gui.Footer(app)
    return # SimpleMessage()


def SchemaElementName(
        app,
        schema,
        se_nameoroid,
        se_class,
        name_template=r'%s',
    ):
    """
    Return a pretty HTML-formatted string describing a schema element
    referenced by name or OID
    """
    result = [name_template % (se_nameoroid.encode())]
    if se_class:
        se = schema.get_obj(se_class, se_nameoroid, None)
        if not se is None:
            result.append(
                app.anchor(
                    'oid', '&raquo;',
                    [
                        ('dn', app.dn),
                        ('oid', se.oid),
                        ('oid_class', ldap0.schema.SCHEMA_ATTR_MAPPING[se_class]),
                    ]
                )
            )
    return '\n'.join(result)


def LDAPURLButton(app, data):
    if isinstance(data, LDAPUrl):
        l = data
    else:
        l = LDAPUrl(ldapUrl=data)
    command_func = {True:'read', False:'search'}[l.scope == ldap0.SCOPE_BASE]
    if l.hostport:
        command_text = 'Connect'
        return app.anchor(
            command_func,
            'Connect and %s' % (command_func),
            (('ldapurl', str(l).decode('ascii')),)
        )
    command_text = {True:'Read', False:'Search'}[l.scope == ldap0.SCOPE_BASE]
    return app.anchor(
        command_func, command_text,
        [
            ('dn', l.dn.decode(app.form.accept_charset)),
            ('filterstr', (l.filterstr or '(objectClass=*)').decode(app.form.accept_charset)),
            ('scope', unicode(l.scope or ldap0.SCOPE_SUBTREE)),
        ],
    )


def DataStr(
        app,
        dn,
        schema,
        attrtype_name,
        value,
        valueindex=0,
        commandbutton=False,
        entry=None
    ):
    """
    Return a pretty HTML-formatted string of the attribute value
    """
    attr_instance = web2ldap.app.schema.syntaxes.syntax_registry.get_at(
        app, dn, schema, attrtype_name, value, entry,
    )
    try:
        result = attr_instance.displayValue(valueindex, commandbutton)
    except UnicodeError:
        attr_instance = web2ldap.app.schema.syntaxes.OctetString(
            app, dn, schema, attrtype_name, value, entry,
        )
        result = attr_instance.displayValue(valueindex, commandbutton)
    return result


def AttributeTypeSelectField(
        app,
        field_name,
        field_desc,
        attr_list,
        default_attr_options=None
    ):
    """
    Return web2ldap.web.forms.Select instance for choosing attribute type names
    """
    attr_options_dict = {}
    for attr_type in (map(unicode, default_attr_options or []) or app.schema.sed[ldap0.schema.models.AttributeType].keys())+attr_list:
        attr_type_se = app.schema.get_obj(ldap0.schema.models.AttributeType, attr_type)
        if attr_type_se:
            if attr_type_se.names:
                attr_type_name = attr_type_se.names[0].decode(app.ls.charset)
            else:
                attr_type_name = attr_type.decode('ascii')
            if attr_type_se.desc:
                try:
                    attr_type_desc = attr_type_se.desc.decode(app.ls.charset)
                except UnicodeDecodeError:
                    attr_type_desc = repr(attr_type_se.desc).decode('ascii')
            else:
                attr_type_desc = None
        else:
            attr_type_name = attr_type
            attr_type_desc = None
        attr_options_dict[attr_type_name] = (attr_type_name, attr_type_desc)
    sorted_attr_options = [
        (at, attr_options_dict[at][0], attr_options_dict[at][1])
        for at in sorted(attr_options_dict.keys(), key=unicode.lower)
    ]
    # Create a select field instance for attribute type name
    attr_select = web2ldap.web.forms.Select(
        field_name, field_desc, 1,
        options=sorted_attr_options,
    )
    attr_select.setCharset(app.form.accept_charset)
    return attr_select


def gen_headers(content_type, charset, more_headers=None):
    assert isinstance(content_type, bytes), TypeError("Type of argument 'content_type' must be bytes but was %r" % (content_type))
    assert isinstance(charset, bytes), TypeError("Type of argument 'charset' must be bytes but was %r" % (charset))
    # Get current time as GMT (seconds since epoch)
    current_datetime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(time.time()))
    headers = []
    if content_type.startswith('text/'):
        content_type = '%s;charset=%s' % (content_type, charset)
    headers.append(('Content-Type', content_type))
    headers.append(('Date', current_datetime))
    headers.append(('Last-Modified', current_datetime))
    headers.append(('Expires', current_datetime))
    for h, v in web2ldapcnf.http_headers.items():
        headers.append((h, v))
    headers.extend(more_headers or [])
    return headers # Header()


def Header(app, content_type, charset, more_headers=None):
    headers = gen_headers(
        content_type=content_type,
        charset=charset,
        more_headers=more_headers,
    )
    if app.form.next_cookie:
        for _, cookie in app.form.next_cookie.items():
            headers.append(('Set-Cookie', str(cookie)[12:]))
    if app.form.env.get('HTTPS', 'off') == 'on' and \
       'Strict-Transport-Security' not in web2ldapcnf.http_headers:
        headers.append(('Strict-Transport-Security', 'max-age=15768000 ; includeSubDomains'))
    app.outf.set_headers(headers)
    return headers # Header()


def Footer(app):
    app.outf.write(HTML_FOOTER)


def SearchRootField(
        app,
        name='dn',
        text=u'Search Root',
        default=None,
        search_root_searchurl=None,
        naming_contexts=None
    ):
    """Prepare input field for search root"""

    def sortkey_func(d):
        try:
            dn, _ = d
        except ValueError:
            dn = d
        if dn:
            dn_list = web2ldap.ldaputil.base.explode_dn(dn.lower())
            dn_list.reverse()
            return ','.join(dn_list)
        return ''

    if app.dn:
        dn_select_list = [app.dn] + web2ldap.ldaputil.base.parent_dn_list(
            app.dn,
            app.ls.get_search_root(app.dn, naming_contexts=naming_contexts),
        )
    else:
        dn_select_list = []
    dn_select_list = web2ldap.msbase.union(app.ls.namingContexts, dn_select_list)
    if search_root_searchurl:
        slu = ldap0.ldapurl.LDAPUrl(search_root_searchurl.encode(app.ls.charset))
        try:
            ldap_result = app.ls.l.search_s(slu.dn, slu.scope, slu.filterstr, attrlist=['1.1'])
        except ldap0.LDAPError:
            pass
        else:
            dn_select_list = web2ldap.msbase.union(
                [
                    app.ls.uc_decode(ldap_dn)[0]
                    for ldap_dn, _ in ldap_result
                    if ldap_dn is not None
                ],
                dn_select_list,
            )
    dn_select_list.append((u'', u'- World -'))
    dn_select_list = list(set(dn_select_list))
    dn_select_list.sort(key=sortkey_func)
    srf = web2ldap.web.forms.Select(
        name, text, 1,
        size=1,
        default=default or app.naming_context,
        options=dn_select_list,
        ignoreCase=1
    )
    srf.setCharset(app.form.accept_charset)
    return srf # SearchRootField()


def ExceptionMsg(app, Heading, Msg):
    """
    Heading
      Unicode string with text for the <h1> heading
    Msg
      Raw string with HTML with text describing the exception
      (Security note: Must already be quoted/escaped!)
    """
    TopSection(app, 'Error', main_menu(app), context_menu_list=[])
    if isinstance(Msg, unicode):
        Msg = Msg.encode(app.form.accept_charset)
    app.outf.write(
        """
        <h1>{heading}</h1>
        <p class="ErrorMessage">
          {error_msg}
        </p>
        """.format(
            heading=app.form.utf2display(Heading),
            error_msg=Msg,
        )
    )
    Footer(app)
    return # ExceptionMsg()
