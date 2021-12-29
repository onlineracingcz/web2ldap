# -*- coding: ascii -*-
"""
web2ldap.app.gui: basic functions for GUI elements

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(C) 1998-2022 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import re
import time
from hashlib import md5

import ldap0
from ldap0.ldapurl import LDAPUrl
import ldap0.filter
from ldap0.dn import DNObj
from ldap0.res import SearchResultEntry

try:
    import dns
except ImportError:
    DNS_AVAIL = False
else:
    DNS_AVAIL = True

import web2ldapcnf

from ..web.forms import Select as SelectField
from ..__about__ import __version__
from ..web import escape_html
from ..ldaputil import logdb_filter
from .tmpl import read_template


# Sequence of patterns to extract attribute names from LDAP diagnostic messages
EXTRACT_INVALID_ATTR_PATTERNS = (
    # OpenLDAP diagnostic messages
    re.compile(r"(?P<at>[a-zA-Z0-9;-]+): value #(?P<index>[0-9]+) invalid per syntax"),
    re.compile(r"object class '(?P<oc>[a-zA-Z0-9;-]+)' requires attribute '(?P<at>[a-zA-Z0-9;-]+)'"),
)


#---------------------------------------------------------------------------
# Constants
#---------------------------------------------------------------------------

HIDDEN_FIELD = '<input type="hidden" name="%s" value="%s">%s\n'

HTML_OFF_S = {False:'', True:'<!--'}
HTML_OFF_E = {False:'', True:'-->'}

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


def dn_anchor_hash(dn):
    return str(md5(dn.encode('utf-8')).hexdigest())


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
        return '%s<p id="%s" class="CT">\n%s\n</p>%s\n' % (
            start_tag,
            div_id,
            (separator).join(commandlist),
            end_tag,
        )
    return ''
    # end of command_div()


def simple_main_menu(app):
    mil = [app.anchor('', 'Connect', [])]
    if app.check_access('monitor'):
        mil.append(app.anchor('monitor', 'Monitor', []))
    if DNS_AVAIL and app.check_access('locate'):
        mil.append(app.anchor('locate', 'DNS lookup', []))
    return mil


def context_menu_single_entry(app, vcard_link=0, dds_link=0, entry_uuid=None):
    """
    Output the context menu for a single entry
    """
    dn_disp = app.dn or 'Root DSE'
    mil = [
        app.anchor(
            'read', 'Raw',
            [
                ('dn', app.dn),
                ('read_output', 'table'),
                ('read_expandattr', '*')
            ],
            title='Display entry\r\n%s\r\nas raw attribute type/value list' % (dn_disp)
        ),
    ]
    if app.dn:
        ldap_url_obj = app.ls.ldap_url('', add_login=False)
        mil.extend([
            app.anchor(
                'login', 'Bind as',
                [
                    ('ldapurl', str(ldap_url_obj)),
                    ('dn', app.dn),
                    ('login_who', app.dn),
                ],
                title='Connect and bind new session as\r\n%s' % (app.dn)
            ),
            app.anchor(
                'modify', 'Modify',
                [('dn', app.dn)],
                title='Modify entry\r\n%s' % (app.dn)
            ),
            app.anchor(
                'rename', 'Rename',
                [('dn', app.dn)],
                title='Rename/move entry\r\n%s' % (app.dn)
            ),
            app.anchor(
                'delete', 'Delete',
                [('dn', app.dn)],
                title='Delete entry and/or subtree\r\n%s' % (app.dn)
            ),
            app.anchor(
                'passwd', 'Password',
                [('dn', app.dn), ('passwd_who', app.dn)],
                title='Set password for entry\r\n%s' % (app.dn)
            ),
            app.anchor(
                'groupadm', 'Groups',
                [('dn', app.dn)],
                title='Change group membership of entry\r\n%s' % (app.dn)
            ),
            app.anchor(
                'add', 'Clone',
                [
                    ('dn', app.parent_dn),
                    ('add_clonedn', app.dn),
                    ('in_ft', 'Template'),
                ],
                title='Clone entry\r\n%s\r\nbeneath %s' % (app.dn, app.parent_dn)
            ),
        ])

    if vcard_link:
        mil.append(
            app.anchor(
                'read', 'vCard',
                [('dn', app.dn), ('read_output', 'vcard')],
                title='Export entry\r\n%s\r\nas vCard' % (dn_disp)
            )
        )

    if dds_link:
        mil.append(
            app.anchor(
                'dds', 'Refresh',
                [('dn', app.dn)],
                title='Refresh dynamic entry %s' % (dn_disp)
            )
        )

    if app.audit_context:
        accesslog_any_filterstr = logdb_filter('auditObject', app.dn, entry_uuid)
        accesslog_write_filterstr = logdb_filter('auditWriteObject', app.dn, entry_uuid)
        mil.extend([
            app.anchor(
                'search', 'Audit access',
                [
                    ('dn', app.audit_context),
                    ('filterstr', accesslog_any_filterstr),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title='Complete audit trail for entry\r\n%s' % (app.dn),
            ),
            app.anchor(
                'search', 'Audit writes',
                [
                    ('dn', app.audit_context),
                    ('filterstr', accesslog_write_filterstr),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title='Audit trail of write access to entry\r\n%s' % (app.dn),
            ),
        ])

    try:
        changelog_dn = app.ls.root_dse['changelog'][0].decode(app.ls.charset)
    except KeyError:
        pass
    else:
        changelog_filterstr = logdb_filter('changeLogEntry', app.dn, entry_uuid)
        mil.append(
            app.anchor(
                'search', 'Change log',
                [
                    ('dn', changelog_dn),
                    ('filterstr', changelog_filterstr),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title='Audit trail of write access to current entry',
            )
        )

    try:
        monitor_context_dn = app.ls.root_dse['monitorContext'][0].decode(app.ls.charset)
    except KeyError:
        pass
    else:
        mil.append(app.anchor(
            'search', 'User conns',
            [
                ('dn', monitor_context_dn),
                (
                    'filterstr',
                    '(&(objectClass=monitorConnection)(monitorConnectionAuthzDN=%s))' % (
                        ldap0.filter.escape_str(app.dn),
                    ),
                ),
                ('scope', str(ldap0.SCOPE_SUBTREE)),
            ],
            title='Find connections of this user in monitor database',
        ))

    return mil
    # end of context_menu_single_entry()


def main_menu(app):
    """
    Returns list of main menu items
    """
    mil = []

    if app.ls is not None and app.ls.uri is not None:

        if app.dn and app.dn_obj != app.naming_context:
            mil.append(
                app.anchor(
                    'search', 'Up',
                    (
                        ('dn', app.parent_dn),
                        ('scope', str(ldap0.SCOPE_ONELEVEL)),
                        ('searchform_mode', 'adv'),
                        ('search_attr', 'objectClass'),
                        ('search_option', '({at}=*)'),
                        ('search_string', ''),
                    ),
                    title='List direct subordinates of %s' % (app.parent_dn or 'Root DSE'),
                )
            )

        mil.extend((
            app.anchor(
                'search', 'Down',
                (
                    ('dn', app.dn),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                    ('searchform_mode', 'adv'),
                    ('search_attr', 'objectClass'),
                    ('search_option', '({at}=*)'),
                    ('search_string', ''),
                ),
                title='List direct subordinates of %s' % (app.dn or 'Root DSE'),
            ),
            app.anchor(
                'searchform', 'Search',
                (('dn', app.dn),),
                title='Enter search criteria in input form',
            ),
        ))

        mil.append(
            app.anchor(
                'dit', 'Tree',
                [('dn', app.dn)],
                title='Display tree around %s' % (app.dn or 'Root DSE'),
                anchor_id=dn_anchor_hash(app.dn_obj)
            ),
        )

        mil.append(
            app.anchor(
                'read', 'Read',
                [('dn', app.dn), ('read_nocache', '1')],
                title='Display entry %s' % (app.dn or 'Root DSE'),
            ),
        )

        mil.extend((
            app.anchor(
                'add', 'New entry',
                [('dn', app.dn)],
                title='Add a new entry below of %s' % (app.dn or 'Root DSE')
            ),
            app.anchor(
                'conninfo', 'ConnInfo',
                [('dn', app.dn)],
                title='Show information about HTTP and LDAP connections'
            ),
            app.anchor(
                'params', 'Params',
                [('dn', app.dn)],
                title='Tweak parameters used for LDAP operations (controls etc.)'
            ),
            app.anchor('login', 'Bind', [('dn', app.dn)], title='Login to directory'),
            app.anchor('oid', 'Schema', [('dn', app.dn)], title='Browse/view subschema'),
        ))

        mil.append(app.anchor('disconnect', 'Disconnect', (), title='Disconnect from LDAP server'))

    else:

        mil.append(app.anchor('', 'Connect', (), title='New connection to LDAP server'))

    return mil
    # end of main_menu()


def dit_navigation(app):
    dnil = [
        app.anchor(
            'read',
            app.form.s2d(str(app.dn_obj.slice(i, i+1)) or '[Root DSE]'),
            [('dn', str(app.dn_obj.slice(i, None)))],
            title='Jump to %s' % (str(app.dn_obj.slice(i, None))),
        )
        for i in range(len(app.dn_obj))
    ]
    dnil.append(
        app.anchor(
            'read', '[Root DSE]',
            [('dn', '')],
            title='Jump to root DSE',
        )
    )
    return dnil
    # end of dit_navigation()


def top_section(
        app,
        title,
        main_menu_list,
        context_menu_list=None,
        main_div_id='Message',
    ):

    # First send the HTTP header
    header(app, 'text/html', app.form.accept_charset)

    # Read the template file for TopSection
    top_template_str = read_template(app, 'top_template', 'top section')

    script_name = escape_html(app.form.script_name)

    template_dict = {
        'main_div_id': main_div_id,
        'accept_charset': app.form.accept_charset,
        'refresh_time': str(web2ldapcnf.session_remove),
        'sid': app.sid or '',
        'title_text': title,
        'script_name': script_name,
        'web2ldap_version': escape_html(__version__),
        'command': app.command,
        'ldap_url': '',
        'ldap_uri': '-/-',
        'description': '',
        'who': '-/-',
        'dn': '-/-',
        'dit_navi': '-/-',
        'main_menu': command_div(
            main_menu_list,
            div_id='MainMenu',
            separator='\n',
            semantic_tag=None,
        ),
        'context_menu': command_div(
            context_menu_list,
            div_id='ContextMenu',
            separator='\n',
            semantic_tag=None,
        ),
    }
    template_dict.update([(k, escape_html(str(v))) for k, v in app.env.items()])

    if app.ls is not None and app.ls.uri is not None:
        # Only output something meaningful if valid connection
        template_dict.update({
            'ldap_url': app.ls.ldap_url(app.dn),
            'ldap_uri': app.form.s2d(app.ls.uri),
            'description': escape_html(app.cfg_param('description', '')),
            'dit_navi': ',\n'.join(dit_navigation(app)),
            'dn': app.form.s2d(app.dn),
        })
        template_dict['who'] = app.display_authz_dn()

    app.outf.write(top_template_str.format(**template_dict))
    # end of top_section()


def attrtype_select_field(
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
    for attr_type in (
            default_attr_options
            or list(app.schema.sed[ldap0.schema.models.AttributeType].keys())+attr_list
        ):
        attr_type_se = app.schema.get_obj(ldap0.schema.models.AttributeType, attr_type)
        if attr_type_se:
            if attr_type_se.names:
                attr_type_name = attr_type_se.names[0]
            else:
                attr_type_name = attr_type
            attr_type_desc = attr_type_se.desc
        else:
            attr_type_name = attr_type
            attr_type_desc = None
        attr_options_dict[attr_type_name] = (attr_type_name, attr_type_desc)
    sorted_attr_options = [
        (at, attr_options_dict[at][0], attr_options_dict[at][1])
        for at in sorted(attr_options_dict.keys(), key=str.lower)
    ]
    # Create a select field instance for attribute type name
    attr_select = SelectField(
        field_name, field_desc, 1,
        options=sorted_attr_options,
        auto_add_option=True,
    )
    attr_select.charset = app.form.accept_charset
    return attr_select
    # end of attrtype_select_field()


def gen_headers(content_type, charset, more_headers=None):
    # Get current time as GMT (seconds since epoch)
    current_datetime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(time.time()))
    headers = []
    if content_type.startswith('text/'):
        content_type = '%s;charset=%s' % (content_type, charset)
    headers.append(('Content-Type', content_type))
    headers.append(('Date', current_datetime))
    headers.append(('Last-Modified', current_datetime))
    headers.append(('Expires', current_datetime))
    for name, val in web2ldapcnf.http_headers.items():
        headers.append((name, val))
    headers.extend(more_headers or [])
    return headers
    # end of gen_headers()


def header(app, content_type, charset, more_headers=None):
    headers = gen_headers(
        content_type=content_type,
        charset=charset,
        more_headers=more_headers,
    )
    app.outf.reset()
    if app.form.next_cookie:
        for _, cookie in app.form.next_cookie.items():
            headers.append(('Set-Cookie', cookie.output()[12:]))
    if app.form.env.get('HTTPS', 'off') == 'on' and \
       'Strict-Transport-Security' not in web2ldapcnf.http_headers:
        headers.append(('Strict-Transport-Security', 'max-age=15768000 ; includeSubDomains'))
    app.outf.set_headers(headers)
    return headers
    # end of header()


def footer(app):
    app.outf.write(HTML_FOOTER)


def search_root_field(
        app,
        name='dn',
        text='Search Root',
        default=None,
        search_root_searchurl=None,
    ):
    """
    Returns input field for search root
    """

    def sortkey_func(d):
        if isinstance(d, DNObj):
            return str(reversed(d)).lower()
        try:
            dn, _ = d
        except ValueError:
            dn = d
        if not dn:
            return ''
        return str(reversed(DNObj.from_str(dn))).lower()

    # add all known naming contexts
    dn_select_list = set(map(str, app.ls.namingContexts))
    if app.dn:
        # add the current DN and all its parent DNs
        dn_select_list.update(map(str, [app.dn_obj] + app.dn_obj.parents()))
    if search_root_searchurl:
        # search for more search bases
        slu = LDAPUrl(search_root_searchurl)
        try:
            ldap_results = app.ls.l.search_s(
                slu.dn,
                slu.scope,
                slu.filterstr,
                attrlist=['1.1']
            )
        except ldap0.LDAPError:
            pass
        else:
            dn_select_list.update([
                r.dn_s
                for r in ldap_results
                if isinstance(r, SearchResultEntry)
            ])
    # Remove empty search base string because it will re-added with description
    if '' in dn_select_list:
        dn_select_list.remove('')
    # Add root search base string with description
    dn_select_list.add(('', '- World -'))
    srf = SelectField(
        name, text, 1,
        size=1,
        options=sorted(
            dn_select_list,
            key=sortkey_func,
        ),
        default=default or str(app.naming_context) or app.dn,
        ignoreCase=1
    )
    srf.charset = app.form.accept_charset
    return srf
    # end of search_root_field()


def invalid_syntax_message(app, invalid_attrs):
    invalid_attr_types_ui = [
        app.form.s2d(at)
        for at in sorted(invalid_attrs.keys())
    ]
    return 'Wrong syntax in following attributes: %s' % (
        ', '.join([
            '<a class="CL" href="#in_a_%s">%s</a>' % (at_ui, at_ui)
            for at_ui in invalid_attr_types_ui
        ])
    )


def extract_invalid_attr(app, ldap_err):
    """
    Extract invalid attributes dict from diagnostic message in LDAPError instance
    """
    try:
        # try to extract OpenLDAP-specific info message
        info = ldap_err.args[0].get('info', b'').decode(app.ls.charset)
    except (AttributeError, IndexError, UnicodeDecodeError):
        # could not extract useful info
        return (app.ldap_error_msg(ldap_err), {})
    invalid_attrs = {}
    for extract_pattern in EXTRACT_INVALID_ATTR_PATTERNS:
        match = extract_pattern.match(info)
        if match is None:
            continue
        matches = match.groupdict()
        if 'at' in matches:
            invalid_attrs[matches['at']] = [int(matches.get('index', 0))]
            if isinstance(ldap_err, ldap0.INVALID_SYNTAX):
                error_msg = invalid_syntax_message(app, invalid_attrs)
            else:
                error_msg = app.ldap_error_msg(ldap_err)
            break
    return error_msg, invalid_attrs


def exception_message(app, h1_msg, error_msg):
    """
    h1_msg
      Unicode string with text for the <h1> heading
    error_msg
      Raw string with HTML with text describing the exception
      (Security note: Must already be quoted/escaped!)
    """
    top_section(app, 'Error', main_menu(app), context_menu_list=[])
    app.outf.write(
        """
        <h1>{heading}</h1>
        <p class="ErrorMessage">
          {error_msg}
        </p>
        """.format(
            heading=app.form.s2d(h1_msg),
            error_msg=error_msg,
        )
    )
    footer(app)
    # end of exception_message()
