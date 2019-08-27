# -*- coding: utf-8 -*-
"""
web2ldap.app.conninfo: Display (SSL) connection data

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time

import ldap0
import ldap0.filter

import web2ldapcnf

import web2ldap.utctime
import web2ldap.ldaputil
import web2ldap.app.core
import web2ldap.app.gui
from web2ldap.app.session import session_store

CONNINFO_LDAP_TEMPLATE = """
<h1>LDAP Connection Parameters</h1>
<h2>LDAP connection</h2>
<table summary="LDAP connection">
  <tr>
    <td>Connected to:</td>
    <td>%s<br>(LDAPv%d, %s, %s)</td>
  </tr>
  <tr>
    <td>Connected since:</td>
    <td>%s (%d secs)</td>
  </tr>
  <tr>
    <td>Reconnect counter:</td>
    <td>%d</td>
  </tr>
  <tr>
    <td>Server vendor info:</td>
    <td>%s %s</td>
  </tr>
  <tr>
    <td>Bound as:</td>
    <td>%s</td>
  </tr>
  <tr>
    <td>Result <em>Who am I?</em>:</td>
    <td>%s</td>
  </tr>
  <tr>
    <td>Bind mechanism used:</td>
    <td>%s</td>
  </tr>
  <tr>
    <td>SASL auth info:</td>
    <td>%s</td>
  </tr>
  <tr>
    <td>SASL SSF info:</td>
    <td>%s</td>
  </tr>
  <tr>
    <td>Current DN:</td>
    <td>%s</td>
  </tr>
  <tr>
    <td>Parent DN:</td>
    <td>%s</td>
  </tr>
  <tr>
    <td>Naming Context:</td>
    <td>%s</td>
  </tr>
  <tr>
    <td>%d last search bases:</td>
    <td>%s</td>
  </tr>
</table>
"""

CONNINFO_LDAP_CACHE_TEMPLATE = """
<h3>LDAP cache information</h3>
<p>%s</p>
<table id="LDAPCacheTable" summary="LDAP cache information">
  <tr>
    <td>Cached searches:</td>
    <td>%d</td>
  </tr>
  <tr>
    <td>Cached subschema DN mappings:</td>
    <td>%d</td>
  </tr>
  <tr>
    <td>Cached subschema subentries:</td>
    <td>%d</td>
  </tr>
  <tr>
    <td>Cache hit ratio:</td>
    <td>%0.1f %%</td>
  </tr>
</table>
"""

CONNINFO_HTTP_TEMPLATE = """
<h2>HTTP connection</h2>
<table summary="HTTP connection">
  <tr><td>Your IP address:</td><td>%s</td></tr>
  <tr><td>direct remote address/port:</td><td>%s:%s</td></tr>
  <tr><td>Server signature:</td><td>%s</td></tr>
  <tr><td>Preferred language:</td><td>%s</td></tr>
  <tr><td>Character set/encoding:</td><td>%s</td></tr>
  <tr>
    <td>Cross-check vars in use:</td>
    <td>
      <table summary="Cross-check vars">
        %s
      </table>
    </td>
  </tr>
  <tr><td>User-Agent header:</td><td>%s</td></tr>
</table>
"""


def w2l_conninfo(app):

    protocol_version = app.ls.l.get_option(ldap0.OPT_PROTOCOL_VERSION)

    conninfo_flushcaches = int(app.form.getInputValue('conninfo_flushcaches', ['0'])[0])
    if conninfo_flushcaches:
        app.ls.flush_cache()

    context_menu_list = []

    # List of candidate DNs for probing configuration information
    config_dn_list = []

    monitored_info = None
    if 'monitorContext' in app.ls.rootDSE:
        # seems to be OpenLDAP's back-monitor
        monitor_context_dn = app.ls.rootDSE['monitorContext'][0]
        context_menu_list.append(
            app.anchor(
                'read', 'Monitor',
                [('dn', monitor_context_dn)],
            )
        )
        try:
            monitored_info = app.ls.l.read_s(
                monitor_context_dn,
                attrlist=['monitoredInfo']
            )['monitoredInfo']
        except (ldap0.LDAPError, KeyError):
            pass
        else:
            context_menu_list.append(app.anchor(
                'search', 'My connections',
                [
                    ('dn', monitor_context_dn),
                    (
                        'filterstr',
                        '(&(objectClass=monitorConnection)(monitorConnectionAuthzDN=%s))' % (
                            ldap0.filter.escape_str(app.ls.who or '')
                        )
                    ),
                    ('scope', str(ldap0.SCOPE_SUBTREE)),
                ],
                title=u'Find own connections in Monitor database',
            ))
    else:
        config_dn_list.append(('CN=MONITOR', 'Monitor'))

    if 'changelog' in app.ls.rootDSE:
        context_menu_list.append(
            app.anchor(
                'read', 'Change log',
                [('dn', app.ls.rootDSE['changelog'][0])],
            )
        )
    else:
        config_dn_list.append(('cn=changelog', 'Change log'))

    if 'configContext' in app.ls.rootDSE:
        context_menu_list.append(
            app.anchor(
                'read', 'Config',
                [('dn', app.ls.rootDSE['configContext'][0])],
            )
        )
    elif 'configurationNamingContext' in app.ls.rootDSE:
        # MS AD
        context_menu_list.append(
            app.anchor(
                'read', 'AD Configuration',
                [('dn', app.ls.rootDSE['configurationNamingContext'][0])]
            )
        )
    elif 'ibm-configurationnamingcontext' in app.ls.rootDSE:
        # IBM Directory Server
        context_menu_list.append(
            app.anchor(
                'read', 'IBM DS Configuration',
                [('dn', app.ls.rootDSE['ibm-configurationnamingcontext'][0])]
            )
        )
    else:
        config_dn_list.extend([
            ('CN=CONFIG', 'Config'),
            ('CN=Configuration', 'Configuration'),
            ('cn=ldbm', 'LDBM Database'),
            ('ou=system', 'System'),
        ])

    if app.audit_context:
        context_menu_list.extend([
            app.anchor(
                'read', 'Audit DB',
                [('dn', app.audit_context)],
            ),
            app.anchor(
                'search', 'Audit my access',
                [
                    ('dn', app.audit_context),
                    ('filterstr', '(&(objectClass=auditObject)(reqAuthzID=%s))' % (ldap0.filter.escape_str(app.ls.who or ''))),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title=u'Complete audit trail for currently bound identity',
            ),
            app.anchor(
                'search', 'Audit my writes',
                [
                    ('dn', app.audit_context),
                    ('filterstr', '(&(objectClass=auditWriteObject)(reqAuthzID=%s))' % (ldap0.filter.escape_str(app.ls.who or ''))),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title=u'Audit trail of write access by currently bound identity',
            ),
            app.anchor(
                'search', 'Last logins',
                [
                    ('dn', app.audit_context),
                    ('filterstr', '(&(objectClass=auditBind)(reqDN=%s))' % (ldap0.filter.escape_str(app.ls.who or ''))),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title=u'Audit trail of last logins (binds) by currently bound identity',
            ),
        ])

    for config_dn, txt in config_dn_list:
        try:
            app.ls.l.read_s(config_dn, attrlist=['1.1'])
        except ldap0.LDAPError:
            pass
        else:
            context_menu_list.append(
                app.anchor(
                    'read', txt,
                    [('dn', config_dn)],
                )
            )

    if 'schemaNamingContext' in app.ls.rootDSE:
        # MS AD schema configuration
        context_menu_list.append(
            app.anchor(
                'read', 'AD Schema Configuration',
                [('dn', app.ls.rootDSE['schemaNamingContext'][0])],
            )
        )

    web2ldap.app.gui.top_section(
        app,
        'Connection Info',
        web2ldap.app.gui.main_menu(app),
        context_menu_list=context_menu_list
    )

    if app.ls.who:
        who_html = '%s<br>( %s )' % (
            app.display_dn(app.ls.who, commandbutton=False),
            web2ldapcnf.command_link_separator.join((
                app.anchor(
                    'read', 'Read',
                    [('dn', app.ls.who)],
                    title=u'Read bound entry\r\n%s' % (app.ls.who),
                ),
                app.anchor(
                    'passwd', 'Password',
                    [('dn', app.ls.who), ('passwd_who', app.ls.who)],
                    title=u'Set password of entry\r\n%s' % (app.ls.who),
                ),
            ))
        )
    else:
        who_html = 'anonymous'

    try:
        whoami_result = '&quot;%s&quot;' % (app.form.utf2display(app.ls.l.whoami_s().decode(app.ls.charset)))
    except ldap0.LDAPError as ldap_err:
        whoami_result = '<strong>Failed:</strong> %s' % (app.ldap_error_msg(ldap_err))

    if app.ls.saslAuth:
        sasl_mech = u'SASL/%s' % (app.ls.saslAuth.mech)
        sasl_auth_info = '<table>%s</table>' % '\n'.join([
            '<tr><td>%s</td><td>%s</td></tr>' % (
                app.form.utf2display(web2ldap.ldaputil.LDAP_OPT_NAMES_DICT.get(k, str(k)).decode('ascii')),
                app.form.utf2display(repr(v).decode(app.ls.charset))
            )
            for k, v in app.ls.saslAuth.cb_value_dict.items()
            if v
        ])
    else:
        sasl_mech = u'simple'
        sasl_auth_info = 'SASL not used'

    try:
        sasl_ssf = str(app.ls.l.get_option(ldap0.OPT_X_SASL_SSF))
    except ldap0.LDAPError as ldap_err:
        sasl_ssf = u'error reading option: %s' % (app.ldap_error_msg(ldap_err))
    except ValueError:
        sasl_ssf = u'option not available'

    vendor_name = (
        app.ls.vendorName
        or (monitored_info or [None])[0]
        or {True:'OpenLDAP', False:''}[app.ls.is_openldap]
        or 'unknown'
    ).decode(app.ls.charset)

    app.outf.write(
        CONNINFO_LDAP_TEMPLATE % (
            app.ls.uri.encode('ascii'),
            protocol_version,
            app.ls.charset.upper(),
            {False:'not secured', True:'secured'}[app.ls.secureConn],
            web2ldap.utctime.strftimeiso8601(time.gmtime(app.ls.connStartTime)),
            time.time()-app.ls.connStartTime,
            app.ls.l._reconnects_done,
            app.form.utf2display(vendor_name),
            app.form.utf2display(app.ls.rootDSE.get('vendorVersion', [''])[0].decode(app.ls.charset)),
            who_html,
            whoami_result,
            app.form.utf2display(sasl_mech),
            sasl_auth_info,
            app.form.utf2display(sasl_ssf),
            app.form.utf2display(app.dn or u'- World -'),
            app.form.utf2display(app.parent_dn if app.parent_dn is not None else u''),
            app.form.utf2display(app.naming_context),
            min(len(app.ls.l.last_search_bases), app.ls.l.last_search_bases.maxlen),
            '<br>'.join([
                app.display_dn(search_base.decode(app.ls.charset), commandbutton=True)
                for search_base in app.ls.l.last_search_bases
            ])
        )
    )

    app.outf.write(
        CONNINFO_LDAP_CACHE_TEMPLATE % (
            app.anchor(
                'conninfo', 'Flush all caches',
                [('dn', app.dn), ('conninfo_flushcaches', '1')],
                title=u'Flush all cached information for this LDAP connection'
            ),
            len(app.ls.l._cache),
            len(app.ls._schema_dn_cache),
            len(app.ls._schema_cache),
            app.ls.l.cache_hit_ratio(),
        )
    )

    cross_check_vars = session_store.sessiondict['__session_checkvars__'+app.sid].items()
    cross_check_vars.sort()
    cross_check_vars_html = '\n'.join([
        '<tr><td>%s</td><td>%s</td></tr>' % (
            app.form.utf2display(str(k, app.form.accept_charset)),
            app.form.utf2display(str(v, app.form.accept_charset)),
        )
        for k, v in cross_check_vars
    ])

    app.outf.write(
        CONNINFO_HTTP_TEMPLATE % (
            app.ls.onBehalf,
            app.form.utf2display(str(app.env.get('REMOTE_ADDR', ''))),
            app.form.utf2display(str(app.env.get('REMOTE_PORT', ''))),
            app.env.get('SERVER_SIGNATURE', ''),
            app.form.utf2display(str(', '.join(app.form.accept_language))),
            app.form.utf2display(app.form.accept_charset.upper().decode()),
            cross_check_vars_html,
            app.form.utf2display(str(app.env.get('HTTP_USER_AGENT', ''), app.form.accept_charset)),
        )
    )
    web2ldap.app.gui.footer(app)
