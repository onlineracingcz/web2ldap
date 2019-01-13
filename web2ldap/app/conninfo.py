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
from ldap0.filter import escape_filter_chars

import web2ldap.utctime
import web2ldap.ldaputil.base
import web2ldapcnf
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


def w2l_conninfo(sid, outf, command, form, ls, dn):

    protocol_version = ls.l.get_option(ldap0.OPT_PROTOCOL_VERSION)

    conninfo_flushcaches = int(form.getInputValue('conninfo_flushcaches', ['0'])[0])
    if conninfo_flushcaches:
        ls.flushCache()

    context_menu_list = []

    # List of candidate DNs for probing configuration information
    config_dn_list = []

    monitored_info = None
    if ls.rootDSE.has_key('monitorContext'):
        context_menu_list.append(
            form.applAnchor(
                'read', 'Monitor', sid,
                [('dn', ls.rootDSE['monitorContext'][0])],
            )
        )
        try:
            monitor_context_dn = ls.rootDSE['monitorContext'][0]
        except KeyError:
            pass
        else:
            try:
                monitored_info = ls.readEntry(
                    monitor_context_dn,
                    ['monitoredInfo']
                )[0][1]['monitoredInfo']
            except (ldap0.LDAPError, KeyError):
                pass
            else:
                context_menu_list.append(form.applAnchor(
                    'search', 'My connections', sid,
                    [
                        ('dn', monitor_context_dn),
                        (
                            'filterstr',
                            '(&(objectClass=monitorConnection)(monitorConnectionAuthzDN=%s))' % (
                                escape_filter_chars(ls.who or '')
                            )
                        ),
                        ('scope', str(ldap0.SCOPE_SUBTREE)),
                    ],
                    title=u'Find own connections in Monitor database',
                ))
    else:
        config_dn_list.append(('CN=MONITOR', 'Monitor'))

    if ls.rootDSE.has_key('changelog'):
        context_menu_list.append(
            form.applAnchor(
                'read', 'Change log', sid,
                [('dn', ls.rootDSE['changelog'][0])],
            )
        )
    else:
        config_dn_list.append(('cn=changelog', 'Change log'))

    if 'configContext' in ls.rootDSE:
        context_menu_list.append(
            form.applAnchor(
                'read', 'Config', sid,
                [('dn', ls.rootDSE['configContext'][0])],
            )
        )
    elif 'configurationNamingContext' in ls.rootDSE:
        # MS AD
        context_menu_list.append(
            form.applAnchor(
                'read', 'AD Configuration', sid,
                [('dn', ls.rootDSE['configurationNamingContext'][0])]
            )
        )
    elif 'ibm-configurationnamingcontext' in ls.rootDSE:
        # IBM Directory Server
        context_menu_list.append(
            form.applAnchor(
                'read', 'IBM DS Configuration', sid,
                [('dn', ls.rootDSE['ibm-configurationnamingcontext'][0])]
            )
        )
    else:
        config_dn_list.extend([
            ('CN=CONFIG', 'Config'),
            ('CN=Configuration', 'Configuration'),
            ('cn=ldbm', 'LDBM Database'),
            ('ou=system', 'System'),
        ])

    current_audit_context = ls.getAuditContext(ls.currentSearchRoot)
    if not current_audit_context is None:
        context_menu_list.extend([
            form.applAnchor(
                'read', 'Audit DB', sid,
                [('dn', current_audit_context)],
            ),
            form.applAnchor(
                'search', 'Audit my access', sid,
                [
                    ('dn', current_audit_context),
                    ('filterstr', '(&(objectClass=auditObject)(reqAuthzID=%s))' % (escape_filter_chars(ls.who or ''))),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title=u'Complete audit trail for currently bound identity',
            ),
            form.applAnchor(
                'search', 'Audit my writes', sid,
                [
                    ('dn', current_audit_context),
                    ('filterstr', '(&(objectClass=auditWriteObject)(reqAuthzID=%s))' % (escape_filter_chars(ls.who or ''))),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title=u'Audit trail of write access by currently bound identity',
            ),
            form.applAnchor(
                'search', 'Last logins', sid,
                [
                    ('dn', current_audit_context),
                    ('filterstr', '(&(objectClass=auditBind)(reqDN=%s))' % (escape_filter_chars(ls.who or ''))),
                    ('scope', str(ldap0.SCOPE_ONELEVEL)),
                ],
                title=u'Audit trail of last logins (binds) by currently bound identity',
            ),
        ])

    for config_dn, txt in config_dn_list:
        try:
            entry_exists = ls.existingEntry(config_dn, suppress_referrals=1)
        except ldap0.LDAPError:
            pass
        else:
            if entry_exists:
                context_menu_list.append(
                    form.applAnchor(
                        'read', txt, sid,
                        [('dn', config_dn)],
                    )
                )

    if ls.rootDSE.has_key('schemaNamingContext'):
        # MS AD schema configuration
        context_menu_list.append(
            form.applAnchor(
                'read', 'AD Schema Configuration', sid,
                [('dn', ls.rootDSE['schemaNamingContext'][0])],
            )
        )

    web2ldap.app.gui.TopSection(
        sid, outf, command, form, ls, dn,
        'Connection Info',
        web2ldap.app.gui.MainMenu(sid, form, ls, dn),
        context_menu_list=context_menu_list
    )

    if ls.who:
        who_html = '%s<br>( %s )' % (
            web2ldap.app.gui.DisplayDN(sid, form, ls, ls.who, commandbutton=False),
            web2ldapcnf.command_link_separator.join((
                form.applAnchor(
                    'read', 'Read', sid,
                    [('dn', ls.who)],
                    title=u'Read bound entry\r\n%s' % (ls.who),
                ),
                form.applAnchor(
                    'passwd', 'Password', sid,
                    [('dn', ls.who), ('passwd_who', ls.who)],
                    title=u'Set password of entry\r\n%s' % (ls.who),
                ),
            ))
        )
    else:
        who_html = 'anonymous'

    try:
        whoami_result = '&quot;%s&quot;' % (form.utf2display(ls.whoami()))
    except ldap0.LDAPError as e:
        whoami_result = '<strong>Failed:</strong> %s' % (web2ldap.app.gui.LDAPError2ErrMsg(e, form, ls.charset))

    if ls.saslAuth:
        sasl_mech = u'SASL/%s' % (ls.saslAuth.mech)
        sasl_auth_info = '<table>%s</table>' % '\n'.join([
            '<tr><td>%s</td><td>%s</td></tr>' % (
                form.utf2display(web2ldap.ldaputil.base.LDAP_OPT_NAMES_DICT.get(k, str(k)).decode('ascii')),
                form.utf2display(repr(v).decode(ls.charset))
            )
            for k, v in ls.saslAuth.cb_value_dict.items()
            if v
        ])
    else:
        sasl_mech = u'simple'
        sasl_auth_info = 'SASL not used'

    try:
        sasl_ssf = unicode(ls.l.get_option(ldap0.OPT_X_SASL_SSF))
    except ldap0.LDAPError as e:
        sasl_ssf = u'error reading option: %s' % (web2ldap.app.gui.LDAPError2ErrMsg(e, form, ls.charset))
    except ValueError:
        sasl_ssf = u'option not available'

    vendor_name = (
        ls.rootDSE.get('vendorName', '') or
        monitored_info or
        [{True:'OpenLDAP', False:''}['OpenLDAProotDSE' in ls.rootDSE.get('objectClass', [])]] or ['unknown']
    )[0].decode(ls.charset)

    outf.write(
        CONNINFO_LDAP_TEMPLATE % (
            ls.uri.encode('ascii'),
            protocol_version,
            ls.charset.upper(),
            {False:'not secured', True:'secured'}[ls.secureConn],
            web2ldap.utctime.strftimeiso8601(time.gmtime(ls.connStartTime)),
            time.time()-ls.connStartTime,
            ls.l._reconnects_done,
            form.utf2display(vendor_name),
            form.utf2display(ls.rootDSE.get('vendorVersion', [''])[0].decode(ls.charset)),
            who_html,
            whoami_result,
            form.utf2display(sasl_mech),
            sasl_auth_info,
            form.utf2display(sasl_ssf),
        )
    )

    outf.write(
        CONNINFO_LDAP_CACHE_TEMPLATE % (
            form.applAnchor(
                'conninfo', 'Flush all caches', sid,
                [('dn', dn), ('conninfo_flushcaches', '1')],
                title=u'Flush all cached information for this LDAP connection'
            ),
            len(ls.l._cache),
            len(ls.schema_dn_cache),
            len(ls.schema_cache),
            ls.l.cache_hit_ratio(),
        )
    )

    cross_check_vars = session_store.sessiondict['__session_checkvars__'+sid].items()
    cross_check_vars.sort()
    cross_check_vars_html = '\n'.join([
        '<tr><td>%s</td><td>%s</td></tr>' % (
            form.utf2display(unicode(k, form.accept_charset)),
            form.utf2display(unicode(v, form.accept_charset)),
        )
        for k, v in cross_check_vars
    ])

    outf.write(
        CONNINFO_HTTP_TEMPLATE % (
            ls.onBehalf,
            form.utf2display(unicode(form.env.get('REMOTE_ADDR', ''))),
            form.utf2display(unicode(form.env.get('REMOTE_PORT', ''))),
            form.env.get('SERVER_SIGNATURE', ''),
            form.utf2display(unicode(', '.join(form.accept_language))),
            form.utf2display(unicode(form.accept_charset.upper())),
            cross_check_vars_html,
            form.utf2display(unicode(form.env.get('HTTP_USER_AGENT', ''), form.accept_charset)),
        )
    )
    web2ldap.app.gui.Footer(outf, form)
