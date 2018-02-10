# -*- coding: utf-8 -*-
"""
web2ldap.app.conninfo: Display (SSL) connection data

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time

import pyweblib.sslenv

import ldap0

import web2ldap.utctime
import web2ldap.ldaputil.base
import web2ldap.msgzip
import web2ldap.app.cnf,web2ldap.app.core,web2ldap.app.gui
from web2ldap.app.session import session

##############################################################################
# Connection info
##############################################################################

def w2l_ConnInfo(sid,outf,command,form,ls,dn):

  protocol_version = ls.l.get_option(ldap0.OPT_PROTOCOL_VERSION)

  conninfo_flushcaches = int(form.getInputValue('conninfo_flushcaches',['0'])[0])
  if conninfo_flushcaches:
    ls.flushCache()

  context_menu_list = []

  # List of candidate DNs for probing configuration information
  config_dn_list = []

  monitored_info = None
  if ls.rootDSE.has_key('monitorContext'):
    context_menu_list.append(form.applAnchor('read','Monitor',sid,[('dn',ls.rootDSE['monitorContext'][0])]))
    try:
      monitor_context_dn = ls.rootDSE['monitorContext'][0]
    except KeyError:
      pass
    else:
      try:
        monitored_info = ls.readEntry(monitor_context_dn,['monitoredInfo'])[0][1]['monitoredInfo']
      except (ldap0.LDAPError,KeyError):
        pass
      else:
        context_menu_list.append(form.applAnchor(
          'search','My connections',sid,
          [
            ('dn',monitor_context_dn),
            ('filterstr','(&(objectClass=monitorConnection)(monitorConnectionAuthzDN=%s))' % (ldap0.filter.escape_filter_chars(ls.who or ''))),
            ('scope',str(ldap0.SCOPE_SUBTREE)),
          ],
          title=u'Find own connections in Monitor database',
        ))
  else:
    config_dn_list.append(('CN=MONITOR','Monitor'))

  if ls.rootDSE.has_key('changelog'):
    # OpenLDAP 2.3+
    context_menu_list.append(form.applAnchor('read','Change log',sid,[('dn',ls.rootDSE['changelog'][0])]))
  else:
    config_dn_list.append(('cn=changelog','Change log'))

  if ls.rootDSE.has_key('configContext'):
    # OpenLDAP 2.3+
    context_menu_list.append(form.applAnchor('read','Config',sid,[('dn',ls.rootDSE['configContext'][0])]))
  elif ls.rootDSE.has_key('configurationNamingContext'):
    # MS AD
    context_menu_list.append(form.applAnchor('read','AD Configuration',sid,[('dn',ls.rootDSE['configurationNamingContext'][0])]))
  elif ls.rootDSE.has_key('ibm-configurationnamingcontext'):
    # IBM Directory Server
    context_menu_list.append(form.applAnchor('read','IBM DS Configuration',sid,[('dn',ls.rootDSE['ibm-configurationnamingcontext'][0])]))
  else:
    config_dn_list.extend([
      ('CN=CONFIG','Config'),
      ('CN=Configuration','Configuration'),
      ('cn=ldbm','LDBM Database'),
      ('ou=system','System'),
    ])

  current_audit_context = ls.getAuditContext(ls.currentSearchRoot)
  if not current_audit_context is None:
    context_menu_list.extend([
      form.applAnchor('read','Audit DB',sid,[('dn',current_audit_context)]),
      form.applAnchor(
        'search','Audit my access',sid,
        [
          ('dn',current_audit_context),
          ('filterstr','(&(objectClass=auditObject)(reqAuthzID=%s))' % (ldap0.filter.escape_filter_chars(ls.who or ''))),
          ('scope',str(ldap0.SCOPE_ONELEVEL)),
        ],
        title=u'Complete audit trail for currently bound identity',
      ),
      form.applAnchor(
        'search','Audit my writes',sid,
        [
          ('dn',current_audit_context),
          ('filterstr','(&(objectClass=auditWriteObject)(reqAuthzID=%s))' % (ldap0.filter.escape_filter_chars(ls.who or ''))),
          ('scope',str(ldap0.SCOPE_ONELEVEL)),
        ],
        title=u'Audit trail of write access by currently bound identity',
      ),
      form.applAnchor(
        'search','Last logins',sid,
        [
          ('dn',current_audit_context),
          ('filterstr','(&(objectClass=auditBind)(reqDN=%s))' % (ldap0.filter.escape_filter_chars(ls.who or ''))),
          ('scope',str(ldap0.SCOPE_ONELEVEL)),
        ],
        title=u'Audit trail of last logins (binds) by currently bound identity',
      ),
    ])

  for config_dn,txt in config_dn_list:
    try:
      entry_exists = ls.existingEntry(config_dn,suppress_referrals=1)
    except ldap0.LDAPError:
      pass
    else:
      if entry_exists:
        context_menu_list.append(form.applAnchor('read',txt,sid,[('dn',config_dn)]))

  if ls.rootDSE.has_key('schemaNamingContext'):
    # MS AD schema configuration
    context_menu_list.append(form.applAnchor('read','AD Schema Configuration',sid,[('dn',ls.rootDSE['schemaNamingContext'][0])]))

  web2ldap.app.gui.TopSection(
    sid,outf,command,form,ls,dn,
    'Connection Info',
    web2ldap.app.gui.MainMenu(sid,form,ls,dn),
    context_menu_list=context_menu_list
  )

  if ls.who:
    who_html = '%s<br>( %s )' % (
      web2ldap.app.gui.DisplayDN(sid,form,ls,ls.who,commandbutton=0),
      web2ldap.app.cnf.misc.command_link_separator.join((
        form.applAnchor(
          'read','Read',sid,[('dn',ls.who)],
          title=u'Read bound entry\r\n%s' % (ls.who),
        ),
        form.applAnchor(
          'passwd','Password',sid,[('dn',ls.who),('passwd_who',ls.who)],
          title=u'Set password of entry\r\n%s' % (ls.who),
        ),
      )))
  else:
    who_html = 'anonymous'

  try:
    whoami_result = '&quot;%s&quot;' % (form.utf2display(ls.whoami()))
  except ldap0.LDAPError as e:
    whoami_result = '<strong>Failed:</strong> %s' % (web2ldap.app.gui.LDAPError2ErrMsg(e,form,ls.charset))

  if ls.saslAuth:
    sasl_mech = u'SASL/%s' % (ls.saslAuth.mech)
    sasl_auth_info = '<table>%s</table>' % '\n'.join([
        '<tr><td>%s</td><td>%s</td></tr>' % (
          form.utf2display(unicode(web2ldap.ldaputil.base.LDAP_OPT_NAMES_DICT.get(k,str(k)),'ascii')),
          form.utf2display(unicode(repr(v),ls.charset))
        )
        for k,v in ls.saslAuth.cb_value_dict.items()
        if v
      ])
  else:
    sasl_mech = u'simple'
    sasl_auth_info = 'SASL not used'

  if ldap0.SASL_AVAIL:
    try:
      sasl_ssf = unicode(ls.l.get_option(ldap0.OPT_X_SASL_SSF))
    except ldap0.LDAPError as e:
      sasl_ssf = u'error reading option: %s' % (web2ldap.app.gui.LDAPError2ErrMsg(e,form,ls.charset))
    except ValueError:
      sasl_ssf = u'option not available'
  else:
    sasl_ssf = u'no SASL support in python-ldap'

  vendor_name = unicode(
    (
      ls.rootDSE.get('vendorName','') or \
      monitored_info or \
      [{True:'OpenLDAP',False:''}['OpenLDAProotDSE' in ls.rootDSE.get('objectClass',[])]] or \
      ['unknown']
    )[0],
    ls.charset
  )

  outf.write("""
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
    """ % (
      ls.uri.encode('ascii'),
      protocol_version,
      ls.charset.upper(),
      {0:'not secured',1:'secured'}[ls.secureConn],
      web2ldap.utctime.strftimeiso8601(time.gmtime(ls.connStartTime)),
      time.time()-ls.connStartTime,
      ls.l._reconnects_done,
      form.utf2display(vendor_name),
      form.utf2display(
        unicode(
          (ls.rootDSE.get('vendorVersion','') or [''])[0],
          ls.charset
        ),
      ),
      who_html,
      whoami_result,
      form.utf2display(sasl_mech),
      sasl_auth_info,
      form.utf2display(sasl_ssf),
    )
  )

  outf.write("""
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
        <td>%d %%</td>
      </tr>
    </table>
    """ % (
      form.applAnchor(
        'conninfo','Flush all caches',sid,
        [
          ('dn',dn),
          ('conninfo_flushcaches','1'),
        ],
        title=u'Flush all cached information for this LDAP connection'
      ),
      len(ls.l._cache),
      len(ls.schema_dn_cache),
      len(ls.schema_cache),
      round(ls.l.get_cache_hit_ratio() or 0.0),
    )
  )

  cross_check_vars = session.sessiondict['__session_checkvars__'+sid].items()
  cross_check_vars.sort()
  cross_check_vars_html = '\n'.join([
    '<tr><td>%s</td><td>%s</td></tr>' % (
      form.utf2display(unicode(k,form.accept_charset)),
      form.utf2display(unicode(v,form.accept_charset)),
    )
    for k,v in cross_check_vars
  ])

  if isinstance(outf,web2ldap.msgzip.GzipFile):
    compresslevel = outf.compresslevel
  else:
    compresslevel = None
  outf.write("""
    <h2>HTTP connection</h2>
    <table summary="HTTP connection">
      <tr><td>Your IP address:</td><td>%s</td></tr>
      <tr><td>direct remote address/port:</td><td>%s:%s</td></tr>
      <tr><td>Server signature:</td><td>%s</td></tr>
      <tr><td>Character set/encoding:</td><td>%s</td></tr>
      <tr><td>GZIP compression level:</td><td>%s</td></tr>
      <tr>
        <td>Cross-check vars in use:</td>
        <td>
          <table summary="Cross-check vars">
            %s
          </table>
        </td>
      </tr>
      <tr><td>User-Agent header:</td><td>%s</td></tr>
      <tr><td>Browser detected:</td><td>%s %s</td></tr>
    </table>
    <h3>SSL</h3>
    """ % (
      ls.onBehalf,
      form.utf2display(unicode(form.env.get('REMOTE_ADDR',''))),
      form.utf2display(unicode(form.env.get('REMOTE_PORT',''))),
      form.env.get('SERVER_SIGNATURE',''),
      form.utf2display(unicode(form.accept_charset.upper())),
      str(compresslevel),
      cross_check_vars_html,
      form.utf2display(unicode(form.env.get('HTTP_USER_AGENT',''),form.accept_charset)),
      form.browser_type or '',
      form.browser_version or '',
    )
  )
  ssl_valid_dn = web2ldap.app.cnf.GetParam(ls,'ssl_valid_dn','')
  ssl_valid_idn = web2ldap.app.cnf.GetParam(ls,'ssl_valid_idn','')
  pyweblib.sslenv.PrintSecInfo(form.env,web2ldap.app.cnf.misc.sec_sslacceptedciphers,ssl_valid_dn,ssl_valid_idn,outf)
  web2ldap.app.gui.Footer(outf,form)
