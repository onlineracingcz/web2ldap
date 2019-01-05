# -*- coding: utf-8 -*-
"""
web2ldap.app.referral: chase LDAP referrals

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import web2ldap.app.core,web2ldap.app.gui,web2ldap.app.cnf

from ldap0.ldapurl import LDAPUrl

ErrorMessageDiv = """
<h1>Error</h1>
<p class="ErrorMessage">
  %s
</p>
"""

def w2l_ChaseReferral(sid,outf,command,form,ls,dn,e):

  web2ldap.app.gui.TopSection(
    sid,outf,command,form,ls,dn,
    'Referral received',
    web2ldap.app.gui.MainMenu(sid,form,ls,dn),
    context_menu_list=[]
  )

  # Pull out referral LDAP URL
  try:
    ldap_url_info = [
      s.strip()
      for s in e.args[0].get('info','').split('\n')
    ]
  except ValueError:
    outf.write(
      ErrorMessageDiv % (
        'Error extracting referral LDAP URL from %s.' % (
          form.utf2display(unicode(repr(e),'ascii'))
        )
      )
    )
    web2ldap.app.gui.Footer(outf,form)
    return
  else:
    try:
      ldap_url_info = ldap_url_info[1]
    except IndexError:
      outf.write(
        ErrorMessageDiv % (
          'Error extracting referral LDAP URL from %s.' % (
            form.utf2display(unicode(repr(ldap_url_info),'ascii'))
          )
        )
      )
      web2ldap.app.gui.Footer(outf,form)
      return
    # Parse the referral LDAP URL
    try:
      referralUrl = LDAPUrl(ldap_url_info[ldap_url_info.find('ldap:'):])
    except ValueError as e:
      outf.write(ErrorMessageDiv % (
          'Error parsing referral URL %s: %s' % (
            form.utf2display(unicode(repr(ldap_url_info),'ascii')),
            form.utf2display(unicode(str(e),'ascii'))
          )
        )
      )
      web2ldap.app.gui.Footer(outf,form)
      return

  login_template_str = web2ldap.app.gui.ReadTemplate(form,ls,'login_template',u'referral login form')

  login_search_root_field = web2ldap.app.gui.SearchRootField(form,ls,dn,name='login_search_root')
  login_fields = login_template_str.format(
    field_login_mech=form.field['login_mech'].inputHTML(),
    value_ldap_who=form.utf2display(ls.who),
    value_ldap_filter=form.utf2display(web2ldap.app.cnf.GetParam(ls,'binddnsearch',ur'(uid=%s)'),'utf-8'),
    field_login_search_root=login_search_root_field.inputHTML(),
    field_login_authzid_prefix=form.field['login_authzid_prefix'].inputHTML(),
    value_submit='Chase Referral',
  )

  outf.write("""
<h1>Referral received</h1>
<p>
  Referral URL:<br>%s
</p>
%s\n%s\n%s\n%s
"""  % (
      form.utf2display(unicode(referralUrl.unparse(),ls.charset)),
      form.beginFormHTML(command,sid,'POST'),
      form.hiddenFieldHTML('host',unicode(referralUrl.hostport),u''),
      form.hiddenFieldHTML('dn',unicode(referralUrl.dn),u''),
      login_fields,
    )
  )
  form.hiddenInputFields(outf,['sid','host','dn','who','cred','login_search_root'])
  outf.write('</form>\n')

  web2ldap.app.gui.Footer(outf,form)
