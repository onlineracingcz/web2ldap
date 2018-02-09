# -*- coding: utf-8 -*-
"""
w2lapp.referral: chase LDAP referrals

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import w2lapp.core,w2lapp.gui,w2lapp.cnf

from ldap0.ldapurl import LDAPUrl

ErrorMessageDiv = """
<h1>Error</h1>
<p class="ErrorMessage">
  %s
</p>
"""

def w2l_ChaseReferral(sid,outf,command,form,ls,dn,e):

  w2lapp.gui.TopSection(
    sid,outf,command,form,ls,dn,
    'Referral received',
    w2lapp.gui.MainMenu(sid,form,ls,dn),
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
    w2lapp.gui.Footer(outf,form)
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
      w2lapp.gui.Footer(outf,form)
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
      w2lapp.gui.Footer(outf,form)
      return

  login_template_str = w2lapp.gui.ReadTemplate(form,ls,'login_template',u'referral login form')

  login_search_root_field = w2lapp.gui.SearchRootField(form,ls,dn,name='login_search_root')
  login_fields = login_template_str.format(
    field_login_mech=form.field['login_mech'].inputHTML(),
    value_ldap_who=form.utf2display(ls.who),
    value_ldap_filter=form.utf2display(w2lapp.cnf.GetParam(ls,'binddnsearch',ur'(uid=%s)'),'utf-8'),
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

  w2lapp.gui.Footer(outf,form)
