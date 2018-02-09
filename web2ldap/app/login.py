# -*- coding: utf-8 -*-
"""
web2ldap.app.login: bind with a specific bind DN and password

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import time,web2ldap.app.core,web2ldap.app.gui,web2ldap.app.cnf

##############################################################################
# Login form
##############################################################################

def w2l_Login(
  sid,outf,command,form,ls,dn,connLDAPUrl,login_search_root,
  title_msg=u'Bind',
  login_msg='',
  who='',relogin=0,nomenu=0,
  login_default_mech=None
):
  """
  Provide a input form for doing a (re-)login
  """
  if 'login_who' in form.inputFieldNames:
    who = form.field['login_who'].value[0]

  if not ls._dn and dn:
    ls.setDN(dn)

  login_search_root_field = web2ldap.app.gui.SearchRootField(form,ls,dn,name='login_search_root')
  login_search_root_field.setDefault(login_search_root or u'')

  login_template_str = web2ldap.app.gui.ReadTemplate(form,ls,'login_template',u'login form')

  if nomenu:
    main_menu_list=[]
  else:
    main_menu_list=web2ldap.app.gui.MainMenu(sid,form,ls,dn)
  web2ldap.app.gui.TopSection(
    sid,outf,command,form,ls,dn,
    login_msg,
    main_menu_list,
    context_menu_list=[],
    main_div_id='Input'
  )

  if ls.rootDSE:
    form.field['login_mech'].setOptions(ls.rootDSE.get('supportedSASLMechanisms',None))

  # Determine the bind mech to be used from the form data or the key-word argument login_default_mech
  login_mech = form.getInputValue('login_mech',[login_default_mech] or '')[0]

  login_fields = login_template_str.format(
    field_login_mech=form.field['login_mech'].inputHTML(default=login_mech),
    value_ldap_who=form.utf2display(who),
    value_ldap_filter=form.utf2display(unicode(web2ldap.app.cnf.GetParam(ls,'binddnsearch',r'(uid=%s)'))),
    field_login_search_root=login_search_root_field.inputHTML(),
    field_login_authzid_prefix=form.field['login_authzid_prefix'].inputHTML(),
    value_submit={0:'Login',1:'Retry w/login'}[relogin],
    value_currenttime=time.strftime(r'%Y%m%d%H%M%SZ',time.gmtime()),
  )

  scope_str = form.getInputValue('scope',[None])[0]
  if not scope_str and connLDAPUrl.scope!=None:
    scope_str = unicode(connLDAPUrl.scope)
  if scope_str:
    scope_hidden_field = form.hiddenFieldHTML('scope',scope_str,u'')
  else:
    scope_hidden_field = ''

  filterstr = form.getInputValue('filterstr',[(connLDAPUrl.filterstr or '').decode(ls.charset)])[0]
  if filterstr:
    filterstr_hidden_field = form.hiddenFieldHTML('filterstr',filterstr,u'')
  else:
    filterstr_hidden_field = ''

  search_attrs_hidden_field = ''
  if command in ('search','searchform'):
    search_attrs = form.getInputValue('search_attrs',[u','.join(connLDAPUrl.attrs or [])])[0]
    if search_attrs:
      search_attrs_hidden_field = form.hiddenFieldHTML('search_attrs',search_attrs,u'')

  if login_msg:
    login_msg_html = '<p class="ErrorMessage">%s</p>' % (login_msg)
  else:
    login_msg_html = ''

  outf.write("""
  <h1>%s</h1>

  %s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s
"""  % (
      form.utf2display(title_msg),
      login_msg_html,
      form.beginFormHTML(command,None,'POST',None),
      form.hiddenFieldHTML('ldapurl',str(ls.ldapUrl('')).decode('ascii'),u''),
      form.hiddenFieldHTML('dn',dn,u''),
      form.hiddenFieldHTML('delsid',sid.decode('ascii'),u''),
      form.hiddenFieldHTML('conntype',unicode(int(ls.startTLSOption>0)),u''),
      scope_hidden_field,
      filterstr_hidden_field,
      login_fields,
      search_attrs_hidden_field,
    )
  )
  if relogin:
    outf.write(form.hiddenInputHTML(
      ignoreFieldNames=set([
        'sid','delsid',
        'ldapurl','conntype','host','who','cred','dn','scope','filterstr','search_attrs',
        'login_mech','login_authzid','login_authzid_prefix','login_realm',
        'login_search_root','login_filterstr'
      ])
    ))
  outf.write('</form>\n')
  web2ldap.app.gui.Footer(outf,form)

