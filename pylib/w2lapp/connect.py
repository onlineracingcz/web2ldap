# -*- coding: utf-8 -*-
"""
w2lapp.connect: present connect dialogue for choosing server

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

# Modules shipped with web2ldap
import types,time,pyweblib.forms,w2lapp.core,w2lapp.gui,w2lapp.cnf

##############################################################################
# Connect form
##############################################################################

def w2l_Connect(outf,form,env,Msg='Connect',ErrorMsg=''):

  connect_template_str = w2lapp.gui.ReadTemplate(
    form,None,None,u'connect form',
    tmpl_filename=w2lapp.cnf.misc.connect_template
  )

  if w2lapp.cnf.hosts.ldap_uri_list:
    uri_select_list = []
    for uri in w2lapp.cnf.hosts.ldap_uri_list:
      if type(uri)==types.TupleType:
        uri,description = uri
      else:
        description = w2lapp.cnf.ldap_def.get(
          uri,
          w2lapp.cnf.hosts.Web2LDAPConfig()
        ).__dict__.get('description',uri)
      uri_select_list.append((unicode(uri,'ascii'),description))
    uri_select_field = pyweblib.forms.Select('ldapurl',u'LDAP uri',1,options=uri_select_list)
    uri_select_field.charset = 'utf-8'
    uri_select_field_html = uri_select_field.inputHTML(title=u'List of pre-configured directories to connect to')
  else:
    uri_select_field_html = ''

  if ErrorMsg:
    ErrorMsg = '<p class="ErrorMessage">%s</p>' % (ErrorMsg)

  w2lapp.gui.TopSection(None,outf,'',form,None,None,'Connect',w2lapp.gui.EntryMainMenu(form,env),[])

  outf.write(connect_template_str.format(
    text_scriptname=form.env.get('SCRIPT_NAME','').decode('utf-8'),
    text_heading=Msg,
    text_error=ErrorMsg,
    form_begin=form.beginFormHTML('searchform',None,'GET',None),
    field_uri_select=uri_select_field_html,
    disable_start={0:'',1:'<!--'}[w2lapp.cnf.hosts.restricted_ldap_uri_list],
    disable_end={0:'',1:'-->'}[w2lapp.cnf.hosts.restricted_ldap_uri_list],
    value_currenttime=time.strftime(r'%Y%m%d%H%M%SZ',time.gmtime()),
  ))

  w2lapp.gui.Footer(outf,form)
