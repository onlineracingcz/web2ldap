# -*- coding: utf-8 -*-
"""
web2ldap.app.rename: modify DN of an entry

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import ldap0,ldap0.ldapurl,pyweblib.forms,ldaputil.base, \
       web2ldap.app.core,web2ldap.app.cnf,web2ldap.app.gui,web2ldap.app.form,web2ldap.app.schema,web2ldap.app.schema.syntaxes

from web2ldap.app.schema.viewer import displayNameOrOIDList


def NewSuperiorField(sid,form,ls,dn,sub_schema,sup_search_url,old_superior_dn):

  class NewSuperiorSelectList(web2ldap.app.schema.syntaxes.DynamicDNSelectList):
    attr_value_dict = {'':u'- Root Naming Context -'}

    def __init__(self,sid,form,ls,dn,schema,attrType,attrValue,ldap_url):
      self.ldap_url = ldap_url
      web2ldap.app.schema.syntaxes.DynamicDNSelectList.__init__(self,sid,form,ls,dn,schema,attrType,attrValue)

  if not sup_search_url is None:
    attr_inst = NewSuperiorSelectList(sid,form,ls,dn,sub_schema,'rdn',old_superior_dn.encode(ls.charset),str(sup_search_url))
    nssf = attr_inst.formField()
    nssf.name='rename_newsuperior'
    nssf.text='New Superior DN'
  else:
    nssf = web2ldap.app.form.DistinguishedNameInput('rename_newsuperior','New Superior DN')
  nssf.setCharset(form.accept_charset)
  nssf.setDefault(old_superior_dn)
  return nssf # NewSuperiorField()


def w2l_Rename(sid,outf,command,form,ls,dn):

  sub_schema = ls.retrieveSubSchema(
    dn,
    web2ldap.app.cnf.GetParam(ls,'_schema',None),
    web2ldap.app.cnf.GetParam(ls,'supplement_schema',None),
    web2ldap.app.cnf.GetParam(ls,'schema_strictcheck',True),
  )
  rename_supsearchurl_cfg = web2ldap.app.cnf.GetParam(ls,'rename_supsearchurl',{})

  if not dn:
    raise web2ldap.app.core.ErrorExit(u'Rename operation not possible at - World - or RootDSE.')

  rename_newrdn = form.getInputValue('rename_newrdn',[None])[0]
  rename_newsuperior = form.getInputValue('rename_newsuperior',[None])[0]
  rename_delold = form.getInputValue('rename_delold',['no'])[0]=='yes'

  if rename_newrdn:

    # ---------------------------------------
    # Rename the entry based on user's input
    # ---------------------------------------

    # Modify the RDN
    old_dn = dn
    dn,entry_uuid = ls.renameEntry(
      dn,rename_newrdn,rename_newsuperior,delold=rename_delold
    )
    ls.setDN(dn)

    web2ldap.app.gui.SimpleMessage(
      sid,outf,command,form,ls,dn,
      'Renamed/moved entry',
      """<p class="SuccessMessage">Renamed/moved entry.</p>
      <dl><dt>Old name:</dt><dd>%s</dd>
      <dt>New name:</dt><dd>%s</dd></dl>""" % (
        web2ldap.app.gui.DisplayDN(sid,form,ls,old_dn),
        web2ldap.app.gui.DisplayDN(sid,form,ls,dn)
      ),
      main_menu_list=web2ldap.app.gui.MainMenu(sid,form,ls,dn),
      context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(sid,form,ls,dn,entry_uuid=entry_uuid)
    )

  else:

    # ---------------------------------------
    # Output input form
    # ---------------------------------------

    old_rdn,old_superior = ldaputil.base.SplitRDN(dn)

    form.field['rename_newrdn'].setDefault(old_rdn)

    rename_template_str = web2ldap.app.gui.ReadTemplate(form,ls,'rename_template',u'rename form')

    rename_supsearchurl = form.getInputValue('rename_supsearchurl',[None])[0]
    try:
      sup_search_url = ldap0.ldapurl.LDAPUrl(rename_supsearchurl_cfg[rename_supsearchurl])
    except KeyError:
      rename_newsupfilter = form.getInputValue('rename_newsupfilter',[None])[0]
      sup_search_url = ldap0.ldapurl.LDAPUrl()
      if rename_newsupfilter!=None:
        sup_search_url.urlscheme = 'ldap'
        sup_search_url.filterstr = (
          rename_newsupfilter or form.field['rename_newsupfilter'].default
        ).encode(ls.charset)
        sup_search_url.dn = form.getInputValue('rename_searchroot',[''])[0].encode(ls.charset)
        sup_search_url.scope  = int(form.getInputValue('scope',[str(ldap0.SCOPE_SUBTREE)])[0])
      else:
        sup_search_url = None

    if not sup_search_url is None:
      if sup_search_url.dn in ('_','..','.'):
        rename_searchroot_default = None
      else:
        rename_searchroot_default = sup_search_url.dn.decode(ls.charset)
      rename_newsupfilter_default = sup_search_url.filterstr.decode(ls.charset)
      scope_default = unicode(sup_search_url.scope)
    else:
      rename_searchroot_default = None
      rename_newsupfilter_default = form.field['rename_newsupfilter'].default
      scope_default = unicode(ldap0.SCOPE_SUBTREE)

    rename_search_root_field = web2ldap.app.gui.SearchRootField(form,ls,dn,name='rename_searchroot')
    rename_new_superior_field = NewSuperiorField(sid,form,ls,dn,sub_schema,sup_search_url,old_superior)

    name_forms_text = ''
    dit_structure_rule_html = ''

    if sub_schema.sed[ldap0.schema.models.NameForm]:
      # Determine if there are name forms defined for structural object class
      search_result = ls.readEntry(dn,['objectClass','structuralObjectClass','governingStructureRule'])
      if not search_result:
        # This should normally not happen, only if entry got deleted in between
        raise web2ldap.app.core.ErrorExit(u'Empty search result when reading entry to be renamed.')

      entry = ldaputil.schema.Entry(sub_schema,dn,search_result[0][1])

      # Determine possible name forms for new RDN
      rdn_options = entry.get_rdn_templates()
      if rdn_options:
        name_forms_text = '<p class="WarningMessage">Available name forms for RDN:<br>%s</p>' % (
          '<br>'.join(rdn_options)
        )

      # Determine LDAP search filter for building a select list for new superior DN
      # based on governing structure rule
      dit_structure_ruleids = entry.get_possible_dit_structure_rules(dn.encode(ls.charset))
      for dit_structure_ruleid in dit_structure_ruleids:
        sup_structural_ruleids,sup_structural_oc = sub_schema.get_superior_structural_oc_names(dit_structure_ruleid)
        if sup_structural_oc:
          rename_newsupfilter_default = '(|%s)' % (
            ''.join([
              '(objectClass=%s)' % (oc)
              for oc in sup_structural_oc
            ])
          ).decode(ls.charset)
          dit_structure_rule_html = 'DIT structure rules:<br>%s' % (
            '<br>'.join(
              displayNameOrOIDList(sid,form,dn,sub_schema,sup_structural_ruleids,ldap0.schema.models.DITStructureRule)
            )
          )

    if rename_supsearchurl_cfg:
      rename_supsearchurl_field = pyweblib.forms.Select('rename_supsearchurl',u'LDAP URL for searching new superior entry',1,options=[])
      rename_supsearchurl_field.setOptions(rename_supsearchurl_cfg.keys())

    # Output empty input form for new RDN
    web2ldap.app.gui.TopSection(
      sid,outf,command,form,ls,dn,
      'Rename Entry',
      web2ldap.app.gui.MainMenu(sid,form,ls,dn),
      context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(sid,form,ls,dn)
    )

    outf.write(
      rename_template_str.format(
        form_begin=form.beginFormHTML('rename',sid,'POST'),
        field_hidden_dn=form.hiddenFieldHTML('dn',dn,u''),
        field_rename_newrdn=form.field['rename_newrdn'].inputHTML(),
        field_rename_new_superior=rename_new_superior_field.inputHTML(),
        text_name_forms=name_forms_text,
        field_rename_supsearchurl=rename_supsearchurl_field.inputHTML(),
        value_rename_newsupfilter=form.utf2display(rename_newsupfilter_default),
        field_rename_search_root=rename_search_root_field.inputHTML(default=rename_searchroot_default),
        field_scope=form.field['scope'].inputHTML(default=scope_default),
        text_dit_structure_rule=dit_structure_rule_html,
      )
    )

    web2ldap.app.gui.Footer(outf,form)
