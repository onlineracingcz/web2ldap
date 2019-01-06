# -*- coding: utf-8 -*-
"""
web2ldap.app.bulkmod: modify several entries found by prior search

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

import web2ldapcnf

import web2ldap.ldapsession,web2ldap.ldaputil.base
import web2ldap.app.cnf,web2ldap.app.gui,web2ldap.app.ldapparams

# OID description dictionary from configuration directory
from web2ldap.ldaputil.oidreg import oid as oid_desc_reg

from web2ldap.app.schema.syntaxes import syntax_registry,LDAPSyntaxValueError


def input_modlist(sid, form, ls,sub_schema,bulkmod_at,bulkmod_op,bulkmod_av):

  mod_dict = {}
  input_errors = set()

  for i in range(len(bulkmod_at)):

    mod_op_str = bulkmod_op[i]
    if not mod_op_str:
      continue
    mod_op = int(mod_op_str)
    mod_type = bulkmod_at[i].encode(ls.charset)
    if not mod_type:
      continue

    attr_instance = syntax_registry.attrInstance(sid, form, ls,u'',sub_schema,mod_type,None,entry=None)
    try:
      mod_val = attr_instance.sanitizeInput(bulkmod_av[i] or '')
    except LDAPSyntaxValueError:
      mod_val = ''
      input_errors.add(i)
    try:
      attr_instance.validate(mod_val)
    except LDAPSyntaxValueError:
      input_errors.add(i)

    if mod_op==ldap0.MOD_INCREMENT:
      mod_dict[(mod_op,mod_type)] = set([None])
    elif not mod_val and mod_op==ldap0.MOD_DELETE:
      mod_dict[(mod_op,mod_type)] = set([None])
    elif mod_val and mod_op in (ldap0.MOD_DELETE,ldap0.MOD_ADD,ldap0.MOD_REPLACE):
      try:
        mod_dict[(mod_op,mod_type)].add(mod_val)
      except KeyError:
        mod_dict[(mod_op,mod_type)] = set([mod_val])

  mod_list = []
  if not input_errors:
    for mod_op,mod_type in mod_dict.keys():
      mod_vals = mod_dict[(mod_op,mod_type)]
      if mod_op==ldap0.MOD_DELETE and None in mod_vals:
        mod_vals = None
      mod_list.append((mod_op,mod_type,mod_vals))
    for i,m in enumerate(mod_list):
      if m[2]!=None:
        mod_list[i] = (m[0],m[1],list(m[2]))

  return mod_list,input_errors # input_modlist()


def bulkmod_input_form(
  sid,outf,command,form,ls,sub_schema,
  bulkmod_submit,
  dn,scope,bulkmod_filter,bulkmod_newsuperior,
  bulkmod_at,bulkmod_op,bulkmod_av,bulkmod_cp,
  input_errors,
):
  # Extend the input lists to at least one empty input row
  bulkmod_at = bulkmod_at or [u'']
  bulkmod_op = bulkmod_op or [u'']
  bulkmod_av = bulkmod_av or [u'']
  error_attrs = sorted(set([
    bulkmod_at[i]
    for i in input_errors
  ]))
  if error_attrs:
    Msg = '<p class="ErrorMessage">Invalid input: %s</p>' % (', '.join(map(form.utf2display,error_attrs)))
  else:
    Msg = '<p class="WarningMessage">Input bulk modify parameters here.</p>'
  if bulkmod_submit and bulkmod_submit.startswith('-'):
    del_row_num = int(bulkmod_submit[1:])
    if len(bulkmod_at)>1:
      del bulkmod_at[del_row_num]
      del bulkmod_op[del_row_num]
      del bulkmod_av[del_row_num]
  elif bulkmod_submit and bulkmod_submit.startswith('+'):
    insert_row_num = int(bulkmod_submit[1:])
    if len(bulkmod_at)<web2ldapcnf.max_searchparams:
      bulkmod_at.insert(insert_row_num+1,bulkmod_at[insert_row_num])
      bulkmod_op.insert(insert_row_num+1,bulkmod_op[insert_row_num])
      bulkmod_av.insert(insert_row_num+1,u'')
  # Generate a select field for the attribute type
  bulkmod_attr_select = web2ldap.app.gui.AttributeTypeSelectField(
    form,ls,sub_schema,
    'bulkmod_at',
    u'Attribute type',
    [],default_attr_options=None
  )
  # Output confirmation form
  web2ldap.app.gui.TopSection(
    sid, outf, command, form, ls, dn,
    'Bulk modification input',
    web2ldap.app.gui.MainMenu(sid, form, ls, dn),
  )
  input_fields = '\n'.join([
    """
    <tr>
      <td><button type="submit" name="bulkmod_submit" value="+%d">+</button></td>
      <td><button type="submit" name="bulkmod_submit" value="-%d">-</button></td>
      <td>%s</td><td>%s</td><td>%s %s</td>
    </tr>
    """ % (
      i,i,
      bulkmod_attr_select.inputHTML(default=bulkmod_at[i]),
      form.field['bulkmod_op'].inputHTML(default=bulkmod_op[i]),
      form.field['bulkmod_av'].inputHTML(default=bulkmod_av[i].decode(ls.charset)),
      (i in input_errors)*'&larr; Input error!'
    )
    for i in range(len(bulkmod_at))
  ])

  outf.write("""
{form_begin}
  {text_msg}
  <fieldset>
    <legend>Search parameters</legend>
    <table>
      <tr>
        <td>Search base:</td><td>{field_hidden_dn}</td>
      </tr>
      <tr>
        <td>Search scope:</td><td>{field_hidden_scope}</td>
      </tr>
      <tr>
        <td>Search filter:</td>
        <td>
          {field_hidden_filterstr}
        </td>
      </tr>
    </table>
  </fieldset>
  <fieldset>
    <legend>Bulk modify input</legend>
    <p><input type="submit" name="bulkmod_submit" value="Next&gt;&gt;"></p>
    <table>
    <tr>
      <td colspan="2">Superior DN:</td><td colspan="3">{field_bulkmod_newsuperior}</td>
    </tr>
    <tr>
      <td colspan="2">Copy entries:</td><td colspan="3">{field_bulkmod_cp}</td>
    </tr>
    {input_fields}
    </table>
  </fieldset>
  <fieldset>
    <legend>Extended controls</legend>
    {field_bulkmod_ctrl}
  </fieldset>
</form>
  """.format(
    text_msg=Msg,
    form_begin=form.beginFormHTML('bulkmod',sid,'POST'),
    field_bulkmod_ctrl=form.field['bulkmod_ctrl'].inputHTML(default=form.field['bulkmod_ctrl'].value),
    input_fields=input_fields,
    field_hidden_dn=form.hiddenFieldHTML('dn',dn,dn),
    field_hidden_filterstr=form.hiddenFieldHTML('filterstr',bulkmod_filter,bulkmod_filter),
    field_hidden_scope=form.hiddenFieldHTML('scope',unicode(scope),unicode(web2ldap.ldaputil.base.SEARCH_SCOPE_STR[scope])),
    field_bulkmod_newsuperior=form.field['bulkmod_newsuperior'].inputHTML(
      default=bulkmod_newsuperior,
      title=u'New superior DN where all entries are moved beneath'
    ),
    field_bulkmod_cp=form.field['bulkmod_cp'].inputHTML(checked=bulkmod_cp),
  ))
  web2ldap.app.gui.Footer(outf,form)
  return # bulkmod_input_form()


def bulkmod_confirmation_form(sid,outf,command,form,ls,sub_schema,dn,scope,bulkmod_filter,bulkmod_newsuperior,bulk_mod_list,bulkmod_cp):
  try:
    num_entries,num_referrals = ls.count(
      dn,
      scope,
      bulkmod_filter,
      sizelimit=1000,
    )
  except web2ldap.ldapsession.LDAPLimitErrors:
    num_entries,num_referrals = ('unknown','unknown')
  else:
    if num_entries==None:
      num_entries = 'unknown'
    else:
      num_entries = str(num_entries)
    if num_referrals==None:
      num_referrals = 'unknown'
    else:
      num_referrals = str(num_referrals)

  if bulk_mod_list:
    bulk_mod_list_ldif = web2ldap.app.modify.ModlistLDIF('cn=bulkmod-dummy',form,bulk_mod_list)
  else:
    bulk_mod_list_ldif = '- none -'

  # Output confirmation form
  web2ldap.app.gui.TopSection(
    sid, outf, command, form, ls, dn,
    'Modify entries?',
    web2ldap.app.gui.MainMenu(sid, form, ls, dn),
    main_div_id='Input'
  )
  outf.write("""
{form_begin}
  <p class="WarningMessage">
    Apply changes to entries found with search?
  </p>
  <table>
    <tr>
      <td>Search base:</td><td>{field_hidden_dn}</td>
    </tr>
    <tr>
      <td>Search scope:</td><td>{field_hidden_scope}</td>
    </tr>
    <tr>
      <td>Search filter:</td>
      <td>
        {field_hidden_filterstr}
      </td>
    </tr>
    <tr>
      <td># affected entries / referrals:</td>
      <td>
        {num_entries} / {num_referrals}
      </td>
    </tr>
  </table>
  <dl>
    <dt>LDIF change record:</dt>
    <dd>
      {text_ldifchangerecord}
    </dd>
    <dt>
      <strong>{text_bulkmod_cp}</strong> all entries beneath this new superior DN:
    </dt>
    <dd><strong>{field_bulkmod_newsuperior}</strong></dd>
    <dt>Additional extended controls to be used:</dt>
    <dd><ul>{field_bulkmod_ctrl}<ul></dd>
  </dl>
  {hidden_fields}
  <p class="WarningMessage">Are you sure?</p>
  <input type="submit" name="bulkmod_submit" value="&lt;&lt;Back">
  <input type="submit" name="bulkmod_submit" value="Apply">
  <input type="submit" name="bulkmod_submit" value="Cancel">
  '</form>
  """.format(
    form_begin=form.beginFormHTML('bulkmod',sid,'POST'),
    field_bulkmod_ctrl='\n'.join([
      '<li>%s (%s)</li>' % (
        form.utf2display(oid_desc_reg.get(ctrl_oid,(ctrl_oid,))[0]),
        form.utf2display(ctrl_oid),
      )
      for ctrl_oid in form.field['bulkmod_ctrl'].value or []
    ]) or '- none -',
    field_hidden_dn=form.hiddenFieldHTML('dn',dn,dn),
    field_hidden_filterstr=form.hiddenFieldHTML('filterstr',bulkmod_filter,bulkmod_filter),
    field_hidden_scope=form.hiddenFieldHTML('scope',unicode(scope),unicode(web2ldap.ldaputil.base.SEARCH_SCOPE_STR[scope])),
    field_bulkmod_newsuperior=form.hiddenFieldHTML('bulkmod_newsuperior',bulkmod_newsuperior,bulkmod_newsuperior),
    text_bulkmod_cp={False:u'Move',True:u'Copy'}[bulkmod_cp],
    num_entries=num_entries,
    num_referrals=num_referrals,
    text_ldifchangerecord=bulk_mod_list_ldif,
    hidden_fields=form.hiddenInputHTML(ignoreFieldNames=[
      'dn','scope','filterstr','bulkmod_submit','bulkmod_newsuperior',
    ]),
  ))
  web2ldap.app.gui.Footer(outf,form)
  return # bulkmod_confirmation_form()


def w2l_BulkMod(sid, outf, command, form, ls, dn,connLDAPUrl):

  sub_schema = ls.retrieveSubSchema(
    dn,
    web2ldap.app.cnf.GetParam(ls, '_schema',None),
    web2ldap.app.cnf.GetParam(ls, 'supplement_schema',None),
    web2ldap.app.cnf.GetParam(ls, 'schema_strictcheck',True),
  )

  bulkmod_submit = form.getInputValue('bulkmod_submit',[None])[0]

  bulkmod_at = form.getInputValue('bulkmod_at',[])
  bulkmod_op = form.getInputValue('bulkmod_op',[])
  bulkmod_av = form.getInputValue('bulkmod_av',[])

  bulkmod_cp = form.getInputValue('bulkmod_cp',[u''])[0]=='yes'

  scope = int(form.getInputValue('scope',[str(connLDAPUrl.scope or ldap0.SCOPE_BASE)])[0])

  bulkmod_filter = form.getInputValue('filterstr',[(connLDAPUrl.filterstr or '').decode(ls.charset)])[0] or u'(objectClass=*)'

  bulkmod_newsuperior = form.getInputValue('bulkmod_newsuperior',[u''])[0]

  # Generate a list of requested LDAPv3 extended controls to be sent along
  # with the modify requests
  bulkmod_ctrl_oids = form.getInputValue('bulkmod_ctrl',[])

  if not (len(bulkmod_at)==len(bulkmod_op)==len(bulkmod_av)):
    raise web2ldap.app.core.ErrorExit(u'Invalid bulk modification input.')

  bulk_mod_list,input_errors = input_modlist(sid, form, ls,sub_schema,bulkmod_at,bulkmod_op,bulkmod_av)

  if bulkmod_submit==u'Cancel':

    web2ldap.app.gui.SimpleMessage(
      sid, outf, command, form, ls, dn,
      'Canceled bulk modification.',
      '<p class="SuccessMessage">Canceled bulk modification.</p>',
      main_menu_list=web2ldap.app.gui.MainMenu(sid, form, ls, dn),
    )

  elif not (bulk_mod_list or bulkmod_newsuperior) or \
       input_errors or \
       bulkmod_submit==None or \
       bulkmod_submit==u'<<Back' or \
       bulkmod_submit.startswith(u'+') or \
       bulkmod_submit.startswith(u'-'):

    bulkmod_input_form(
      sid,outf,command,form,ls,sub_schema,
      bulkmod_submit,
      dn,scope,bulkmod_filter,
      bulkmod_newsuperior,
      bulkmod_at,bulkmod_op,bulkmod_av,bulkmod_cp,
      input_errors
    )

  elif bulkmod_submit==u'Next>>':

    bulkmod_confirmation_form(sid,outf,command,form,ls,sub_schema,dn,scope,bulkmod_filter,bulkmod_newsuperior,bulk_mod_list,bulkmod_cp)

  elif bulkmod_submit==u'Apply':

    bulkmod_ctrl_oids = form.getInputValue('bulkmod_ctrl',[])
    if ls.l.protocol_version>=ldap0.VERSION3:
      conn_server_ctrls = set([
        server_ctrl.controlType
        for server_ctrl in ls.l._serverctrls['**all**']+ls.l._serverctrls['**write**']+ls.l._serverctrls['modify']
      ])
      bulkmod_server_ctrls = list(set([
        ldap0.controls.LDAPControl(ctrl_oid,1,None)
        for ctrl_oid in bulkmod_ctrl_oids
        if not ctrl_oid in conn_server_ctrls
      ])) or None
    else:
      bulkmod_server_ctrls = None

    ldap_error_html = []

    begin_time_stamp = time.time()

    ldap_msgid = ls.l.search(dn.encode(ls.charset),scope,bulkmod_filter.encode(ls.charset),attrlist=['1.1'])
    result_iter = ls.l.results(ldap_msgid)

    result_ldif_html = []

    for _,result_list,_,_ in result_iter:
      for ldap_dn,_ in result_list:
        if ldap_dn is None:
          # this is likely a search continuation (referral)
          continue
        ldap_dn = ldap_dn.decode(ls.charset)
        # Apply the modify request
        if bulk_mod_list:
          try:
            ls.modifyEntry(ldap_dn,bulk_mod_list,serverctrls=bulkmod_server_ctrls)
          except ldap0.LDAPError as e:
            ldap_error_html.append(
              '<dt>%s</dt><dd>%s</dd>' % (form.utf2display(ldap_dn),form.utf2display(unicode(str(e))))
            )
          else:
            result_ldif_html.append(web2ldap.app.modify.ModlistLDIF(
              ldap_dn,form,bulk_mod_list
            ))
        # Apply the modrdn request
        if bulkmod_newsuperior:
          old_rdn,_ = web2ldap.ldaputil.base.split_rdn(ldap_dn)
          try:
            if bulkmod_cp:
              ls.copyEntry(ldap_dn,old_rdn,new_superior=bulkmod_newsuperior)
            else:
              ls.renameEntry(
                ldap_dn,
                old_rdn,
                new_superior=bulkmod_newsuperior,
                delold=web2ldap.app.cnf.GetParam(ls, 'bulkmod_delold', 0),
              )
          except ldap0.LDAPError as e:
            ldap_error_html.append(
              '<dt>%s</dt><dd>%s</dd>' % (form.utf2display(ldap_dn),form.utf2display(unicode(str(e))))
            )
          else:
            result_ldif_html.append('<p>%s %s beneath %s</p>' % (
              {False:'Moved',True:'Copied'}[bulkmod_cp],
              form.utf2display(ldap_dn),
              form.utf2display(bulkmod_newsuperior),
            ))

    end_time_stamp = time.time()

    error_messages = ''
    if ldap_error_html:
      error_messages = '<strong>Errors</strong><dl>%s</dl>' % (
        '\n'.join(ldap_error_html),
      )
    change_records = ''
    if result_ldif_html:
      change_records = '<strong>Successfully applied changes</strong><p>%s</p>' % (
        '\n'.join(result_ldif_html),
      )

    num_mods = len(result_ldif_html)
    num_errors = len(ldap_error_html)
    num_sum = num_mods+num_errors
    web2ldap.app.gui.SimpleMessage(
      sid, outf, command, form, ls, dn,
      'Modified entries',
      """
        <p class="SuccessMessage">Modified entries.</p>
        <table>
          <tr>
            <td>Modified entries:</td>
            <td>%d</td>
            <td>
              <meter min="0" max="%d" value="%d" optimum="%d" title="entries">%d</meter>
            </td>
          </tr>
          <tr>
            <td>Errors:</td>
            <td>%d</td>
            <td>
              <meter min="0" max="%d" value="%d" optimum="0" title="entries">%d</meter>
            </td>
          </tr>
          <tr><td>Search base:</td><td>%s</td></tr>
          <tr><td>Search scope:</td><td>%s</td></tr>
          <tr><td>Time elapsed:</td><td>%0.2f seconds</td></tr>
        </table>
        %s
        %s
          <p><input type="submit" name="bulkmod_submit" value="&lt;&lt;Back"></p>
        </form>
        %s
        %s
      """ % (
        num_mods,
        num_sum,num_mods,num_sum,num_mods,
        num_errors,
        num_sum,num_errors,num_errors,
        web2ldap.app.gui.DisplayDN(sid, form, ls, dn),
        web2ldap.ldaputil.base.SEARCH_SCOPE_STR[scope],
        end_time_stamp-begin_time_stamp,
        form.beginFormHTML('bulkmod',sid,'POST'),
        form.hiddenInputHTML(ignoreFieldNames=['bulkmod_submit']),
        error_messages,
        change_records,
      ),
      main_menu_list=web2ldap.app.gui.MainMenu(sid, form, ls, dn),
    )

  else:

    raise web2ldap.app.core.ErrorExit(u'Invalid bulk modification form data.')
