# -*- coding: utf-8 -*-
"""
web2ldap.app.add: add an entry

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import ldap0,ldap0.modlist,web2ldap.web.forms, \
       web2ldap.app.cnf,web2ldap.app.core,web2ldap.app.gui,web2ldap.app.schema,web2ldap.app.addmodifyform,web2ldap.app.modify

from ldap0.dn import escape_dn_chars
from ldap0.controls.readentry import PostReadControl

# Attribute types always ignored for add requests
ADD_IGNORE_ATTR_TYPES = {
  'entryDN',
  'entryCSN',
  'governingStructureRule',
  'hasSubordinates',
  'structuralObjectClass',
  'subschemaSubentry',
  'collectiveAttributeSubentries',
}


def ModlistTable(schema,modlist):
  """
  Return a string containing a HTML table showing attr type/value pairs
  """
  s = []
  s.append('<table summary="Modify list">')
  for attr_type,attr_value in modlist:
    if web2ldap.app.schema.no_humanreadable_attr(schema,attr_type):
      tablestr = '%s bytes of binary data' % (
        ' + '.join(
          [ str(len(x)) for x in attr_value ]
        )
      )
    else:
      tablestr = '<br>'.join([
        web2ldap.web.forms.escapeHTML(repr(v))
        for v in attr_value
      ])
    s.append('<tr><td>%s</td><td>%s</td></tr>' % (
      web2ldap.web.forms.escapeHTML(attr_type),tablestr
    )
  )
  s.append('</table>')
  return '\n'.join(s) # ModlistTable()


########################################################################
# Add new entry
########################################################################

def w2l_Add(sid,outf,command,form,ls,dn):

  sub_schema = ls.retrieveSubSchema(
    dn,
    web2ldap.app.cnf.GetParam(ls, '_schema',None),
    web2ldap.app.cnf.GetParam(ls, 'supplement_schema',None),
    web2ldap.app.cnf.GetParam(ls, 'schema_strictcheck',True),
  )

  input_modrow = form.getInputValue('in_mr',['.'])[0]

  if input_modrow[0]=='-':
    del_row_num = int(input_modrow[1:])
    del form.field['in_at'].value[del_row_num]
    del form.field['in_av'].value[del_row_num]
    # FIX ME! This is definitely not sufficient!
    del form.field['in_avi'].value[del_row_num]
  elif input_modrow[0]=='+':
    insert_row_num = int(input_modrow[1:])
    form.field['in_at'].value.insert(insert_row_num+1,form.field['in_at'].value[insert_row_num])
    form.field['in_av'].value.insert(insert_row_num+1,'')
    # FIX ME! This is definitely not sufficient!
    form.field['in_avi'].value.insert(insert_row_num+1,form.field['in_avi'].value[insert_row_num])

  add_clonedn = form.getInputValue('add_clonedn',[None])[0]
  add_template = form.getInputValue('add_template',[None])[0]
  invalid_attrs = None

  if add_clonedn:
    entry,_ = web2ldap.app.addmodifyform.ReadOldEntry(ls,add_clonedn,sub_schema,None,{'*':'*'})
    add_rdn,add_basedn = web2ldap.ldaputil.base.split_rdn(add_clonedn)
    add_rdn_dnlist = ldap0.dn.str2dn(add_rdn.encode(ls.charset))
    add_rdn = u'+'.join(['%s=' % (at) for at,_,_ in add_rdn_dnlist[0]]).decode(ls.charset)
    add_basedn = add_basedn or dn

  elif add_template:
    add_dn,entry = web2ldap.app.addmodifyform.ReadLDIFTemplate(ls,form,add_template)
    entry = ldap0.schema.models.Entry(sub_schema,None,entry)
    add_rdn,add_basedn = web2ldap.ldaputil.base.split_rdn(add_dn.decode(ls.charset))
    add_basedn = add_basedn or dn

  else:
    entry,invalid_attrs = web2ldap.app.modify.GetEntryfromInputForm(form,ls,dn,sub_schema)
    add_rdn = form.getInputValue('add_rdn',[''])[0]
    add_basedn = form.getInputValue('add_basedn',[dn])[0]

  if invalid_attrs:
    invalid_attr_types_ui = [
      form.utf2display(at)
      for at in sorted(invalid_attrs.keys())
    ]
    error_msg = 'Wrong syntax in following attributes: %s' % (
      ', '.join([
        '<a class="CommandLink" href="#in_a_%s">%s</a>' % (v,v)
        for v in invalid_attr_types_ui
      ])
    )
  else:
    error_msg = ''

  if add_clonedn or add_template or \
     not entry or invalid_attrs or \
     'in_mr' in form.inputFieldNames or \
     'in_oc' in form.inputFieldNames or \
     'in_ft' in form.inputFieldNames:
    web2ldap.app.addmodifyform.w2l_AddForm(
      sid,outf,'add',form,ls,dn,
      add_rdn,add_basedn,entry,
      Msg=error_msg,
      invalid_attrs=invalid_attrs,
    )
    return

  # Filter out empty values
  for attr_type,attr_values in entry.items():
    entry[attr_type] = filter(None,attr_values)

  # If rdn does not contain a complete RDN try to determine
  # the attribute type for forming the RDN.
  try:
    rdn_list = [ tuple(rdn_comp.split('=',1)) for rdn_comp in ldap0.dn.explode_rdn(add_rdn.encode(ls.charset)) ]
  except ldap0.DECODING_ERROR:
    web2ldap.app.addmodifyform.w2l_AddForm(
      sid,outf,'add',form,ls,dn,
      add_rdn,add_basedn,entry,
      Msg='Wrong format of RDN string.',
    )
    return

  # Automagically derive the RDN from the entry
  for i in range(len(rdn_list)):
    rdn_attr_type,rdn_attr_value = rdn_list[i]
    # Normalize old LDAPv2 RDN form
    if rdn_attr_type.lower().startswith('oid.'):
      rdn_attr_type = rdn_attr_type[4:]
    if entry.has_key(rdn_attr_type) and \
       (
         (not rdn_attr_value and len(entry[rdn_attr_type])==1) or rdn_attr_value in entry[rdn_attr_type]
       ):
      rdn_list[i] = rdn_attr_type,entry[rdn_attr_type][0]
    else:
      web2ldap.app.addmodifyform.w2l_AddForm(
      sid,outf,'add',form,ls,dn,
      add_rdn.decode(ls.charset),add_basedn,entry,
        Msg='Attribute <var>%s</var> required for RDN not in entry data.' % (
          form.utf2display(unicode(rdn_attr_type))
        ),
      )
      return

  # Join the list of RDN components to one RDN string
  rdn = '+'.join([
    '='.join((atype,escape_dn_chars(avalue or '')))
    for atype,avalue in rdn_list
  ])

  # Generate list of modifications
  modlist = ldap0.modlist.add_modlist(dict(entry.items()),ignore_attr_types=ADD_IGNORE_ATTR_TYPES)

  if not modlist:
    raise web2ldap.app.core.ErrorExit(u'Cannot add entry without attribute values.')

  if dn:
    new_dn = ','.join([rdn,add_basedn.encode(ls.charset)])
  else:
    # Makes it possible to add entries for a namingContext
    new_dn = rdn

  if PostReadControl.controlType in ls.supportedControl:
    add_serverctrls = [PostReadControl(criticality=False,attrList=['entryUUID'])]
  else:
    add_serverctrls = None

  # Try to add the new entry
  try:
    _,_,_,add_resp_ctrls = ls.l.add_s(
      new_dn,
      modlist,
      serverctrls=add_serverctrls
    )
  except ldap0.NO_SUCH_OBJECT as e:
    raise web2ldap.app.core.ErrorExit(
      u"""
      %s<br>
      Probably this superiour entry does not exist:<br>%s<br>
      Maybe wrong base DN in LDIF template?<br>
      """ % (
        web2ldap.app.gui.LDAPError2ErrMsg(e,form,ls.charset),
        web2ldap.app.gui.DisplayDN(sid, form, ls,add_basedn.decode(ls.charset),commandbutton=0),
    ))
  except (
    ldap0.ALREADY_EXISTS,
    ldap0.CONSTRAINT_VIOLATION,
    ldap0.INVALID_DN_SYNTAX,
    ldap0.INVALID_SYNTAX,
    ldap0.NAMING_VIOLATION,
    ldap0.OBJECT_CLASS_VIOLATION,
    ldap0.OTHER,
    ldap0.TYPE_OR_VALUE_EXISTS,
    ldap0.UNDEFINED_TYPE,
    ldap0.UNWILLING_TO_PERFORM,
  ),e:
    # Some error in user's input => present input form to edit input values
    web2ldap.app.addmodifyform.w2l_AddForm(
      sid,outf,'add',form,ls,dn,
      add_rdn.decode(ls.charset),add_basedn.decode(ls.charset),entry,
      Msg=web2ldap.app.gui.LDAPError2ErrMsg(e,form,ls.charset),
    )
  else:
    # Try to extract Post Read Entry response control
    prec_ctrls = [
      c
      for c in add_resp_ctrls or []
      if c.controlType == PostReadControl.controlType
    ]
    if prec_ctrls:
      new_dn = prec_ctrls[0].dn
    new_dn_u = new_dn.decode(ls.charset)
    web2ldap.app.gui.SimpleMessage(
      sid,outf,command,form,ls,dn,
      'Added Entry',
      """
      <p class="SuccessMessage">Successfully added new entry.</p>
      <p>%s</p>
      <dl>
        <dt>Distinguished name:</dt>
        <dd>%s</dd>
        <dt>Entry data:</dt>
        <dd>%s</dd>
      </dl>
      """ % (
        form.applAnchor('read','Read added entry',sid,[('dn',new_dn_u)],title=u'Display added entry %s' % new_dn_u),
        web2ldap.app.gui.DisplayDN(sid, form, ls,new_dn_u,commandbutton=0),
        ModlistTable(sub_schema,modlist)
      ),
      main_menu_list=web2ldap.app.gui.MainMenu(sid, form, ls, dn),
      context_menu_list=[]
    )
