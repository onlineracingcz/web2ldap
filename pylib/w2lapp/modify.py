# -*- coding: utf-8 -*-
"""
w2lapp.modify: modify an entry

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import ldap,ldif,ldap.schema,ldaputil.schema, \
       ldapsession,w2lapp.core,w2lapp.cnf,w2lapp.gui,w2lapp.addmodifyform,w2lapp.add

from w2lapp.schema.syntaxes import syntax_registry,LDAPSyntaxValueError

try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO

from ldap.schema.models import AttributeType
from ldaputil.modlist2 import modifyModlist

def GetEntryfromInputForm(form,ls,dn,sub_schema):

  # Get all the attribute types
  in_attrtype_list = [
    a.encode('ascii')
    for a in form.getInputValue('in_at',[])
  ]
  # Grab the raw input strings
  in_value_indexes = [
    a for a in form.getInputValue('in_avi',[])
  ]
  # Grab the raw input strings
  in_value_list = [
    a for a in form.getInputValue('in_av',[])
  ]

  if not (len(in_attrtype_list)==len(in_value_list)==len(in_value_indexes)):
    raise w2lapp.core.ErrorExit(u'Different count of attribute types and values input.')

  entry = ldaputil.schema.Entry(sub_schema,dn.encode(ls.charset),{})

  # Stuff input field lists into raw dictionary
  for i,attr_type in enumerate(in_attrtype_list):
    try:
      entry[attr_type].append(in_value_list[i])
    except KeyError:
      entry[attr_type] = [in_value_list[i]]

  # Convert input field string representation into potential LDAP string representation
  # sanitize 'objectClass' first
  attr_type = 'objectClass'
  attr_values = []
  for in_value in entry.get(attr_type,[]):
    attr_instance = syntax_registry.attrInstance(None,form,ls,dn,sub_schema,attr_type,None,entry=entry)
    try:
      attr_value = attr_instance.sanitizeInput(in_value)
    except LDAPSyntaxValueError:
      attr_value = in_value
    attr_values.append(attr_value)
  entry[attr_type] = attr_values

  # sanitize rest of dict
  for attr_type,in_values in entry.items():
    if attr_type=='2.5.4.0':
      # ignore object class attribute herein
      continue
    attr_values = []
    for in_value in in_values:
      attr_instance = syntax_registry.attrInstance(None,form,ls,dn,sub_schema,attr_type,None,entry=entry)
      try:
        attr_value = attr_instance.sanitizeInput(in_value)
      except LDAPSyntaxValueError:
        attr_value = in_value
      attr_values.append(attr_value)
    entry[attr_type] = attr_values

  # extend entry with LDIF input
  try:
    in_ldif = form.field['in_ldif'].getLDIFRecords()
  except ValueError as e:
    raise w2lapp.core.ErrorExit(u'LDIF parsing error: %s' % (form.utf2display(unicode(e))))
  else:
    if in_ldif:
      entry.update(in_ldif[0][1])

  # Transmuting whole attribute value lists into final LDAP string
  # representation which may be an interative result
  iteration_count = 7
  entry_changed = True
  while entry_changed and iteration_count:
    iteration_count -= 1
    entry_changed = False
    for attr_type,attr_values in entry.items():
      attr_instance = syntax_registry.attrInstance(None,form,ls,dn,sub_schema,attr_type,None,entry=entry)
      try:
        new_values = attr_instance.transmute(attr_values)
      except (KeyError,IndexError):
        entry_changed = True
        entry[attr_type] = ['']
      else:
        entry_changed = entry_changed or (new_values!=attr_values)
        entry[attr_type] = new_values

  invalid_attrs = {}

  # Checking for invalid input done after sanitizing all values so
  # plugin classes can use all entry's attributes for cross-checking input
  for attr_type,attr_values in entry.items():
    attr_values = entry[attr_type]
    if not attr_values:
      del entry[attr_type]
      continue
    attr_instance = syntax_registry.attrInstance(None,form,ls,dn,sub_schema,attr_type,None,entry=entry)
    for attr_index,attr_value in enumerate(attr_values):
      if attr_value:
        try:
          attr_instance.validate(attr_value)
        except LDAPSyntaxValueError:
          try:
            invalid_attrs[unicode(attr_type)].append(attr_index)
          except KeyError:
            invalid_attrs[unicode(attr_type)] = [attr_index]

  return entry,invalid_attrs # GetEntryfromInputForm()


def ModlistLDIF(dn,form,modlist):
  """
  Return a string containing a HTML-formatted LDIF change record
  """
  s = []
  s.append('<pre>')
  f = StringIO()
  ldif_writer = ldif.LDIFWriter(f)
  ldif_writer.unparse(dn.encode('utf-8'),modlist)
  s.append(form.utf2display(f.getvalue().decode('utf-8')).replace('\n','<br>'))
  s.append('</pre>')
  return ''.join(s) # ModlistTable()


##############################################################################
# Modify existing entry
##############################################################################

def w2l_Modify(sid,outf,command,form,ls,dn):

  sub_schema = ls.retrieveSubSchema(
    dn,
    w2lapp.cnf.GetParam(ls,'_schema',None),
    w2lapp.cnf.GetParam(ls,'supplement_schema',None),
    w2lapp.cnf.GetParam(ls,'schema_strictcheck',True),
  )

  in_assertion = form.getInputValue('in_assertion',[u'(objectClass=*)'])[0]

  input_modrow = form.getInputValue('in_mr',['.'])[0]

  if input_modrow[0]=='-':
    del_row_num = int(input_modrow[1:])
    in_at_len = len(form.field['in_at'].value)
    if in_at_len>=del_row_num+2 and \
       form.field['in_at'].value[del_row_num]==form.field['in_at'].value[del_row_num+1] or \
       in_at_len>=1 and \
       form.field['in_at'].value[del_row_num]==form.field['in_at'].value[del_row_num-1]:
      # more input fields for same attribute type => pop()
      form.field['in_at'].value.pop(del_row_num)
      form.field['in_av'].value.pop(del_row_num)
    else:
      # only delete attribute value
      form.field['in_av'].value[del_row_num] = ''
    form.field['in_avi'].value = map(str,range(0,len(form.field['in_av'].value)))
  elif input_modrow[0]=='+':
    insert_row_num = int(input_modrow[1:])
    form.field['in_at'].value.insert(insert_row_num+1,form.field['in_at'].value[insert_row_num])
    form.field['in_av'].value.insert(insert_row_num+1,'')
    form.field['in_avi'].value = map(str,range(0,len(form.field['in_av'].value)))

  new_entry,invalid_attrs = w2lapp.modify.GetEntryfromInputForm(form,ls,dn,sub_schema)

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

  # Check if the user just switched/modified input form
  if 'in_ft' in form.inputFieldNames or \
     'in_oc' in form.inputFieldNames or \
     'in_mr' in form.inputFieldNames or \
     not new_entry or \
     invalid_attrs:
    w2lapp.addmodifyform.w2l_ModifyForm(
      sid,outf,'modify',form,ls,dn,
      new_entry,
      Msg=error_msg,
      invalid_attrs=invalid_attrs,
    )
    return

  in_oldattrtypes = {}
  for a in form.getInputValue('in_oldattrtypes',[]):
    attr_type = a.encode('ascii')
    in_oldattrtypes[attr_type] = None

  try:
    old_entry,dummy = w2lapp.addmodifyform.ReadOldEntry(ls,dn,sub_schema,in_assertion)
  except ldap.NO_SUCH_OBJECT:
    raise w2lapp.core.ErrorExit(u'Old entry was removed or modified in between! You have to edit it again.')

  # Filter out empty values
  for attr_type,attr_values in new_entry.items():
    new_entry[attr_type] = filter(None,attr_values)

  # Set up a dictionary of all attribute types to be ignored
  ignore_attr_types = ldaputil.schema.SchemaElementOIDSet(sub_schema,AttributeType,w2lapp.add.ADD_IGNORE_ATTR_TYPES)

  # Determine whether Relax Rules control is in effect
  relax_rules_enabled = ls.l._get_server_ctrls('**write**').has_key(ldapsession.CONTROL_RELAXRULES)

  if not relax_rules_enabled:
    # Add all attributes which have NO-USER-MODIFICATION set
    ignore_attr_types.update(sub_schema.no_user_mod_attr_oids)
    # Ignore attributes which are assumed to be constant (some operational attributes)
    ignore_attr_types.update(w2lapp.addmodifyform.ConfiguredConstantAttributes(ls).values())

  # All attributes currently read which were not visible before
  # must be ignored to avoid problems with different access rights
  # after possible re-login
  ignore_attr_types.update([
    a
    for a in old_entry.keys()
    if not in_oldattrtypes.has_key(a)
  ])

  old_entry_structural_oc = old_entry.get_structural_oc()
  # Ignore binary attributes from old entry data in any case
  for attr_type in old_entry.keys():
    syntax_class = syntax_registry.syntaxClass(sub_schema,attr_type,old_entry_structural_oc)
    if not syntax_class.editable:
      ignore_attr_types.add(attr_type)

  try:
    ignore_attr_types.remove('2.5.4.0')
  except KeyError:
    pass

  # Create modlist containing deltas
  modlist = modifyModlist(
    sub_schema,
    old_entry,new_entry,
    ignore_attr_types=ignore_attr_types,
    ignore_oldexistent=0,
  )
  # Binary values are always replaced
  new_entry_structural_oc = new_entry.get_structural_oc()
  for attr_type in new_entry.keys():
    syntax_class = syntax_registry.syntaxClass(sub_schema,attr_type,new_entry_structural_oc)
    if (not syntax_class.editable) and \
       new_entry[attr_type] and \
       (not attr_type in old_entry or new_entry[attr_type]!=old_entry[attr_type]):
      modlist.append((ldap.MOD_REPLACE,attr_type,new_entry[attr_type]))

  if modlist:
    # Send modify-list to host
    try:
      ls.modifyEntry(dn,modlist,assertion_filter=in_assertion)
    except ldap.ASSERTION_FAILED:
      raise w2lapp.core.ErrorExit(u'Assertion failed => Entry was removed or modified in between! You have to edit it again.')
    except (
      ldap.CONSTRAINT_VIOLATION,
      ldap.INVALID_DN_SYNTAX,
      ldap.INVALID_SYNTAX,
      ldap.NAMING_VIOLATION,
      ldap.OBJECT_CLASS_VIOLATION,
      ldap.OTHER,
      ldap.TYPE_OR_VALUE_EXISTS,
      ldap.UNDEFINED_TYPE,
      ldap.UNWILLING_TO_PERFORM,
    ),e:
      w2lapp.addmodifyform.w2l_ModifyForm(
        sid,outf,'modify',form,ls,dn,
        new_entry,
        Msg=w2lapp.gui.LDAPError2ErrMsg(e,form,ls.charset),
      )
      return
    else:
      # delete all cache entries referencing to old DN
      UserMsg = '<p class="SuccessMessage">Modified entry %s</p><p>%s</p><dt>LDIF change record:</dt>\n<dd>%s</dd>' % (
        w2lapp.gui.DisplayDN(sid,form,ls,dn),
        form.applAnchor('read','Read modified entry',sid,[('dn',dn)],title=u'Display modified entry %s' % dn),
        ModlistLDIF(dn,form,modlist),
      )
  else:
    UserMsg = '<p class="SuccessMessage">No attributes modified of entry %s</p><p>%s</p>' % (
      w2lapp.gui.DisplayDN(sid,form,ls,dn),
      form.applAnchor('read','Read entry',sid,[('dn',dn)],title=u'Display entry %s' % dn),
    )

  # Output comes here
  w2lapp.gui.SimpleMessage(
    sid,outf,command,form,ls,dn,
    'Modify result',
    UserMsg,
    main_menu_list=w2lapp.gui.MainMenu(sid,form,ls,dn),
    context_menu_list=w2lapp.gui.ContextMenuSingleEntry(sid,form,ls,dn)
  )

