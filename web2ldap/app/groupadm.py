# -*- coding: utf-8 -*-
"""
web2ldap.app.groupadm: add/delete user entry to/from group entries

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import ldap0,ldap0.cidict

import web2ldap.ldaputil.base
import web2ldap.app.core,web2ldap.app.gui

ACTION2MODTYPE = {'add':ldap0.MOD_ADD,'remove':ldap0.MOD_DELETE}

REQUESTED_GROUP_ATTRS = ['objectClass','cn','description']


def GroupSelectFieldHTML(
  ls,member_dn,form,
  groups_dict,
  field_name,field_title,
  group_search_root,dn_list,
  optgroup_bounds,
):
  optgroup_min_level,optgroup_max_level = optgroup_bounds
  # Generate a dict for <optgroup> tags
  if optgroup_min_level!=None or optgroup_max_level!=None:
    optgroup_dict = {None:[]}
    for dn in dn_list:
      try:
        colgroup_dn = u','.join(web2ldap.ldaputil.base.explode_dn(dn)[optgroup_min_level:optgroup_max_level])
      except (IndexError,ValueError):
        colgroup_dn = None
      if colgroup_dn:
        try:
          optgroup_dict[colgroup_dn].append(dn)
        except KeyError:
          optgroup_dict[colgroup_dn] = [dn]
    optgroup_list = []
    try:
      colgroup_memberdn = u','.join(web2ldap.ldaputil.base.explode_dn(member_dn)[optgroup_min_level:optgroup_max_level])
    except (IndexError,ValueError):
      colgroup_memberdn = None
    else:
      if colgroup_memberdn in optgroup_dict:
        optgroup_list.append(colgroup_memberdn)
    colgroup_authzdn = None
    if ls.who!=None:
      try:
        colgroup_authzdn = u','.join(web2ldap.ldaputil.base.explode_dn(ls.who)[optgroup_min_level:optgroup_max_level])
      except (IndexError,ValueError,ldap0.DECODING_ERROR):
        pass
      else:
        if colgroup_authzdn in optgroup_dict and colgroup_authzdn!=colgroup_memberdn:
          optgroup_list.append(colgroup_authzdn)
    optgroup_list.extend(sorted([
      dn
      for dn in optgroup_dict.keys()
      if dn!=None and dn!=colgroup_memberdn and dn!=colgroup_authzdn
    ],key=unicode.lower))
    optgroup_list.append(None)
  else:
    optgroup_dict = {None:dn_list}
    optgroup_list = [None]
  option_list = []
  for optgroup_dn in optgroup_list:
    if optgroup_dn:
      option_list.append('<optgroup label="%s">' % (form.utf2display(optgroup_dn)))
    for dn in sorted(optgroup_dict[optgroup_dn],key=unicode.lower):
      option_text = form.utf2display(unicode(
        groups_dict[dn].get(
          'cn',[dn[:-len(group_search_root) or len(dn)].encode(ls.charset)]
        )[0],
        ls.charset
      ))
      option_title = form.utf2display(unicode(
        groups_dict[dn].get(
          'description',[dn[:-len(group_search_root)].encode(ls.charset)]
        )[0],
        ls.charset
      ))
      option_list.append(
        ('<option value="%s" title="%s">%s</option>' % (
          form.utf2display(dn),option_title,option_text
        ))
      )
    if optgroup_dn:
      option_list.append('</optgroup>')
  return '<select size="15" multiple id="%s" name="%s" title="%s">\n%s\n</select>\n' % (
    field_name,
    field_name,
    field_title,
    '\n'.join(option_list)
  )


def w2l_GroupAdm(sid, outf, command, form, ls, dn,InfoMsg='',ErrorMsg=''):

  groupadm_defs = ldap0.cidict.cidict(web2ldap.app.cnf.GetParam(ls, 'groupadm_defs',{}))
  if not groupadm_defs:
    raise web2ldap.app.core.ErrorExit(u'Group admin options empty or not set.')
  groupadm_defs_keys = groupadm_defs.keys()

  all_membership_attrs = [
    gad[1]
    for gad in groupadm_defs.values()
    if not gad[1] is None
  ]

  sub_schema = ls.retrieveSubSchema(
    dn,
    web2ldap.app.cnf.GetParam(ls, '_schema', None),
    web2ldap.app.cnf.GetParam(ls, 'supplement_schema', None),
    web2ldap.app.cnf.GetParam(ls, 'schema_strictcheck',True),
  )

  result_dnlist = ls.readEntry(dn,all_membership_attrs)
  if not result_dnlist:
    raise web2ldap.app.core.ErrorExit(u'No search result when reading entry.')

  user_entry = ldap0.schema.models.Entry(sub_schema,dn,result_dnlist[0][1])

  # Extract form parameters
  group_search_root = form.getInputValue('groupadm_searchroot',[ls.getSearchRoot(dn)])[0]
  groupadm_view = int(form.getInputValue('groupadm_view',['1'])[0])
  groupadm_name = form.getInputValue('groupadm_name',[None])[0]

  filter_components = []
  for oc in groupadm_defs.keys():
    if len(groupadm_defs[oc])==3 and not groupadm_defs[oc][2]:
      continue
    group_member_attrtype,user_entry_attrtype = groupadm_defs[oc][:2]
    if user_entry_attrtype is None:
      user_entry_attrvalue = dn.encode(ls.charset)
    else:
      try:
        user_entry_attrvalue = user_entry[user_entry_attrtype][0]
      except KeyError:
        continue
    filter_components.append(
      (
        oc.strip(),
        group_member_attrtype.strip(),
        ldap0.filter.escape_filter_chars(user_entry_attrvalue)
      )
    )

  #################################################################
  # Search all the group entries
  #################################################################

  groupadm_filterstr_template = web2ldap.app.cnf.GetParam(ls, 'groupadm_filterstr_template',r'(|%s)')

  all_group_filterstr = groupadm_filterstr_template % (''.join(
    [
      '(objectClass=%s)' % (oc)
      for oc,attr_type,attr_value in filter_components
    ]
  ))
  if groupadm_name:
    all_group_filterstr = '(&(cn=*%s*)%s)' % (
      ldap0.filter.escape_filter_chars(groupadm_name.encode(ls.charset)),
      all_group_filterstr
    )

  all_groups_dict = {}

  try:
    msg_id = ls.l.search(
      group_search_root.encode(ls.charset),
      ldap0.SCOPE_SUBTREE,
      all_group_filterstr,
      attrlist=REQUESTED_GROUP_ATTRS,attrsonly=0,timeout=ls.timeout
    )
    for _,res_data,_,_ in ls.l.results(msg_id):
      for group_dn,group_entry in res_data:
        if group_dn!=None:
          all_groups_dict[unicode(group_dn,ls.charset)] = ldap0.cidict.cidict(group_entry)
  except ldap0.NO_SUCH_OBJECT:
    ErrorMsg = 'No such object! Did you choose a valid search base?'
  except (ldap0.SIZELIMIT_EXCEEDED,ldap0.TIMELIMIT_EXCEEDED):
    ErrorMsg = 'Size or time limit exceeded while searching group entries! Try to refine search parameters.'

  all_group_entries = all_groups_dict.keys()
  all_group_entries.sort(key=unicode.lower)

  #################################################################
  # Apply changes to group membership
  #################################################################

  if 'groupadm_add' in form.inputFieldNames or \
     'groupadm_remove' in form.inputFieldNames:

    ldaperror_entries = []
    successful_group_mods = []

    for action in ['add','remove']:
      for action_group_dn in form.getInputValue('groupadm_%s'%action,[]):
        group_dn = action_group_dn
        if not all_groups_dict.has_key(group_dn):
          # The group entry could have been removed in the mean time
          # => Ignore that condition
          continue
        modlist = []
        for oc in groupadm_defs_keys:
          if oc.lower() in [ v.lower() for v in all_groups_dict[group_dn].get('objectClass',[]) ]:
            group_member_attrtype,user_entry_attrtype = groupadm_defs[oc][0:2]
            if user_entry_attrtype is None:
              member_value = dn.encode(ls.charset)
            else:
              if not user_entry.has_key(user_entry_attrtype):
                raise web2ldap.app.core.ErrorExit(u"""
                  Object class %s requires entry to have member attribute %s.""" % (
                    oc,user_entry_attrtype
                  )
                )
              member_value = user_entry[user_entry_attrtype][0]
            modlist.append((ACTION2MODTYPE[action],group_member_attrtype,[member_value]))
        # Finally try to apply group membership modification(s) to single group entry
        if modlist:
          try:
            ls.modifyEntry(group_dn,modlist)
          except ldap0.LDAPError as e:
            ldaperror_entries.append((group_dn,modlist,web2ldap.app.gui.LDAPError2ErrMsg(e,form,ls.charset)))
          else:
            successful_group_mods.append((group_dn,modlist))

    if successful_group_mods:
      group_add_list = [
        (group_dn,modlist)
        for group_dn,modlist in successful_group_mods
        if modlist and modlist[0][0]==ldap0.MOD_ADD
      ]
      group_remove_list = [
        (group_dn,modlist)
        for group_dn,modlist in successful_group_mods
        if modlist and modlist[0][0]==ldap0.MOD_DELETE
      ]
      InfoMsg_list = ['<p class="SuccessMessage">Changed group membership</p>']
      if group_add_list:
        InfoMsg_list.append('<p>Added to:</p>')
        InfoMsg_list.append('<ul>')
        InfoMsg_list.extend([
          '<li>%s</li>' % (form.utf2display(group_dn))
          for group_dn,modlist in group_add_list
        ])
        InfoMsg_list.append('</ul>')
      if group_remove_list:
        InfoMsg_list.append('<p>Removed from:</p>')
        InfoMsg_list.append('<ul>')
        InfoMsg_list.extend([
          '<li>%s</li>' % (form.utf2display(group_dn))
          for group_dn,modlist in group_remove_list
        ])
        InfoMsg_list.append('</ul>')
      InfoMsg = '\n'.join(InfoMsg_list)

    if ldaperror_entries:
      ErrorMsg_list = [ErrorMsg]
      ErrorMsg_list.extend([
        'Error while modifying {group_dn}:<br>{error_msg}'.format(
          group_dn=form.utf2display(group_dn),
          error_msg=error_msg
        )
        for group_dn,modlist,error_msg in ldaperror_entries
      ])
      ErrorMsg = '<br>'.join(ErrorMsg_list)

  #################################################################
  # Search for groups the entry is member of
  #################################################################

  remove_group_filterstr = '(|%s)' % (''.join(
    [
      '(&(objectClass=%s)(%s=%s))' % (oc,attr_type,attr_value)
      for oc,attr_type,attr_value in filter_components
    ]
  ))

  remove_groups_dict = {}

  try:
    msg_id = ls.l.search(
      group_search_root.encode(ls.charset),
      ldap0.SCOPE_SUBTREE,
      remove_group_filterstr,
      attrlist=REQUESTED_GROUP_ATTRS,attrsonly=0,timeout=ls.timeout
    )
    for _,res_data,_,_ in ls.l.results(msg_id):
      for group_dn,group_entry in res_data:
        if group_dn!=None:
          remove_groups_dict[unicode(group_dn,ls.charset)] = ldap0.cidict.cidict(group_entry)
  except ldap0.NO_SUCH_OBJECT:
    ErrorMsg = 'No such object! Did you choose a valid search base?'
  except (ldap0.SIZELIMIT_EXCEEDED,ldap0.TIMELIMIT_EXCEEDED):
    # This should never happen if all groups could be retrieved
    ErrorMsg = 'Size or time limit exceeded while searching group entries!<br>Try to refine search parameters.'

  remove_group_dns = remove_groups_dict.keys()
  remove_group_dns.sort(key=unicode.lower)

  all_groups_dict.update(remove_groups_dict)

  remove_groups = [ group_dn for group_dn in remove_group_dns ]

  if not all_groups_dict:
    InfoMsg = 'No group entries found. Did you choose a valid search base or valid name?'

  #########################################################
  # Sort out groups the entry is not(!) a member of
  #########################################################

  add_groups = [
    group_dn
    for group_dn in all_group_entries
    if not remove_groups_dict.has_key(group_dn)
  ]

  #########################################################
  # HTML output
  #########################################################

  web2ldap.app.gui.TopSection(
    sid, outf, command, form, ls, dn,
    'Group membership',
    web2ldap.app.gui.MainMenu(sid, form, ls, dn),
    context_menu_list=[]
  )

  group_search_root_field = web2ldap.app.gui.SearchRootField(
    form,ls,dn,name='groupadm_searchroot'
  )
  group_search_root_field.charset = form.accept_charset
  group_search_root_field.setDefault(group_search_root)

  if ErrorMsg:
    outf.write('<p class="ErrorMessage">%s</p>' % (ErrorMsg))
  if InfoMsg:
    outf.write('<p class="InfoMessage">%s</p>' % (InfoMsg))

  if all_groups_dict:

    optgroup_bounds = web2ldap.app.cnf.GetParam(ls, 'groupadm_optgroup_bounds',(1,None))

    outf.write("""
      %s\n%s\n%s\n
        <input type="submit" value="Change Group Membership">
        <table summary="Group select fields">
          <tr>
            <td width="50%%">Add to...</td>
            <td width="50%%">Remove from...</td>
          </tr>
          <tr>
            <td width="50%%">%s</td>
            <td width="50%%">%s</td>
          </tr>
        </table>
      </form>
    """ % (
      # form for changing group membership
      form.beginFormHTML('groupadm',sid,'POST',target='_top'),
      form.hiddenFieldHTML('dn',dn,u''),
      form.hiddenFieldHTML('groupadm_searchroot',group_search_root,u''),
      GroupSelectFieldHTML(
        ls,dn,form,
        all_groups_dict,
        'groupadm_add','Groups to add to',
        group_search_root,
        add_groups,
        optgroup_bounds,
      ),
      GroupSelectFieldHTML(
        ls,dn,form,
        remove_groups_dict,
        'groupadm_remove','Groups to remove from',
        group_search_root,
        remove_groups,
        optgroup_bounds,
      ),
    ))

  outf.write("""%s\n%s\n
      <p><input type="submit" value="List"> group entries below: %s.</p>
      <p>where group name contains: %s</p>
      <p>List %s groups.</p>
    </form>
  """ % (
    # form for searching group entries
    form.beginFormHTML('groupadm',sid,'GET'),
    form.hiddenFieldHTML('dn',dn,u''),
    group_search_root_field.inputHTML(title='Search root for searching group entries'),
    form.field['groupadm_name'].inputHTML(),
    form.field['groupadm_view'].inputHTML(title='Group entries list',default=str(groupadm_view)),
  ))

  if groupadm_view:
    outf.write('<dl>\n')
    # Output a legend of all group entries
    for group_dn in {1:remove_groups,2:all_group_entries}[groupadm_view]:
      group_entry = all_groups_dict[group_dn]
      outf.write('<dt>%s | %s</dt>\n<dd>%s<br>\n(%s)<br>\n%s</dd>\n' % (
        ', '.join(group_entry.get('cn',[])),
        form.applAnchor('read','Read',sid,[('dn',group_dn)],title=u'Display group entry'),
        form.utf2display(group_dn),
        ', '.join(group_entry.get('objectClass',[])),
        '<br>'.join(group_entry.get('description',[]))
      ))
    outf.write('</dl>\n')

  web2ldap.app.gui.Footer(outf, form)
