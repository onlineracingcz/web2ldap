# -*- coding: utf-8 -*-
"""
w2lapp.delete: delete one entry or several entries

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import time,pyweblib.forms,ldap,ldap.async,ldapsession,ldaputil.base, \
       w2lapp.core,w2lapp.cnf,w2lapp.gui,w2lapp.ldapparams

# OID description dictionary from configuration directory
from ldapoidreg import oid as oid_desc_reg

class DeleteLeafs(ldap.async.AsyncSearchHandler):
  """
  Class for deleting entries which are results of a search.

  DNs of Non-leaf entries are collected in DeleteLeafs.nonLeafEntries.
  """
  _entryResultTypes = set([
    ldap.RES_SEARCH_ENTRY,
    ldap.RES_SEARCH_RESULT,
  ])

  def __init__(self,l,treeDeleteControl,delete_server_ctrls):
    ldap.async.AsyncSearchHandler.__init__(self,l)
    self.serverctrls = delete_server_ctrls
    self.treeDeleteControl = treeDeleteControl

  def startSearch(self,searchRoot,searchScope,filterStr):
    if searchScope==ldap.SCOPE_BASE:
      raise ValueError, "Parameter searchScope must not be ldap.SCOPE_BASE."
    self.nonLeafEntries = []
    self.nonDeletableEntries = []
    self.deletedEntries = 0
    self.noSuchObjectCounter = 0
    ldap.async.AsyncSearchHandler.startSearch(
      self,
      searchRoot,
      searchScope,
      filterStr=filterStr,
      attrList=[
        'hasSubordinates','subordinateCount','numSubordinates','numAllSubordinates',
        'msDS-Approx-Immed-Subordinates'],
      attrsOnly=0,
    )

  def _processSingleResult(self,resultType,resultItem):
    if resultType in self._entryResultTypes:
      # Don't process search references
      dn,entry = resultItem[0],ldap.cidict.cidict(resultItem[1])
      try:
        hasSubordinates = entry['hasSubordinates'][0].upper()=='TRUE'
      except KeyError:
        # hasSubordinates not available => look at numeric subordinate counters
        hasSubordinates = None
        try:
          subordinateCount = int(
            entry.get('subordinateCount',
              entry.get('numSubordinates',
                entry.get('numAllSubordinates',
                  entry['msDS-Approx-Immed-Subordinates']
              )))[0])
        except KeyError:
          subordinateCount = None
      else:
        subordinateCount = None
      if not self.treeDeleteControl and (hasSubordinates or (subordinateCount or 0)>0):
        self.nonLeafEntries.append(dn)
      else:
        try:
          self._l.delete_ext_s(dn,serverctrls=self.serverctrls)
        except ldap.NO_SUCH_OBJECT:
          # Don't do anything if the entry is already gone except counting
          # these sub-optimal cases
          self.noSuchObjectCounter = self.noSuchObjectCounter+1
        except ldap.INSUFFICIENT_ACCESS:
          self.nonDeletableEntries.append(dn)
        except ldap.NOT_ALLOWED_ON_NONLEAF:
          if hasSubordinates is None and subordinateCount is None:
            self.nonLeafEntries.append(dn)
          # Next statements are kind of a safety net and should never be executed
          elif not hasSubordinates or subordinateCount==0:
            raise ValueError,"Entry %s is non-leaf but is announced as leaf! hasSubordinates: %s, subordinateCount: %s" % (
              repr(dn),repr(hasSubordinates),repr(subordinateCount)
            )
          else:
            raise ValueError,"Entry %s contains invalid subordinate value! hasSubordinates: %s, subordinateCount: %s" % (
              repr(dn),repr(hasSubordinates),repr(subordinateCount)
            )
        else:
          # The entry was correctly deleted
          self.deletedEntries += 1


def DeleteEntries(outf,ls,dn,scope,tree_delete_control,delete_server_ctrls,delete_filter,delete_timelimit=90):
  """
  Recursively delete entries below or including entry with name dn.
  """
  start_time = time.time()
  end_time = start_time + delete_timelimit
  delete_filter = (delete_filter or u'(objectClass=*)').encode(ls.charset)
  if scope==ldap.SCOPE_SUBTREE and tree_delete_control:
    # Try to directly delete the whole subtree with the tree delete control
    ls.l.delete_ext_s(dn,serverctrls=delete_server_ctrls)
    return True
  else:
    leafs_deleter = DeleteLeafs(ls.l,tree_delete_control,delete_server_ctrls)
    deleted_entries_count = 0
    non_leaf_entries = set()
    non_deletable_entries = set()
    while time.time()<=end_time:
      # Send something for keeping the connection to the user's web browser open
      outf.write('');outf.flush()
      try:
        leafs_deleter.startSearch(dn,scope,filterStr=delete_filter)
        leafs_deleter.processResults(timeout=ls.timeout)
      except ldap.NO_SUCH_OBJECT:
        break
      except (ldap.SIZELIMIT_EXCEEDED,ldap.ADMINLIMIT_EXCEEDED):
        deleted_entries_count += leafs_deleter.deletedEntries
        non_leaf_entries.update(leafs_deleter.nonLeafEntries)
        non_deletable_entries.update(leafs_deleter.nonDeletableEntries)
      else:
        deleted_entries_count += leafs_deleter.deletedEntries
        non_leaf_entries.update(leafs_deleter.nonLeafEntries)
        non_deletable_entries.update(leafs_deleter.nonDeletableEntries)
        break
    else:
      non_deletable_entries.update(non_leaf_entries)
    while non_leaf_entries and time.time()<=end_time:
      dn = non_leaf_entries.pop()
      if dn in non_deletable_entries:
        continue
      try:
        leafs_deleter.startSearch(dn,ldap.SCOPE_SUBTREE,filterStr=delete_filter)
        leafs_deleter.processResults(timeout=ls.timeout)
      except (ldap.SIZELIMIT_EXCEEDED,ldap.ADMINLIMIT_EXCEEDED):
        deleted_entries_count += leafs_deleter.deletedEntries
        non_leaf_entries.add(dn)
        non_leaf_entries.update(leafs_deleter.nonLeafEntries)
      else:
        deleted_entries_count += leafs_deleter.deletedEntries
        if leafs_deleter.deletedEntries==0:
          non_deletable_entries.add(dn)
          continue
        non_leaf_entries.update(leafs_deleter.nonLeafEntries)
      if time.time()>end_time:
        non_deletable_entries.update(non_leaf_entries)
        break
    else:
      non_deletable_entries.update(non_leaf_entries)
    return deleted_entries_count,non_deletable_entries # DeleteEntries()


def DelSingleEntryForm(sid,form,ls,dn):
  return """
  <p class="WarningMessage">Delete whole entry %s?</p>
  """ % (
    w2lapp.gui.DisplayDN(sid,form,ls,dn)
  )


def DelSubtreeForm(sid,form,ls,dn,scope):
  delete_scope_field = pyweblib.forms.Select(
    'scope',u'Scope of delete operation',1,
    options=(
      (str(ldap.SCOPE_BASE),'Only this entry'),
      (str(ldap.SCOPE_ONELEVEL),'All entries below this entry (recursive)'),
      (str(ldap.SCOPE_SUBTREE),'All entries including this entry (recursive)'),
    ),
    default=str(scope),
  )
  hasSubordinates,numSubordinates,numAllSubordinates = ls.subOrdinates(dn)
  if not hasSubordinates:
    return DelSingleEntryForm(sid,form,ls,dn)
  if numSubordinates:
    numSubordinates_html = '<p>Number of direct subordinates: %d</p>' % (numSubordinates)
  else:
    numSubordinates_html = ''
  if numAllSubordinates:
    numAllSubordinates_html = '<p>Total number of subordinates: %d</p>' % (numAllSubordinates)
  else:
    numAllSubordinates_html = ''

  return """
    <p class="WarningMessage">
      Delete entries found below {text_dn}?<br>
      {text_num_sub_ordinates}
      {text_num_all_sub_ordinates}
    </p>
    <table>
      <tr>
        <td>Scope:</td>
        <td>{field_delete_scope}</td>
      </tr>
      <tr>
        <td>Use tree delete control:</td>
        <td>
          <input type="checkbox"
                 name="delete_ctrl"
                 value="{value_delete_ctrl_oid}"{value_delete_ctrl_checked}>
        </td>
      </tr>
    </table>
    <p><strong>
        Use recursive delete with extreme care!
        Might take some time.
    </strong></p>
  """.format(
    text_dn=w2lapp.gui.DisplayDN(sid,form,ls,dn),
    text_num_sub_ordinates=numSubordinates_html,
    text_num_all_sub_ordinates=numAllSubordinates_html,
    field_delete_scope=delete_scope_field.inputHTML(),
    value_delete_ctrl_oid=ldapsession.CONTROL_TREEDELETE,
    value_delete_ctrl_checked=' checked'*int(
      ldapsession.CONTROL_TREEDELETE in ls.supportedControl and \
      not 'OpenLDAProotDSE' in ls.rootDSE.get('objectClass',[])
    ),
  )


def DelAttrForm(sid,form,ls,dn,entry,delete_attr):
  return """
  <p class="WarningMessage">Delete following attribute(s) of entry %s?</p>
  <p>%s</p>
  """ % (
    w2lapp.gui.DisplayDN(sid,form,ls,dn),
    '\n'.join([
      '<input type="checkbox" name="delete_attr" value="%s"%s>%s<br>' % (
        form.utf2display(attr_type,sp_entity='  '),
        ' checked'*(attr_type in entry),
        form.utf2display(attr_type),
      )
      for attr_type in delete_attr
    ]),
  )


def DelSearchForm(sid,form,ls,dn,scope,delete_filter):
  try:
    num_entries,num_referrals = ls.count(
      dn,
      scope,
      delete_filter,
      sizelimit=1000,
    )
  except ldapsession.LDAPLimitErrors:
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
  return """
  <p class="WarningMessage">
    Delete entries found with search?
  </p>
  <table>
  <tr>
    <td>Search base:</td><td>{text_dn}</td>
  </tr>
  <tr>
    <td>Search scope:</td><td>{text_scope}</td>
  </tr>
  <tr>
    <td>Delete filter:</td>
    <td>
      {value_delete_filter}
    </td>
  </tr>
  <tr>
    <td># affected entries / referrals:</td>
    <td>
      {num_entries} / {num_referrals}
    </td>
  </tr>
  </table>
  <input type="hidden" name="filterstr" value="{value_delete_filter}">
  <input type="hidden" name="scope" value="{value_delete_scope}">
  """.format(
    value_dn=form.utf2display(dn),
    text_dn=w2lapp.gui.DisplayDN(sid,form,ls,dn),
    text_scope=ldaputil.base.SEARCH_SCOPE_STR[scope],
    num_entries=num_entries,
    num_referrals=num_referrals,
    value_delete_filter=form.utf2display(delete_filter),
    value_delete_scope=form.utf2display(unicode(scope)),
  )


def w2l_Delete(sid,outf,command,form,ls,dn,connLDAPUrl):

  sub_schema = ls.retrieveSubSchema(
    dn,
    w2lapp.cnf.GetParam(ls,'_schema',None),
    w2lapp.cnf.GetParam(ls,'supplement_schema',None),
    w2lapp.cnf.GetParam(ls,'schema_strictcheck',True),
  )

  delete_confirm = form.getInputValue('delete_confirm',[None])[0]

  delete_attr = form.getInputValue('delete_attr',[a.decode('ascii') for a in connLDAPUrl.attrs or []])
  delete_attr.sort()
  if delete_attr:
    scope = ldap.SCOPE_BASE
  else:
    scope = int(form.getInputValue('scope',[str(connLDAPUrl.scope or ldap.SCOPE_BASE)])[0])

  delete_filter = form.getInputValue('filterstr',[connLDAPUrl.filterstr])[0]

  # Generate a list of requested LDAPv3 extended controls to be sent along
  # with a modify or delete request
  delete_ctrl_oids = form.getInputValue('delete_ctrl',[])
  delete_ctrl_tree_delete = ldapsession.CONTROL_TREEDELETE in delete_ctrl_oids

  if delete_confirm:

    if ls.l.protocol_version>=ldap.VERSION3:
      conn_server_ctrls = set([
        server_ctrl.controlType
        for server_ctrl in ls.l._serverctrls['**all**']+ls.l._serverctrls['**write**']+ls.l._serverctrls['delete_ext']
      ])
      delete_server_ctrls = [
        ldap.controls.LDAPControl(ctrl_oid,1,None)
        for ctrl_oid in delete_ctrl_oids
        if not ctrl_oid in conn_server_ctrls
      ] or None
    else:
      delete_server_ctrls = None

    if delete_confirm=='yes':

      # Recursive delete of whole sub-tree

      if scope!=ldap.SCOPE_BASE:

        ##########################################################
        # Recursive delete of entries in sub-tree
        ##########################################################

        begin_time_stamp = time.time()
        deleted_entries_count,non_deletable_entries = DeleteEntries(
          outf,ls,
          dn.encode(ls.charset),
          scope,
          delete_ctrl_tree_delete,
          delete_server_ctrls,
          delete_filter,
        )
        end_time_stamp = time.time()

        old_dn = dn
        if scope==ldap.SCOPE_SUBTREE and delete_filter==None:
          dn = ldaputil.base.ParentDN(dn)
          ls.setDN(dn)
        w2lapp.gui.SimpleMessage(
          sid,outf,command,form,ls,dn,
          'Deleted entries',
          """
            <p class="SuccessMessage">Deleted entries.</p>
            <table>
              <tr><td>Deleted entries:</td><td>%d</td></tr>
              <tr><td>Search base:</td><td>%s</td></tr>
              <tr><td>Search scope:</td><td>%s</td></tr>
              <tr><td>Time elapsed:</td><td>%0.2f seconds</td></tr>
              <tr><td>Skipped:</td><td>%d</td></tr>
            </table>
          """ % (
            deleted_entries_count,
            w2lapp.gui.DisplayDN(sid,form,ls,old_dn),
            ldaputil.base.SEARCH_SCOPE_STR[scope],
            end_time_stamp-begin_time_stamp,
            len(non_deletable_entries),
          ),
          main_menu_list=w2lapp.gui.MainMenu(sid,form,ls,dn),
          context_menu_list=w2lapp.gui.ContextMenuSingleEntry(sid,form,ls,dn)
        )

      elif scope==ldap.SCOPE_BASE and delete_attr:

        ##########################################################
        # Delete attribute(s) from an entry with modify request
        ##########################################################

        mod_list = [
          (ldap.MOD_DELETE,attr_type,None)
          for attr_type in delete_attr
        ]
        ls.modifyEntry(dn,mod_list,serverctrls=delete_server_ctrls)
        w2lapp.gui.SimpleMessage(
          sid,outf,command,form,ls,dn,
          'Deleted Attribute(s)',
          """
          <p class="SuccessMessage">Deleted attribute(s) from entry %s</p>
          <ul>
            <li>
            %s
            </li>
          </ul>
          """ % (
            w2lapp.gui.DisplayDN(sid,form,ls,dn),
            '</li>\n<li>'.join([
              form.hiddenFieldHTML('delete_attr',attr_type,attr_type)
              for attr_type in delete_attr
            ]),
          ),
          main_menu_list=w2lapp.gui.MainMenu(sid,form,ls,dn),
          context_menu_list=w2lapp.gui.ContextMenuSingleEntry(sid,form,ls,dn)
        )

      elif scope==ldap.SCOPE_BASE:

        ##########################################################
        # Delete a single whole entry
        ##########################################################

        ls.deleteEntry(dn)
        old_dn = dn
        dn = ldaputil.base.ParentDN(dn)
        ls.setDN(dn)
        w2lapp.gui.SimpleMessage(
          sid,outf,command,form,ls,dn,
          'Deleted Entry',
          '<p class="SuccessMessage">Deleted entry: %s</p>' % (
            w2lapp.gui.DisplayDN(sid,form,ls,old_dn)
          ),
          main_menu_list=w2lapp.gui.MainMenu(sid,form,ls,dn),
          context_menu_list=w2lapp.gui.ContextMenuSingleEntry(sid,form,ls,dn)
        )

    else:
      w2lapp.gui.SimpleMessage(
        sid,outf,command,form,ls,dn,
        'Canceled delete',
        '<p class="SuccessMessage">Canceled delete.</p>',
        main_menu_list=w2lapp.gui.MainMenu(sid,form,ls,dn),
        context_menu_list=w2lapp.gui.ContextMenuSingleEntry(sid,form,ls,dn)
      )

  else:

    ##########################################################
    # Show delete confirmation and delete mode select form
    ##########################################################


    # Read the editable attribute values of entry
    try:
      ldap_entry = ls.readEntry(
        dn,
        [a.encode(ls.charset) for a in delete_attr],
        search_filter='(objectClass=*)',
        no_cache=1,
        server_ctrls=None,
      )[0][1]
    except IndexError:
      ldap_entry = {}

    entry = ldaputil.schema.Entry(sub_schema,dn,ldap_entry)

    if delete_attr:
      inner_form = DelAttrForm(sid,form,ls,dn,entry,delete_attr)
    elif delete_filter:
      inner_form = DelSearchForm(sid,form,ls,dn,scope,delete_filter)
    else:
      inner_form = DelSubtreeForm(sid,form,ls,dn,scope)

    # Output confirmation form
    w2lapp.gui.TopSection(
      sid,outf,command,form,ls,dn,
      'Delete entry?',
      w2lapp.gui.MainMenu(sid,form,ls,dn),
      context_menu_list=w2lapp.gui.ContextMenuSingleEntry(sid,form,ls,dn)
    )

    outf.write("""
{form_begin}
  {inner_form}
  <dl>
    <dt>Additional extended controls to be used:</dt>
    <dd>{field_delete_ctrl}</dd>
  </dl>
  <p class="WarningMessage">Are you sure?</p>
  {field_hidden_dn}
  <input type="submit" name="delete_confirm" value="yes">
  <input type="submit" name="delete_confirm" value="no">
</form>
""".format(
      form_begin=form.beginFormHTML('delete',sid,'POST'),
      inner_form=inner_form,
      field_delete_ctrl=form.field['delete_ctrl'].inputHTML(default=delete_ctrl_oids),
      field_hidden_dn=form.hiddenFieldHTML('dn',dn,u''),
    ))
    w2lapp.gui.Footer(outf,form)

