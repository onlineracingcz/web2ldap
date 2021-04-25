# -*- coding: utf-8 -*-
"""
web2ldap.app.delete: delete one entry or several entries

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import time

import ldap0
from ldap0.res import SearchResultEntry

from ..web.forms import Select as SelectField
from ..ldaputil.asynch import AsyncSearchHandler
from ..ldapsession import CONTROL_TREEDELETE, LDAPLimitErrors
from .gui import (
    context_menu_single_entry,
    footer,
    main_menu,
    top_section,
)
from ..log import logger


DELETE_SUBTREE_FORM_TMPL = """
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
"""

DELETE_FORM_TEMPLATE = """
  {form_begin}
    {inner_form}
    <dl>
      <dt>Use extended controls:</dt>
      <dd>{field_delete_ctrl}</dd>
    </dl>
    <p class="WarningMessage">Are you sure?</p>
    {field_hidden_dn}
    <input type="submit" name="delete_confirm" value="yes">
    <input type="submit" name="delete_confirm" value="no">
  </form>
"""

DELETE_SEARCH_FORM_TMPL = """
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
"""

DELETE_ENTRIES_SUCCESS_TMPL = """
<p class="SuccessMessage">Deleted entries.</p>
<table>
  <tr><td>Deleted entries:</td><td>%d</td></tr>
  <tr><td>Search base:</td><td>%s</td></tr>
  <tr><td>Search scope:</td><td>%s</td></tr>
  <tr><td>Time elapsed:</td><td>%0.2f seconds</td></tr>
  <tr><td>Skipped:</td><td>%d</td></tr>
</table>
"""


class DeleteLeafs(AsyncSearchHandler):
    """
    Class for deleting entries which are results of a search.

    DNs of Non-leaf entries are collected in DeleteLeafs.nonLeafEntries.
    """
    _entryResultTypes = {
        ldap0.RES_SEARCH_ENTRY,
        ldap0.RES_SEARCH_RESULT,
    }

    def __init__(self, l, tree_delete_ctrl, delete_server_ctrls):
        AsyncSearchHandler.__init__(self, l)
        self.req_ctrls = delete_server_ctrls
        self.tree_delete_ctrl = tree_delete_ctrl

    def start_search(self, searchRoot, searchScope, filterStr):
        if searchScope == ldap0.SCOPE_BASE:
            raise ValueError('Parameter searchScope must not be ldap0.SCOPE_BASE.')
        self.nonLeafEntries = []
        self.nonDeletableEntries = []
        self.deletedEntries = 0
        self.noSuchObjectCounter = 0
        AsyncSearchHandler.start_search(
            self,
            searchRoot,
            searchScope,
            filterStr=filterStr,
            attrList=[
                'hasSubordinates',
                'subordinateCount',
                'numSubordinates',
                'numAllSubordinates',
                'msDS-Approx-Immed-Subordinates',
            ],
        )

    def _process_result(self, resultItem):
        # Don't process search references
        if not isinstance(resultItem, SearchResultEntry):
            return
        dn, entry = resultItem.dn_s, resultItem.entry_s
        try:
            hasSubordinates = entry['hasSubordinates'][0].upper() == 'TRUE'
        except KeyError:
            # hasSubordinates not available => look at numeric subordinate counters
            hasSubordinates = None
            try:
                subordinateCount = int(
                    entry.get(
                        'subordinateCount',
                        entry.get(
                            'numSubordinates',
                            entry.get(
                                'numAllSubordinates',
                                entry['msDS-Approx-Immed-Subordinates'])))[0]
                )
            except KeyError:
                subordinateCount = None
        else:
            subordinateCount = None
        if (
                not self.tree_delete_ctrl and
                (hasSubordinates or (subordinateCount or 0) > 0)
            ):
            logger.debug('Skipping deletion of non-leaf entry %r', dn)
            self.nonLeafEntries.append(dn)
            return
        logger.debug('Deleting entry %r', dn)
        try:
            self._l.delete_s(dn, req_ctrls=self.req_ctrls)
        except ldap0.NO_SUCH_OBJECT:
            # Don't do anything if the entry is already gone except counting
            # these sub-optimal cases
            self.noSuchObjectCounter += 1
        except ldap0.INSUFFICIENT_ACCESS:
            self.nonDeletableEntries.append(dn)
        except ldap0.NOT_ALLOWED_ON_NONLEAF:
            if hasSubordinates is None and subordinateCount is None:
                self.nonLeafEntries.append(dn)
            # Next statements are kind of a safety net and should never be executed
            else:
                raise ValueError(
                    'Non-leaf entry %r has hasSubordinates %r and subordinateCount %r' % (
                        dn, hasSubordinates, subordinateCount,
                    )
                )
        else:
            # The entry was correctly deleted
            self.deletedEntries += 1
        # end of _process_result()


def delete_entries(
        app,
        dn,
        scope,
        tree_delete_control,
        delete_server_ctrls,
        delete_filter,
        delete_timelimit=90,
    ):
    """
    Recursively delete entries below or including entry with name dn.
    """
    start_time = time.time()
    end_time = start_time + delete_timelimit
    delete_filter = delete_filter or '(objectClass=*)'
    if scope == ldap0.SCOPE_SUBTREE and tree_delete_control:
        # Try to directly delete the whole subtree with the tree delete control
        app.ls.l.delete_s(dn, req_ctrls=delete_server_ctrls)
        return (1, set())
    leafs_deleter = DeleteLeafs(app.ls.l, tree_delete_control, delete_server_ctrls)
    deleted_entries_count = 0
    non_leaf_entries = set()
    non_deletable_entries = set()
    while time.time() <= end_time:
        try:
            leafs_deleter.start_search(dn, scope, filterStr=delete_filter)
            leafs_deleter.process_results()
        except ldap0.NO_SUCH_OBJECT:
            break
        except (ldap0.SIZELIMIT_EXCEEDED, ldap0.ADMINLIMIT_EXCEEDED):
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
    while non_leaf_entries and time.time() <= end_time:
        dn = non_leaf_entries.pop()
        if dn in non_deletable_entries:
            continue
        try:
            leafs_deleter.start_search(dn, ldap0.SCOPE_SUBTREE, filterStr=delete_filter)
            leafs_deleter.process_results()
        except (ldap0.SIZELIMIT_EXCEEDED, ldap0.ADMINLIMIT_EXCEEDED):
            deleted_entries_count += leafs_deleter.deletedEntries
            non_leaf_entries.add(dn)
            non_leaf_entries.update(leafs_deleter.nonLeafEntries)
        else:
            deleted_entries_count += leafs_deleter.deletedEntries
            if leafs_deleter.deletedEntries == 0:
                non_deletable_entries.add(dn)
                continue
            non_leaf_entries.update(leafs_deleter.nonLeafEntries)
        if time.time() > end_time:
            non_deletable_entries.update(non_leaf_entries)
            break
    else:
        non_deletable_entries.update(non_leaf_entries)
    return deleted_entries_count, non_deletable_entries
    # end of delete_entries()


def del_singleentry_form(app):
    return '<p class="WarningMessage">Delete whole entry %s?</p>' % (
        app.display_dn(app.dn)
    )


def del_subtree_form(app, scope):
    delete_scope_field = SelectField(
        'scope', 'Scope of delete operation', 1,
        options=(
            (str(ldap0.SCOPE_BASE), 'Only this entry'),
            (str(ldap0.SCOPE_ONELEVEL), 'All entries below this entry (recursive)'),
            (str(ldap0.SCOPE_SUBTREE), 'All entries including this entry (recursive)'),
        ),
        default=str(scope),
    )
    hasSubordinates, numSubordinates, numAllSubordinates = app.ls.get_sub_ordinates(app.dn)
    if not hasSubordinates:
        return del_singleentry_form(app)
    if numSubordinates:
        numSubordinates_html = '<p>Number of direct subordinates: %d</p>' % (numSubordinates)
    else:
        numSubordinates_html = ''
    if numAllSubordinates:
        numAllSubordinates_html = '<p>Total number of subordinates: %d</p>' % (numAllSubordinates)
    else:
        numAllSubordinates_html = ''
    return DELETE_SUBTREE_FORM_TMPL.format(
        text_dn=app.display_dn(app.dn),
        text_num_sub_ordinates=numSubordinates_html,
        text_num_all_sub_ordinates=numAllSubordinates_html,
        field_delete_scope=delete_scope_field.input_html(),
        value_delete_ctrl_oid=CONTROL_TREEDELETE,
        value_delete_ctrl_checked=' checked'*int(
            CONTROL_TREEDELETE in app.ls.supportedControl and \
            not app.ls.is_openldap
        ),
    )


def del_attr_form(app, entry, delete_attr):
    return """
    <p class="WarningMessage">Delete following attribute(s) of entry %s?</p>
    <p>%s</p>
    """ % (
        app.display_dn(app.dn),
        '\n'.join([
            '<input type="checkbox" name="delete_attr" value="%s"%s>%s<br>' % (
                app.form.s2d(attr_type, sp_entity='  '),
                ' checked'*(attr_type in entry),
                app.form.s2d(attr_type),
            )
            for attr_type in delete_attr
        ]),
    )


def del_search_form(app, scope, delete_filter):
    try:
        num_entries, num_referrals = app.ls.count(
            app.dn,
            scope,
            delete_filter,
            sizelimit=1000,
        )
    except LDAPLimitErrors:
        num_entries, num_referrals = ('unknown', 'unknown')
    else:
        if num_entries is None:
            num_entries = 'unknown'
        else:
            num_entries = str(num_entries)
        if num_referrals is None:
            num_referrals = 'unknown'
        else:
            num_referrals = str(num_referrals)
    return DELETE_SEARCH_FORM_TMPL.format(
        text_dn=app.display_dn(app.dn),
        text_scope=ldap0.ldapurl.SEARCH_SCOPE_STR[scope],
        num_entries=num_entries,
        num_referrals=num_referrals,
        value_delete_filter=app.form.s2d(delete_filter),
        value_delete_scope=app.form.s2d(str(scope)),
    )


def w2l_delete(app):

    delete_confirm = app.form.getInputValue('delete_confirm', [None])[0]
    delete_attr = app.form.getInputValue(
        'delete_attr',
        [
            a.decode('ascii')
            for a in app.ldap_url.attrs or []
        ]
    )
    delete_filter = app.form.getInputValue('filterstr', [app.ldap_url.filterstr])[0]
    delete_attr.sort()
    if delete_attr:
        scope = ldap0.SCOPE_BASE
    else:
        scope = int(
            app.form.getInputValue(
                'scope',
                [str(app.ldap_url.scope or ldap0.SCOPE_BASE)],
            )[0]
        )

    # Generate a list of requested LDAPv3 extended controls to be sent along
    # with a modify or delete request
    delete_ctrl_oids = app.form.getInputValue('delete_ctrl', [])
    delete_ctrl_tree_delete = CONTROL_TREEDELETE in delete_ctrl_oids

    if delete_confirm is None:
        # First show delete confirmation and delete mode select form
        # Read the editable attribute values of entry
        ldap_res = app.ls.l.read_s(
            app.dn,
            filterstr='(objectClass=*)',
            attrlist=delete_attr,
            cache_ttl=-1.0,
        )
        entry = ldap0.schema.models.Entry(app.schema, app.dn, ldap_res.entry_as)
        if delete_attr:
            inner_form = del_attr_form(app, entry, delete_attr)
        elif delete_filter:
            inner_form = del_search_form(app, scope, delete_filter)
        else:
            inner_form = del_subtree_form(app, scope)
        # Output confirmation form
        top_section(
            app,
            'Delete entry?',
            main_menu(app),
            context_menu_list=[],
        )
        app.outf.write(
            DELETE_FORM_TEMPLATE.format(
                form_begin=app.begin_form('delete', 'POST'),
                inner_form=inner_form,
                field_delete_ctrl=app.form.field['delete_ctrl'].input_html(
                    default=delete_ctrl_oids
                ),
                field_hidden_dn=app.form.hidden_field_html('dn', app.dn, ''),
            )
        )
        footer(app)
        return

    if delete_confirm != 'yes':
        app.simple_message(
            'Canceled delete',
            '<p class="SuccessMessage">Canceled delete.</p>',
            main_menu_list=main_menu(app),
            context_menu_list=context_menu_single_entry(app)
        )
        return

    # determine extended controls to be sent with delete operation
    conn_server_ctrls = {
        server_ctrl.controlType
        for server_ctrl in app.ls.l._req_ctrls['**all**']+app.ls.l._req_ctrls['**write**']+app.ls.l._req_ctrls['delete']
    }
    delete_server_ctrls = [
        ldap0.controls.LDAPControl(ctrl_oid, True, None)
        for ctrl_oid in delete_ctrl_oids
        if ctrl_oid and ctrl_oid not in conn_server_ctrls
    ] or None

    # Recursive delete of whole sub-tree

    if scope != ldap0.SCOPE_BASE:

        # Recursive delete of entries in sub-tree
        #-----------------------------------------

        begin_time_stamp = time.time()
        deleted_entries_count, non_deletable_entries = delete_entries(
            app,
            app.dn,
            scope,
            delete_ctrl_tree_delete,
            delete_server_ctrls,
            delete_filter,
        )
        end_time_stamp = time.time()

        old_dn = app.dn
        if scope == ldap0.SCOPE_SUBTREE and delete_filter is None:
            app.dn = app.parent_dn
        app.simple_message(
            'Deleted entries',
            DELETE_ENTRIES_SUCCESS_TMPL % (
                deleted_entries_count,
                app.display_dn(old_dn),
                ldap0.ldapurl.SEARCH_SCOPE_STR[scope],
                end_time_stamp-begin_time_stamp,
                len(non_deletable_entries),
            ),
            main_menu_list=main_menu(app),
            context_menu_list=[],
        )

    elif scope == ldap0.SCOPE_BASE and delete_attr:

        ##########################################################
        # Delete attribute(s) from an entry with modify request
        ##########################################################

        mod_list = [
            (ldap0.MOD_DELETE, attr_type.encode('ascii'), None)
            for attr_type in delete_attr
        ]
        app.ls.modify(app.dn, mod_list, req_ctrls=delete_server_ctrls)
        app.simple_message(
            'Deleted Attribute(s)',
            """
            <p class="SuccessMessage">Deleted attribute(s) from entry %s</p>
            <ul>
              <li>
              %s
              </li>
            </ul>
            """ % (
                app.display_dn(app.dn),
                '</li>\n<li>'.join([
                    app.form.hidden_field_html('delete_attr', attr_type, attr_type)
                    for attr_type in delete_attr
                ]),
            ),
            main_menu_list=main_menu(app),
            context_menu_list=context_menu_single_entry(app)
        )

    elif scope == ldap0.SCOPE_BASE:

        # Delete a single whole entry
        #-----------------------------

        app.ls.l.delete_s(app.dn)
        old_dn = app.dn
        app.dn = app.parent_dn
        app.simple_message(
            'Deleted Entry',
            '<p class="SuccessMessage">Deleted entry: %s</p>' % (
                app.display_dn(old_dn)
            ),
            main_menu_list=main_menu(app),
            context_menu_list=[],
        )
