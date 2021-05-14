# -*- coding: utf-8 -*-
"""
web2ldap.app.groupadm: add/delete user entry to/from group entries

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0
import ldap0.cidict
from ldap0.dn import DNObj
from ldap0.res import SearchResultEntry

from .gui import (
    footer,
    main_menu,
    search_root_field,
    top_section,
)
from . import ErrorExit

ACTION2MODTYPE = {
    'add': ldap0.MOD_ADD,
    'remove': ldap0.MOD_DELETE,
}

REQUESTED_GROUP_ATTRS = ['objectClass', 'cn', 'description']


def group_select_field(
        app,
        groups_dict,
        field_name,
        field_title,
        group_search_root,
        dn_list,
        optgroup_bounds,
    ):
    optgroup_min_level, optgroup_max_level = optgroup_bounds
    # Generate a dict for <optgroup> tags
    if optgroup_min_level is not None or optgroup_max_level is not None:
        optgroup_dict = {None:[]}
        for dn in dn_list:
            try:
                colgroup_dn = str(DNObj.from_str(dn).slice(optgroup_min_level, optgroup_max_level))
            except (IndexError, ValueError):
                colgroup_dn = None
            if colgroup_dn:
                try:
                    optgroup_dict[colgroup_dn].append(dn)
                except KeyError:
                    optgroup_dict[colgroup_dn] = [dn]
        optgroup_list = []
        try:
            colgroup_memberdn = str(app.dn_obj.slice(optgroup_min_level, optgroup_max_level))
        except (IndexError, ValueError):
            colgroup_memberdn = None
        else:
            if colgroup_memberdn in optgroup_dict:
                optgroup_list.append(colgroup_memberdn)
        colgroup_authzdn = None
        if app.ls.who is not None:
            try:
                colgroup_authzdn = str(
                    DNObj.from_str(app.ls.who).slice(optgroup_min_level, optgroup_max_level)
                )
            except (IndexError, ValueError, ldap0.DECODING_ERROR):
                pass
            else:
                if colgroup_authzdn in optgroup_dict and colgroup_authzdn != colgroup_memberdn:
                    optgroup_list.append(colgroup_authzdn)
        optgroup_list.extend(
            sorted(
                [
                    dn
                    for dn in optgroup_dict
                    if dn is not None and dn != colgroup_memberdn and dn != colgroup_authzdn
                ],
                key=str.lower
            )
        )
        optgroup_list.append(None)
    else:
        optgroup_dict = {None:dn_list}
        optgroup_list = [None]
    option_list = []
    for optgroup_dn in optgroup_list:
        if optgroup_dn:
            option_list.append('<optgroup label="%s">' % (app.form.s2d(optgroup_dn)))
        for dn in sorted(optgroup_dict[optgroup_dn], key=str.lower):
            option_text = app.form.s2d(
                groups_dict[dn].get(
                    'cn',
                    [dn[:-len(group_search_root) or len(dn)]]
                )[0],
            )
            option_title = app.form.s2d(
                groups_dict[dn].get(
                    'description',
                    [dn[:-len(group_search_root)]]
                )[0],
            )
            option_list.append((
                '<option value="%s" title="%s">%s</option>' % (
                    app.form.s2d(dn),
                    option_title,
                    option_text
                )
            ))
        if optgroup_dn:
            option_list.append('</optgroup>')
    return '<select size="15" multiple id="%s" name="%s" title="%s">\n%s\n</select>\n' % (
        field_name,
        field_name,
        field_title,
        '\n'.join(option_list)
    )


def w2l_groupadm(app, info_msg='', error_msg=''):

    groupadm_defs = ldap0.cidict.CIDict(app.cfg_param('groupadm_defs', {}))
    if not groupadm_defs:
        raise ErrorExit(u'Group admin options empty or not set.')
    groupadm_defs_keys = groupadm_defs.keys()

    all_membership_attrs = [
        gad[1]
        for gad in groupadm_defs.values()
        if not gad[1] is None
    ]

    search_result = app.ls.l.read_s(app.dn, attrlist=all_membership_attrs)
    if not search_result:
        raise ErrorExit(u'No search result when reading entry.')

    user_entry = ldap0.schema.models.Entry(app.schema, app.dn, search_result.entry_as)

    # Extract form parameters
    group_search_root = app.form.getInputValue('groupadm_searchroot', [app.naming_context])[0]
    groupadm_view = int(app.form.getInputValue('groupadm_view', ['1'])[0])
    groupadm_name = app.form.getInputValue('groupadm_name', [None])[0]

    filter_components = []
    for ocl in groupadm_defs.keys():
        if len(groupadm_defs[ocl]) == 3 and not groupadm_defs[ocl][2]:
            continue
        group_member_attrtype, user_entry_attrtype = groupadm_defs[ocl][:2]
        if user_entry_attrtype is None:
            user_entry_attrvalue = app.dn
        else:
            try:
                user_entry_attrvalue = user_entry[user_entry_attrtype][0].decode(app.ls.charset)
            except KeyError:
                continue
        filter_components.append((
            ocl.strip(),
            group_member_attrtype.strip(),
            ldap0.filter.escape_str(user_entry_attrvalue),
        ))

    #################################################################
    # Search all the group entries
    #################################################################

    groupadm_filterstr_template = app.cfg_param('groupadm_filterstr_template', r'(|%s)')

    all_group_filterstr = groupadm_filterstr_template % (
        ''.join(
            [
                '(objectClass=%s)' % (oc)
                for oc, attr_type, attr_value in filter_components
            ]
        )
    )
    if groupadm_name:
        all_group_filterstr = '(&(cn=*%s*)%s)' % (
            ldap0.filter.escape_str(groupadm_name),
            all_group_filterstr
        )

    all_groups_dict = {}

    try:
        msg_id = app.ls.l.search(
            str(group_search_root),
            ldap0.SCOPE_SUBTREE,
            all_group_filterstr,
            attrlist=REQUESTED_GROUP_ATTRS,
        )
        for res in app.ls.l.results(msg_id):
            for sre in res.rdata:
                if isinstance(sre, SearchResultEntry):
                    all_groups_dict[sre.dn_s] = ldap0.cidict.CIDict(sre.entry_s)
    except ldap0.NO_SUCH_OBJECT:
        error_msg = 'No such object! Did you choose a valid search base?'
    except (ldap0.SIZELIMIT_EXCEEDED, ldap0.TIMELIMIT_EXCEEDED):
        error_msg = 'Size or time limit exceeded while searching group entries!'

    all_group_entries = sorted(all_groups_dict.keys(), key=str.lower)

    #################################################################
    # Apply changes to group membership
    #################################################################

    if 'groupadm_add' in app.form.input_field_names or \
       'groupadm_remove' in app.form.input_field_names:

        ldaperror_entries = []
        successful_group_mods = []

        for action in ACTION2MODTYPE:

            for action_group_dn in app.form.getInputValue('groupadm_%s' % action, []):
                group_dn = action_group_dn
                if group_dn not in all_groups_dict:
                    # The group entry could have been removed in the mean time
                    # => Ignore that condition
                    continue
                modlist = []
                for ocl in groupadm_defs_keys:
                    if ocl.lower() in [
                            v.lower()
                            for v in all_groups_dict[group_dn].get('objectClass', [])
                        ]:
                        group_member_attrtype, user_entry_attrtype = groupadm_defs[ocl][0:2]
                        if user_entry_attrtype is None:
                            member_value = app.ldap_dn
                        else:
                            if user_entry_attrtype not in user_entry:
                                raise ErrorExit(
                                    u'Object class %s requires attribute %s in group entry.' % (
                                        ocl,
                                        user_entry_attrtype,
                                    )
                                )
                            member_value = user_entry[user_entry_attrtype][0]
                        modlist.append((
                            ACTION2MODTYPE[action],
                            group_member_attrtype.encode('ascii'),
                            [member_value],
                        ))
                # Finally try to apply group membership modification(s) to single group entry
                if modlist:
                    try:
                        app.ls.modify(group_dn, modlist)
                    except ldap0.LDAPError as err:
                        ldaperror_entries.append((
                            group_dn,
                            modlist,
                            app.ldap_error_msg(err),
                        ))
                    else:
                        successful_group_mods.append((group_dn, modlist))

        if successful_group_mods:
            group_add_list = [
                (group_dn, modlist)
                for group_dn, modlist in successful_group_mods
                if modlist and modlist[0][0] == ldap0.MOD_ADD
            ]
            group_remove_list = [
                (group_dn, modlist)
                for group_dn, modlist in successful_group_mods
                if modlist and modlist[0][0] == ldap0.MOD_DELETE
            ]
            info_msg_list = ['<p class="SuccessMessage">Changed group membership</p>']
            if group_add_list:
                info_msg_list.append('<p>Added to:</p>')
                info_msg_list.append('<ul>')
                info_msg_list.extend([
                    '<li>%s</li>' % (app.form.s2d(group_dn))
                    for group_dn, modlist in group_add_list
                ])
                info_msg_list.append('</ul>')
            if group_remove_list:
                info_msg_list.append('<p>Removed from:</p>')
                info_msg_list.append('<ul>')
                info_msg_list.extend([
                    '<li>%s</li>' % (app.form.s2d(group_dn))
                    for group_dn, modlist in group_remove_list
                ])
                info_msg_list.append('</ul>')
            info_msg = '\n'.join(info_msg_list)

        if ldaperror_entries:
            error_msg_list = [error_msg]
            error_msg_list.extend([
                'Error while modifying {group_dn}:<br>{error_msg}'.format(
                    group_dn=app.form.s2d(group_dn),
                    error_msg=error_msg
                )
                for group_dn, modlist, error_msg in ldaperror_entries
            ])
            error_msg = '<br>'.join(error_msg_list)

    #################################################################
    # Search for groups the entry is member of
    #################################################################

    remove_group_filterstr = '(|%s)' % (
        ''.join(
            [
                '(&(objectClass=%s)(%s=%s))' % (oc, attr_type, attr_value)
                for oc, attr_type, attr_value in filter_components
            ]
        )
    )

    remove_groups_dict = {}

    try:
        msg_id = app.ls.l.search(
            str(group_search_root),
            ldap0.SCOPE_SUBTREE,
            remove_group_filterstr,
            attrlist=REQUESTED_GROUP_ATTRS,
        )
        for res in app.ls.l.results(msg_id):
            for sre in res.rdata:
                if isinstance(sre, SearchResultEntry):
                    remove_groups_dict[sre.dn_s] = ldap0.cidict.CIDict(sre.entry_s)
    except ldap0.NO_SUCH_OBJECT:
        error_msg = 'No such object! Did you choose a valid search base?'
    except (ldap0.SIZELIMIT_EXCEEDED, ldap0.TIMELIMIT_EXCEEDED):
        error_msg = 'Size or time limit exceeded while searching group entries!'

    all_groups_dict.update(remove_groups_dict)

    remove_groups = sorted(remove_groups_dict.keys(), key=str.lower)

    if not all_groups_dict:
        info_msg = 'No group entries found. Did you choose a valid search base or valid name?'

    #########################################################
    # Sort out groups the entry is not(!) a member of
    #########################################################

    add_groups = [
        group_dn
        for group_dn in all_group_entries
        if group_dn not in remove_groups_dict
    ]

    #########################################################
    # HTML output
    #########################################################

    top_section(app, 'Group membership', main_menu(app), context_menu_list=[])

    group_search_root_field = search_root_field(
        app,
        name='groupadm_searchroot',
        default=str(group_search_root),
    )

    if error_msg:
        app.outf.write('<p class="ErrorMessage">%s</p>' % (error_msg))
    if info_msg:
        app.outf.write('<p class="InfoMessage">%s</p>' % (info_msg))

    if all_groups_dict:

        optgroup_bounds = app.cfg_param('groupadm_optgroup_bounds', (1, None))

        app.outf.write(
            """
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
                app.begin_form('groupadm', 'POST'),
                app.form.hidden_field_html('dn', app.dn, u''),
                app.form.hidden_field_html('groupadm_searchroot', str(group_search_root), u''),
                group_select_field(
                    app,
                    all_groups_dict,
                    'groupadm_add',
                    'Groups to add to',
                    group_search_root,
                    add_groups,
                    optgroup_bounds,
                ),
                group_select_field(
                    app,
                    remove_groups_dict,
                    'groupadm_remove',
                    'Groups to remove from',
                    group_search_root,
                    remove_groups,
                    optgroup_bounds,
                ),
            )
        )

    app.outf.write(
        """%s\n%s\n
          <p><input type="submit" value="List"> group entries below: %s.</p>
          <p>where group name contains: %s</p>
          <p>List %s groups.</p>
        </form>
        """ % (
            # form for searching group entries
            app.begin_form('groupadm', 'GET'),
            app.form.hidden_field_html('dn', app.dn, u''),
            group_search_root_field.input_html(title='Search root for searching group entries'),
            app.form.field['groupadm_name'].input_html(),
            app.form.field['groupadm_view'].input_html(
                title='Group entries list',
                default=str(groupadm_view),
            ),
        )
    )

    if groupadm_view:
        app.outf.write('<dl>\n')
        # Output a legend of all group entries
        for group_dn in {1: remove_groups, 2:all_group_entries}[groupadm_view]:
            group_entry = all_groups_dict[group_dn]
            app.outf.write('<dt>%s | %s</dt>\n<dd>%s<br>\n(%s)<br>\n%s</dd>\n' % (
                ', '.join(group_entry.get('cn', [])),
                app.anchor(
                    'read', 'Read',
                    [('dn', group_dn)],
                    title=u'Display group entry',
                ),
                app.form.s2d(group_dn),
                ', '.join(group_entry.get('objectClass', [])),
                '<br>'.join(group_entry.get('description', []))
            ))
        app.outf.write('</dl>\n')

    footer(app)
