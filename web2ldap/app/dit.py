# -*- coding: utf-8 -*-
"""
web2ldap.app.dit: do a tree search and display to the user

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0
from ldap0.dn import DNObj

from ..ldaputil import has_subordinates
from .gui import dn_anchor_hash, main_menu


# All attributes to be read for nodes
DIT_ATTR_LIST = [
    'objectClass',
    'structuralObjectClass',
    'displayName',
    'description',
    'hasSubordinates',
    'subordinateCount',
    'numSubordinates',
    #  Siemens DirX
    'numAllSubordinates',
    # Critical Path Directory Server
    'countImmSubordinates',
    'countTotSubordinates',
    # MS Active Directory
    'msDS-Approx-Immed-Subordinates',
]


def dit_html(app, anchor_dn, dit_dict, entry_dict, max_levels):
    """
    Outputs HTML representation of a directory information tree (DIT)
    """

    assert isinstance(anchor_dn, DNObj), ValueError(
        'Expected anchor_dn to be DNObj, got %r' % (anchor_dn,),
    )

    # Start node's HTML
    res = ['<dl>']

    for dn, ddat in dit_dict.items():

        assert isinstance(dn, DNObj), ValueError(
            'Expected dn to be DNObj, got %r' % (dn,),
        )

        try:
            size_limit = ddat['_sizelimit_']
        except KeyError:
            size_limit = False
        else:
            del ddat['_sizelimit_']

        # Generate anchor for this node
        if dn:
            rdn = dn.rdn()
        else:
            rdn = 'Root DSE'

        try:
            node_entry = entry_dict[dn]
        except KeyError:
            # Try to read the missing entry
            try:
                ldap_res = app.ls.l.read_s(str(dn), attrlist=DIT_ATTR_LIST)
            except ldap0.LDAPError:
                node_entry = {}
            else:
                node_entry = {} if ldap_res is None else ldap_res.entry_s

        if size_limit:
            partial_str = '<strong>...</strong>'
        else:
            partial_str = ''

        try:
            display_name_list = [app.form.s2d(node_entry['displayName'][0]), partial_str]
        except KeyError:
            display_name_list = [app.form.s2d(str(rdn)), partial_str]
        display_name = ''.join(display_name_list)

        title_msg = u'\r\n'.join(
            (str(dn) or u'Root DSE', node_entry.get('structuralObjectClass', [u''])[0]) + \
            tuple(node_entry.get('description', []))
        )

        dn_anchor_id = dn_anchor_hash(dn)

        res.append('<dt id="%s">' % (app.form.s2d(dn_anchor_id)))
        if has_subordinates(node_entry, default=True):
            if dn == anchor_dn:
                link_text = '&lsaquo;&lsaquo;'
                next_dn = dn.parent()
            else:
                link_text = '&rsaquo;&rsaquo;'
                next_dn = dn
            # Only display link if there are subordinate entries expected or unknown
            res.append(
                app.anchor(
                    'dit', link_text,
                    [('dn', str(next_dn))],
                    title=u'Browse from %s' % (str(next_dn),),
                    anchor_id=dn_anchor_id,
                )
            )
        else:
            # FIX ME! Better solution in pure CSS?
            res.append('&nbsp;&nbsp;&nbsp;&nbsp;')
        res.append('<span title="%s">%s</span>' % (
            app.form.s2d(title_msg),
            display_name
        ))
        res.append(
            app.anchor(
                'read', '&rsaquo;',
                [('dn', str(dn))],
                title=u'Read entry',
            )
        )
        res.append('</dt>')

        # Subordinate nodes' HTML
        res.append('<dd>')
        if max_levels and ddat:
            res.extend(dit_html(app, anchor_dn, ddat, entry_dict, max_levels-1))
        res.append('</dd>')

    # Finish node's HTML
    res.append('</dl>')

    return res # dit_html()


def w2l_dit(app):

    dit_dict = {}
    entry_dict = {}

    root_dit_dict = dit_dict

    dn_levels = len(app.dn_obj)
    dit_max_levels = app.cfg_param('dit_max_levels', 10)
    cut_off_levels = max(0, dn_levels-dit_max_levels)

    for i in range(1, dn_levels-cut_off_levels+1):
        search_base = app.dn_obj.slice(dn_levels-cut_off_levels-i, None)
        dit_dict[search_base] = {}
        try:
            msg_id = app.ls.l.search(
                str(search_base),
                ldap0.SCOPE_ONELEVEL,
                '(objectClass=*)',
                attrlist=DIT_ATTR_LIST,
                timeout=app.cfg_param('dit_search_timelimit', 10),
                sizelimit=app.cfg_param('dit_search_sizelimit', 50),
            )
            for ldap_result in app.ls.l.results(msg_id):
                # FIX ME! Search continuations are ignored for now
                if ldap_result.rtype == ldap0.RES_SEARCH_REFERENCE:
                    continue
                for res in ldap_result.rdata:
                    entry_dict[res.dn_o] = res.entry_s
                    dit_dict[search_base][res.dn_o] = {}
        except (
                ldap0.TIMEOUT,
                ldap0.SIZELIMIT_EXCEEDED,
                ldap0.TIMELIMIT_EXCEEDED,
                ldap0.ADMINLIMIT_EXCEEDED,
                ldap0.NO_SUCH_OBJECT,
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.PARTIAL_RESULTS,
                ldap0.REFERRAL,
            ):
            dit_dict[search_base]['_sizelimit_'] = True
        else:
            dit_dict[search_base]['_sizelimit_'] = False
        dit_dict = dit_dict[search_base]

    if root_dit_dict:
        outf_lines = dit_html(
            app,
            app.dn_obj,
            root_dit_dict,
            entry_dict,
            dit_max_levels,
        )
    else:
        if app.dn:
            outf_lines = ['No results.']
        else:
            outf_lines = ['<p>No results for root search.</p>']
            for naming_context in app.ls.namingContexts:
                outf_lines.append(
                    '<p>%s %s</p>' % (
                        app.anchor(
                            'dit', '&rsaquo;&rsaquo;',
                            (('dn', str(naming_context)),),
                            title=u'Display tree beneath %s' % (naming_context,),
                        ),
                        app.form.s2d(str(naming_context)),
                    )
                )

    app.simple_message(
        'Tree view',
        """
        <h1>Directory Information Tree</h1>
        <div id="DIT">%s</div>
        """ % ('\n'.join(outf_lines)),
        main_menu_list=main_menu(app),
        context_menu_list=[]
    )

    # end of w2l_dit()
