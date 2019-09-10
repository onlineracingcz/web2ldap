# -*- coding: utf-8 -*-
"""
web2ldap.app.dit: do a tree search and display to the user

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0
from ldap0.dn import DNObj

import web2ldap.app.gui
from web2ldap.app.gui import dn_anchor_hash


# All attributes to be read for nodes
DIT_ATTR_LIST = [
    b'objectClass',
    b'structuralObjectClass',
    b'displayName',
    b'description',
    b'hasSubordinates',
    b'subordinateCount',
    b'numSubordinates',
    #  Siemens DirX
    b'numAllSubordinates',
    # Critical Path Directory Server
    b'countImmSubordinates',
    b'countTotSubordinates',
    # MS Active Directory
    b'msDS-Approx-Immed-Subordinates',
]


def decode_dict(d, charset):
    r = {}
    for k, v in d.items():
        r[k] = [
            value.decode(charset)
            for value in v
        ]
    return r


def dit_html(app, anchor_dn, dit_dict, entry_dict, max_levels):
    """
    Outputs HTML representation of a directory information tree (DIT)
    """

    def meta_results(d):
        """
        Side effect! This removes meta result data from d!
        """
        try:
            size_limit = d['_sizelimit_']
        except KeyError:
            size_limit = False
        else:
            del d['_sizelimit_']
        return size_limit

    assert isinstance(anchor_dn, DNObj), ValueError(
        'Expected anchor_dn to be DNObj, got %r' % (anchor_dn,),
    )

    # Start node's HTML
    r = ['<dl>']

    for dn, d in dit_dict.items():

        assert isinstance(dn, DNObj), ValueError(
            'Expected dn to be DNObj, got %r' % (dn,),
        )

        # Handle special dict items
        size_limit = meta_results(d)

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
                node_entry = decode_dict(
                    app.ls.l.read_s(
                        dn.encode(app.ls.charset),
                        attrlist=DIT_ATTR_LIST,
                    ) or {},
                    app.ls.charset,
                )
            except ldap0.LDAPError:
                node_entry = {}

        if size_limit:
            partial_str = '<strong>...</strong>'
        else:
            partial_str = ''

        # Try to determine from entry's attributes if there are subordinates
        hasSubordinates = node_entry.get('hasSubordinates', ['TRUE'])[0].upper() == 'TRUE'
        try:
            subordinateCountFlag = int(
                node_entry.get(
                    'subordinateCount',
                    node_entry.get(
                        'numAllSubordinates',
                        node_entry.get('msDS-Approx-Immed-Subordinates', ['1'])))[0]
            )
        except ValueError:
            subordinateCountFlag = 1
        has_subordinates = hasSubordinates and subordinateCountFlag

        try:
            display_name_list = [app.form.utf2display(node_entry['displayName'][0]), partial_str]
        except KeyError:
            display_name_list = [app.form.utf2display(str(rdn)), partial_str]
        display_name = ''.join(display_name_list)

        title_msg = u'\r\n'.join(
            (str(dn) or u'Root DSE', node_entry.get('structuralObjectClass', [u''])[0]) + \
            tuple(node_entry.get('description', []))
        )

        dn_anchor_id = dn_anchor_hash(dn)

        r.append('<dt id="%s">' % (app.form.utf2display(dn_anchor_id)))
        if has_subordinates:
            if dn == anchor_dn:
                link_text = '&lsaquo;&lsaquo;'
                next_dn = dn.parent()
            else:
                link_text = '&rsaquo;&rsaquo;'
                next_dn = dn
            # Only display link if there are subordinate entries expected or unknown
            r.append(
                app.anchor(
                    'dit', link_text,
                    [('dn', str(next_dn))],
                    title=u'Browse from %s' % (str(next_dn),),
                    anchor_id=dn_anchor_id,
                )
            )
        else:
            # FIX ME! Better solution in pure CSS?
            r.append('&nbsp;&nbsp;&nbsp;&nbsp;')
        r.append('<span title="%s">%s</span>' % (
            app.form.utf2display(title_msg),
            display_name
        ))
        r.append(
            app.anchor(
                'read', '&rsaquo;',
                [('dn', str(dn))],
                title=u'Read entry',
            )
        )
        r.append('</dt>')

        # Subordinate nodes' HTML
        r.append('<dd>')
        if max_levels and d:
            r.extend(dit_html(app, anchor_dn, d, entry_dict, max_levels-1))
        r.append('</dd>')

    # Finish node's HTML
    r.append('</dl>')

    return r # dit_html()


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
                search_base.encode(app.ls.charset),
                ldap0.SCOPE_ONELEVEL,
                '(objectClass=*)',
                attrlist=DIT_ATTR_LIST,
                timeout=app.cfg_param('dit_search_timelimit', 10),
                sizelimit=app.cfg_param('dit_search_sizelimit', 50),
            )
            for res in app.ls.l.results(msg_id):
                # FIX ME! Search continuations are ignored for now
                if res.rtype == ldap0.RES_SEARCH_REFERENCE:
                    continue
                for res_dn, res_entry in res.data:
                    res_dn = DNObj.from_str(res_dn.decode(app.ls.charset))
                    entry_dict[res_dn] = decode_dict(res_entry, app.ls.charset)
                    dit_dict[search_base][res_dn] = {}
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
                        app.form.utf2display(str(naming_context)),
                    )
                )

    app.simple_message(
        'Tree view',
        """
        <h1>Directory Information Tree</h1>
        <div id="DIT">%s</div>
        """ % ('\n'.join(outf_lines)),
        main_menu_list=web2ldap.app.gui.main_menu(app),
        context_menu_list=[]
    )

    return
