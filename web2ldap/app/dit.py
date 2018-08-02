# -*- coding: utf-8 -*-
"""
web2ldap.app.dit: do a tree search and display to the user

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

# Alltributes to be read for nodes
DIT_ATTR_LIST = [
  'objectClass',
  'structuralObjectClass',
  'displayName',
  'description',
  'hasSubordinates','subordinateCount',
  'numSubordinates',
  'numAllSubordinates', #  Siemens DirX
  'countImmSubordinates','countTotSubordinates', # Critical Path Directory Server
  'msDS-Approx-Immed-Subordinates' # MS Active Directory
]

import ldap0,web2ldap.app.gui

from web2ldap.ldaputil.base import explode_dn,SplitRDN,ParentDN
from web2ldap.app.gui import dn_anchor_hash


def decode_dict(d,charset):
  r = {}
  for k,v in d.items():
    r[k] = [ value.decode(charset) for value in v ]
  return r


def DIT_HTML(sid,outf,form,ls,anchor_dn,dit_dict,entry_dict,max_levels):

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

  # Start node's HTML
  r = ['<dl>']

  for dn,d in sorted(dit_dict.items()):

    # Handle special dict items
    size_limit = meta_results(d)

    # Generate anchor for this node
    if dn:
      rdn,_ = SplitRDN(dn)
    else:
      rdn = u'Root DSE'

    try:
      node_entry = entry_dict[dn]
    except KeyError:
      # Try to read the missing entry
      try:
        ldap_result = ls.readEntry(dn,DIT_ATTR_LIST)
        node_entry = decode_dict(ldap_result[0][1],ls.charset)
      except Exception:
        node_entry = {}

    if size_limit:
      partial_str = '<strong>...</strong>'
    else:
      partial_str = ''

    # Try to determine from entry's attributes if there are subordinates
    hasSubordinates = node_entry.get('hasSubordinates',['TRUE'])[0].upper()=='TRUE'
    try:
      subordinateCountFlag = int(node_entry.get('subordinateCount',node_entry.get('numAllSubordinates',node_entry.get('msDS-Approx-Immed-Subordinates',['1'])))[0])
    except ValueError:
      subordinateCountFlag = 1
    has_subordinates = hasSubordinates and subordinateCountFlag

    try:
      display_name_list = [form.utf2display(node_entry['displayName'][0]),partial_str]
    except KeyError:
      display_name_list = [form.utf2display(rdn),partial_str]
    display_name = ''.join(display_name_list)

    title_msg=u'\r\n'.join(
      (dn or u'Root DSE',node_entry.get('structuralObjectClass',[u''])[0])+tuple(node_entry.get('description',[]))
    )

    dn_anchor_id = dn_anchor_hash(dn)

    r.append('<dt id="%s">' % (form.utf2display(dn_anchor_id)))
    if has_subordinates:
      if dn==anchor_dn:
        link_text = '&lsaquo;&lsaquo;'
        next_dn = ParentDN(dn)
      else:
        link_text = '&rsaquo;&rsaquo;'
        next_dn = dn
      # Only display link if there are subordinate entries expected or unknown
      r.append(form.applAnchor(
          'dit',
          link_text,
          sid,[('dn',next_dn)],
          title=u'Browse from %s' % (next_dn),
          anchor_id=dn_anchor_id,
        )
      )
    else:
      # FIX ME! Better solution in pure CSS?
      r.append('&nbsp;&nbsp;&nbsp;&nbsp;')
    r.append('<span title="%s">%s</span>' % (
      form.utf2display(title_msg),
      display_name
    ))
    r.append(form.applAnchor(
        'read',
        '<span class="plus">&rsaquo;</span>',
        sid,[('dn',dn)],
        title=u'Read entry',
      )
    )
    r.append('</dt>')

    # Subordinate nodes' HTML
    r.append('<dd>')
    if max_levels and d:
      r.extend(DIT_HTML(sid,outf,form,ls,anchor_dn,d,entry_dict,max_levels-1))
    r.append('</dd>')

  # Finish node's HTML
  r.append('</dl>')

  return r # DIT_HTML()


def w2l_DIT(sid,outf,command,form,ls,dn):

  dn_components = explode_dn(dn)

  dit_dict = {}
  entry_dict = {}

  root_dit_dict = dit_dict

  dn_levels = len(dn_components)
  dit_max_levels = int(form.getInputValue('dit_max_levels',['10'])[0])
  cut_off_levels = max(0,dn_levels-dit_max_levels)

  for i in range(1,dn_levels-cut_off_levels+1):
    search_base = u','.join(dn_components[dn_levels-cut_off_levels-i:])
    dit_dict[search_base] = {}
    try:
      msg_id = ls.l.search(
        search_base.encode(ls.charset),
        ldap0.SCOPE_ONELEVEL,
        '(objectClass=*)',
        attrlist=DIT_ATTR_LIST,
        timeout=int(form.getInputValue('dit_search_timelimit',['10'])[0]),
        sizelimit=int(form.getInputValue('dit_search_sizelimit',['50'])[0]),
      )
      for res_type,res_data,_,_ in ls.l.results(msg_id):
        # FIX ME! Search continuations are ignored for now
        if res_type==ldap0.RES_SEARCH_REFERENCE:
          continue
        for res_dn,res_entry in res_data:
          res_dn = res_dn.decode(ls.charset)
          entry_dict[res_dn] = decode_dict(res_entry,ls.charset)
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
    outf_lines = DIT_HTML(
      sid,outf,form,ls,dn,
      root_dit_dict,entry_dict,
      dit_max_levels,
    )
  else:
    if dn:
      outf_lines = ['No results.']
    else:
      outf_lines = ['<p>No results for root search.</p>']
      for naming_context in ls.namingContexts:
        outf_lines.append('<p>%s %s</p>' % (
          form.applAnchor(
            'dit','&rsaquo;&rsaquo;',sid,
            (
              ('dn',naming_context),
            ),
            title=u'Display tree beneath %s' % (naming_context),
          ),
          form.utf2display(naming_context),
        )
      )

  web2ldap.app.gui.SimpleMessage(
    sid,outf,command,form,ls,dn,
    'Tree view',
    """
    <h1>Directory Information Tree</h1>
    <div id="DIT">%s</div>
    """ % ('\n'.join(outf_lines)),
    main_menu_list=web2ldap.app.gui.MainMenu(sid,form,ls,dn),
    context_menu_list=[]
  )

  return # w2l_DIT()
