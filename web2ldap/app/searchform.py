# -*- coding: utf-8 -*-
"""
web2ldap.app.searchform: different search forms

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import types,ldap0,pyweblib.forms,web2ldap.app.core,web2ldap.app.gui,web2ldap.app.cnf

searchform_mode_text = {
  'adv':'Advanced',
  'base':'Basic',
  'exp':'Expert',
}

SEARCH_OPT_CONTAINS = u'({at}=*{av}*)'
SEARCH_OPT_DOESNT_CONTAIN = u'(!({at}=*{av}*))'
SEARCH_OPT_ATTR_EXISTS = u'({at}=*)'
SEARCH_OPT_ATTR_NOT_EXISTS = u'(!({at}=*))'
SEARCH_OPT_IS_EQUAL = u'({at}={av})'
SEARCH_OPT_IS_NOT = u'(!({at}={av}))'
SEARCH_OPT_BEGINS_WITH = u'({at}={av}*)'
SEARCH_OPT_ENDS_WITH = u'({at}=*{av})'
SEARCH_OPT_SOUNDS_LIKE = u'({at}~={av})'
SEARCH_OPT_GE_THAN = u'({at}>={av})'
SEARCH_OPT_LE_THAN = u'({at}<={av})'
SEARCH_OPT_DN_ATTR_IS = u'({at}:dn:={av})'
SEARCH_OPT_DN_SUBORDINATE = u'({at}:dnSubordinateMatch:={av})'
SEARCH_OPT_DN_SUBTREE = u'({at}:dnSubtreeMatch:={av})'
SEARCH_OPT_DN_ONE_LEVEL = u'({at}:dnOneLevelMatch:={av})'

search_options = (
  (SEARCH_OPT_IS_EQUAL,u'attribute value is'),
  (SEARCH_OPT_CONTAINS,u'attribute value contains'),
  (SEARCH_OPT_DOESNT_CONTAIN,u'attribute value does not contain'),
  (SEARCH_OPT_IS_NOT,u'attribute value is not'),
  (SEARCH_OPT_BEGINS_WITH,u'attribute value begins with'),
  (SEARCH_OPT_ENDS_WITH,u'attribute value ends with'),
  (SEARCH_OPT_SOUNDS_LIKE,u'attribute value sounds like'),
  (SEARCH_OPT_GE_THAN,u'attribute value greater equal than'),
  (SEARCH_OPT_LE_THAN,u'attribute value lesser equal than'),
  (SEARCH_OPT_DN_ATTR_IS,u'DN attribute value is'),
  (SEARCH_OPT_ATTR_EXISTS,u'entry has attribute'),
  (SEARCH_OPT_ATTR_NOT_EXISTS,u'entry does not have attribute'),
  (SEARCH_OPT_DN_SUBORDINATE,u'DN is subordinate of'),
  (SEARCH_OPT_DN_SUBTREE,u'DN within subtree'),
  (SEARCH_OPT_DN_ONE_LEVEL,u'DN is direct child of'),
)

SEARCH_SCOPE_STR_BASE = u'0'
SEARCH_SCOPE_STR_ONELEVEL = u'1'
SEARCH_SCOPE_STR_SUBTREE = u'2'
SEARCH_SCOPE_STR_SUBORDINATES = u'3'

SEARCH_SCOPE_OPTIONS = [
  (SEARCH_SCOPE_STR_BASE,u'Base'),
  (SEARCH_SCOPE_STR_ONELEVEL,u'One level'),
  (SEARCH_SCOPE_STR_SUBTREE,u'Sub tree'),
  (SEARCH_SCOPE_STR_SUBORDINATES,u'Subordinate'),
]


def SearchForm_exp(form,ls,dn,sub_schema,filterstr=''):
  """Output expert search form"""
  # expert search form for using LDAP filters
  filterstr = form.getInputValue('filterstr',[filterstr])[0]
  result = """
  <fieldset>
    <legend>LDAP filter string</legend>
    <input name="filterstr" maxlength="%d" size="%d" value="%s">
  </fieldset>
    """ % (
      form.field['filterstr'].maxLen,
      form.field['filterstr'].size,
      form.utf2display(filterstr),
    )
  return result # SearchForm_exp()


def SearchForm_base(form,ls,dn,sub_schema,searchform_template_name):
  """
  Output basic search form based on a HTML template configured
  with host-specific configuration parameter searchform_template
  """
  searchform_template_cfg = web2ldap.app.cnf.GetParam(ls,'searchform_template','')
  assert type(searchform_template_cfg)==types.DictType,TypeError("Host-specific parameter 'searchform_template' has invalid type")
  searchform_template = searchform_template_cfg.get(searchform_template_name,None)
  searchform_template_filename = web2ldap.app.gui.GetVariantFilename(searchform_template,form.accept_language)
  template_str = open(searchform_template_filename,'r').read()
  return template_str # SearchForm_base()


def SearchForm_adv(form,ls,dn,sub_schema):
  """advanced search form with select lists"""

  search_submit = form.getInputValue('search_submit',[u''])[0]

  # Get input values
  search_attr_list = form.getInputValue('search_attr',[u''])
  search_option_list = form.getInputValue('search_option',[None]*len(search_attr_list))
  search_mr_list = form.getInputValue('search_mr',[None]*len(search_attr_list))
  search_string_list = form.getInputValue('search_string',[u'']*len(search_attr_list))

  if search_submit.startswith('-'):
    del_row_num = int(search_submit[1:])
    if len(search_attr_list)>1:
      del search_option_list[del_row_num]
      del search_attr_list[del_row_num]
      del search_mr_list[del_row_num]
      del search_string_list[del_row_num]
  elif search_submit.startswith('+'):
    insert_row_num = int(search_submit[1:])
    if len(search_attr_list)<web2ldap.app.cnf.misc.max_searchparams:
      search_option_list.insert(insert_row_num+1,search_option_list[insert_row_num])
      search_attr_list.insert(insert_row_num+1,search_attr_list[insert_row_num])
      search_mr_list.insert(insert_row_num+1,search_mr_list[insert_row_num])
      search_string_list.insert(insert_row_num+1,u'')

  if not len(search_option_list)==len(search_attr_list)==len(search_string_list):
    raise web2ldap.app.core.ErrorExit(u'Invalid search form data.')

  search_mode = form.getInputValue('search_mode',[ur'(&%s)'])[0]

  search_mode_select = pyweblib.forms.Select(
    'search_mode',
    u'Search mode',1,
    options=[(ur'(&%s)',u'all'),(ur'(|%s)',u'any')],
    default=search_mode
  )
  search_mode_select.setCharset(form.accept_charset)

  search_attr_select = web2ldap.app.gui.AttributeTypeSelectField(
    form,ls,sub_schema,
    'search_attr',
    u'Search attribute type',
    search_attr_list,
    default_attr_options=web2ldap.app.cnf.GetParam(ls,'search_attrs',[])
  )

  mr_list = [u'']
  mr_list.extend(sorted([unicode(mr) for mr in sub_schema.name2oid[ldap0.schema.models.MatchingRule].keys()]))
  # Create a select field instance for matching rule name
  search_mr_select = pyweblib.forms.Select(
    'search_mr',u'Matching rule used',
    web2ldap.app.cnf.misc.max_searchparams,
    options=mr_list,
  )
  search_mr_select.setCharset(form.accept_charset)

  search_fields_html_list = []

  # Output a row of the search form
  for i in range(len(search_attr_list)):
    search_fields_html_list.append('\n'.join((
      '<tr>\n<td rowspan="2">',
      '<button type="submit" name="search_submit" value="+%d">+</button>' % (i),
      '<button type="submit" name="search_submit" value="-%d">-</button>' % (i),
      '</td>\n<td>',
      search_attr_select.inputHTML(default=search_attr_list[i]),
      search_mr_select.inputHTML(default=search_mr_list[i]),
      form.field['search_option'].inputHTML(default=search_option_list[i]),
      '</td></tr>\n<tr><td>',
      form.field['search_string'].inputHTML(default=search_string_list[i]),
      '</td></tr>',
    )))

  # Eigentliches Suchformular ausgeben
  result = """
    <fieldset>
      <legend>Search filter parameters</legend>
      Match %s of the following.<br>
      <table>%s</table>
    </fieldset>
    """ % (
      search_mode_select.inputHTML(),
      '\n'.join(search_fields_html_list),
      )
  return result # SearchForm_adv()


def w2l_SearchForm(
  sid,outf,command,form,ls,dn,
  Msg='',
  filterstr='',
  scope=ldap0.SCOPE_SUBTREE,
  search_root=None,
  searchform_mode=None,
):
  """Output a search form"""

  if Msg:
    msg_html = '<p class="ErrorMessage">%s</p>' % (Msg)
  else:
    msg_html = ''

  sub_schema = ls.retrieveSubSchema(
    dn,
    web2ldap.app.cnf.GetParam(ls,'_schema',None),
    web2ldap.app.cnf.GetParam(ls,'supplement_schema',None),
    web2ldap.app.cnf.GetParam(ls,'schema_strictcheck',True),
  )

  searchform_mode = searchform_mode or form.getInputValue('searchform_mode',[u'base'])[0]
  searchform_template_name = form.getInputValue('searchform_template',[u'_'])[0]

  naming_contexts = web2ldap.app.cnf.GetParam(ls,'naming_contexts',None)

  search_root = form.getInputValue('search_root',[search_root or ls.getSearchRoot(dn,naming_contexts)])[0]
  search_root_field = web2ldap.app.gui.SearchRootField(
    form,ls,dn,
    name='search_root',
    search_root_searchurl=web2ldap.app.cnf.GetParam(ls,'searchform_search_root_url',None),
    naming_contexts=naming_contexts,
  )
  search_root_field.setDefault(search_root)

  ContextMenuList = [
    form.applAnchor(
      'searchform',searchform_mode_text[mode],sid,
      [
        ('dn',dn),
        ('searchform_mode',mode),
        ('search_root',search_root),
        ('filterstr',filterstr),
        ('scope',str(scope)),
      ],
    )
    for mode in searchform_mode_text.keys()
    if mode!=searchform_mode
  ]

  searchform_template_cfg = web2ldap.app.cnf.GetParam(ls,'searchform_template','')
  if type(searchform_template_cfg)==types.DictType:
    for sftn in searchform_template_cfg.keys():
      if sftn!='_':
        ContextMenuList.append(form.applAnchor(
          'searchform',sftn,sid,
          [
            ('dn',dn),
            ('searchform_mode','base'),
            ('searchform_template',sftn),
            ('search_root',search_root),
            ('filterstr',filterstr),
            ('scope',str(scope)),
          ],
        ))

  if searchform_mode == u'base':
    # base search form with fixed input fields
    try:
      inner_searchform_html = SearchForm_base(form,ls,dn,sub_schema,searchform_template_name)
    except IOError:
      msg_html = '\n'.join((
        msg_html,
        '<p class="ErrorMessage">I/O error while loading search form template!</p>'
      ))
      inner_searchform_html = SearchForm_adv(form,ls,dn,sub_schema)
      searchform_mode = u'adv'
  elif searchform_mode == u'exp':
    # expert search form with single filter input field
    inner_searchform_html = SearchForm_exp(form,ls,dn,sub_schema,filterstr)
  elif searchform_mode == u'adv':
    # base search form with fixed input fields
    inner_searchform_html = SearchForm_adv(form,ls,dn,sub_schema)

  searchoptions_template_filename = web2ldap.app.gui.GetVariantFilename(
    web2ldap.app.cnf.GetParam(ls,'searchoptions_template',None),
    form.accept_language
  )
  searchoptions_template_str = open(searchoptions_template_filename,'r').read()

  web2ldap.app.gui.TopSection(
    sid,outf,command,form,ls,dn,
    '%s Search Form' % searchform_mode_text[searchform_mode],
    web2ldap.app.gui.MainMenu(sid,form,ls,dn),
    context_menu_list=ContextMenuList,
    main_div_id='Input'
  )

  outf.write("""
    {msg_html}
    {form_search_html}
      <input type="hidden" name="searchform_mode" value="{searchform_mode}">
      <input type="hidden" name="searchform_template" value="{searchform_template}">
      <p>
        <input type="submit" name="search_submit" value="Search">
        <input type="reset" value="Reset">
      </p>
      {inner_searchform_html}
      {form_dn_html}
      {searchoptions_template_str}
    </form>
  """.format(
    form_search_html=form.beginFormHTML('search',sid,'GET'),
    searchform_mode=form.utf2display(searchform_mode),
    searchform_template=form.utf2display(searchform_template_name),
    msg_html=msg_html,
    inner_searchform_html=inner_searchform_html,
    form_dn_html=form.hiddenFieldHTML('dn',dn,u''),
    searchoptions_template_str=searchoptions_template_str.format(
      field_search_root=search_root_field.inputHTML(),
      field_search_scope=form.field['scope'].inputHTML(
        default=form.getInputValue('scope',[unicode(scope)])[0]
      ),
      field_search_resnumber=form.field['search_resnumber'].inputHTML(
        default=unicode(web2ldap.app.cnf.GetParam(ls,'search_resultsperpage',10))
      ),
      field_search_lastmod=form.field['search_lastmod'].inputHTML(
        default=form.getInputValue('search_lastmod',[unicode(-1)])[0]
      ),
      value_search_attrs=form.utf2display(form.getInputValue('search_attrs',[''])[0]),
    ),
  ))

  web2ldap.app.gui.Footer(outf,form)
