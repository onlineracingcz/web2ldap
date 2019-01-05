# -*- coding: utf-8 -*-
"""
web2ldap.app.gui: basic functions for GUI elements

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time
import os
from types import UnicodeType
from hashlib import md5

import pyweblib.forms
from pyweblib.forms import escapeHTML

import ldap0
import ldap0.ldapurl
from ldap0.ldapurl import LDAPUrl
from ldap0.filter import escape_filter_chars

import web2ldapcnf

import web2ldap.__about__
import web2ldap.ldaputil,web2ldap.msbase

import web2ldap.app.core,web2ldap.app.cnf,web2ldap.app.schema.syntaxes,web2ldap.app.locate,web2ldap.app.searchform,web2ldap.app.monitor

import web2ldap.ldaputil.base
from web2ldap.ldaputil.base import \
  explode_dn,logdb_filter, \
  AD_LDAP49_ERROR_CODES,AD_LDAP49_ERROR_PREFIX

from web2ldap.msbase import GrabKeys

########################################################################
# Initialize some constants used throughout web2ldap
########################################################################

host_pattern = '[a-zA-Z0-9_.:\[\]-]+'

HIDDEN_FIELD = '<input type="hidden" name="%s" value="%s">%s\n'

# This function searches for variants
def GetVariantFilename(pathname,variantlist):
  checked_set = set()
  for v in variantlist:
    # Strip subtags
    v = v.lower().split('-',1)[0]
    if v=='en':
      variant_filename = pathname
    else:
      variant_filename = '.'.join((pathname,v))
    if not v in checked_set and os.path.isfile(variant_filename):
      break
    else:
      checked_set.add(v)
  else:
    variant_filename = pathname
  return variant_filename


def ReadTemplate(form,ls,config_key,form_desc=u'',tmpl_filename=None):
  if not tmpl_filename:
    tmpl_filename = web2ldap.app.cnf.GetParam(ls or '_',config_key,None)
  if not tmpl_filename:
    raise web2ldap.app.core.ErrorExit(u'No template specified for %s.' % (form_desc))
  tmpl_filename = web2ldap.app.gui.GetVariantFilename(tmpl_filename,form.accept_language)
  try:
    # Read template from file
    tmpl_str = open(tmpl_filename,'r').read()
  except IOError:
    raise web2ldap.app.core.ErrorExit(u'I/O error during reading %s template file.' % (form_desc))
  return tmpl_str # ReadTemplate()


def LDAPError2ErrMsg(e,form,charset='utf-8',template='{error_msg}<br>{matched_dn}'):
  """
  Converts a LDAPError exception into HTML error message

  e
    LDAPError instance
  form
    Web2LDAPForm instance
  charset
    Character set for decoding the LDAP error messages (diagnosticMessage)
  template
    Raw binary string to be used as template
    (must contain only a single placeholder)
  """

  matched_dn = None

  if isinstance(e,ldap0.TIMEOUT) or not e.args:

    ErrMsg = u''

  elif isinstance(e,ldap0.INVALID_CREDENTIALS) and \
       AD_LDAP49_ERROR_PREFIX in e.args[0].get('info',''):

    ad_error_code_pos = e.args[0]['info'].find(AD_LDAP49_ERROR_PREFIX)+len(AD_LDAP49_ERROR_PREFIX)
    ad_error_code = int(e.args[0]['info'][ad_error_code_pos:ad_error_code_pos+3],16)
    ErrMsg = u'%s:\n%s (%s)' % (
      unicode(e.args[0]['desc'],charset),
      unicode(e.args[0].get('info',''),charset),
      AD_LDAP49_ERROR_CODES.get(ad_error_code,u'unknown'),
    )

  else:

    try:
      ErrMsg = u':\n'.join((
        unicode(e.args[0]['desc'],charset),
        unicode(e.args[0].get('info',''),charset)
      ))
    except UnicodeDecodeError:
      ErrMsg = u':\n'.join((
        unicode(e.args[0]['desc'],charset),
        unicode(repr(e.args[0].get('info','')),charset)
      ))
    except TypeError:
      try:
        ErrMsg = u':\n'.join((
          unicode(e[0],charset),
          unicode(e[1],charset)
        ))
      except (TypeError,IndexError):
        ErrMsg = unicode(str(e),charset)
    else:
      try:
        matched_dn = unicode(e.args[0].get('matched',''),charset)
      except KeyError:
        matched_dn = None

  ErrMsg = ErrMsg.replace(u'\r','').replace(u'\t','')
  ErrMsg_html = form.utf2display(ErrMsg,lf_entity='<br>')

  # Add matchedDN to error message HTML if needed
  if matched_dn:
    matched_dn_html = '<br>Matched DN: %s' % (form.utf2display(matched_dn))
  else:
    matched_dn_html = ''

  return template.format(
    error_msg=ErrMsg_html,
    matched_dn=matched_dn_html
  )


def dn_anchor_hash(dn):
  return unicode(md5(dn.strip().lower().encode('utf-8')).hexdigest())


def ts2repr(time_divisors,ts_sep,ts_value):
  rest = long(ts_value)
  result = []
  for desc,divisor in time_divisors:
    mult = rest / divisor
    rest = rest % divisor
    if mult>0:
      result.append(u'%d %s' % (mult,desc))
    if rest==0:
      break
  return ts_sep.join(result)


def repr2ts(time_divisors,ts_sep,value):
  l1 = [ v.strip().split(u' ') for v in value.split(ts_sep) ]
  l2 = [
    (int(v),d.strip())
    for v,d in l1
  ]
  time_divisors_dict = dict(time_divisors)
  result = 0
  for value,desc in l2:
    try:
      result += value*time_divisors_dict[desc]
    except KeyError:
      raise ValueError
    else:
      del time_divisors_dict[desc]
  return result


def DisplayDN(sid,form,ls,dn,commandbutton=0):
  """Display a DN as LDAP URL with or without button"""
  assert type(dn)==UnicodeType, "Argument 'dn' must be UnicodeType"
  dn_str = form.utf2display(dn or u'- World -')
  if commandbutton:
    command_buttons = [
      dn_str,
      form.applAnchor('read','Read',sid,[('dn',dn)])
    ]
    return web2ldapcnf.command_link_separator.join(command_buttons)
  else:
    return dn_str


def CommandTableString(
  commandlist,
  div_id='CommandDiv',
  separator=' ',
  semantic_tag='nav',
):
  if semantic_tag:
    start_tag = '<%s>' % semantic_tag
    end_tag = '<%s>' % semantic_tag
  else:
    start_tag = ''
    end_tag = ''
  if commandlist:
    return '%s<p id="%s" class="CommandTable">\n%s\n</p>%s\n' % (
      start_tag,
      div_id,
      (separator).join(commandlist),
      end_tag,
    )
  else:
    return ''
  return # CommandTableString()


def CommandTable(
  outf,
  commandlist,
  div_id='CommandDiv',
  separator=' ',
  semantic_tag='nav',
):
  if commandlist:
    outf.write(CommandTableString(commandlist,div_id,separator,semantic_tag))
  return # CommandTable()


def EntryMainMenu(form,env):
  main_menu = [form.applAnchor('','Connect',None,[])]
  if web2ldap.app.handler.check_access(env,'monitor'):
    main_menu.append(form.applAnchor('monitor','Monitor',None,[]))
  if web2ldap.app.handler.check_access(env,'locate'):
    main_menu.append(form.applAnchor('locate','DNS lookup',None,[]))
  return main_menu


def ContextMenuSingleEntry(sid,form,ls,dn,vcard_link=0,dds_link=0,entry_uuid=None):
  """
  Output the context menu for a single entry
  """
  dn_disp = dn or u'Root DSE'
  result = [
    form.applAnchor('read','Raw',sid,[('dn',dn),('read_output','table'),('read_expandattr','*')],title=u'Display entry\r\n%s\r\nas raw attribute type/value list' % (dn_disp)),
  ]
  if dn:
    parent_dn = web2ldap.ldaputil.base.parent_dn(dn)
    ldap_url_obj = ls.ldapUrl('',add_login=False)
    result.extend([
      form.applAnchor(
        'login',
        'Bind as',
        None,
        [
          ('ldapurl',str(ldap_url_obj).decode('ascii')),
          ('dn',dn),
          ('login_who',dn),
        ],
        title=u'Connect and bind new session as\r\n%s' % (dn)
      ),
      form.applAnchor('modify','Modify',sid,[('dn',dn)],title=u'Modify entry\r\n%s' % (dn)),
      form.applAnchor('rename','Rename',sid,[('dn',dn)],title=u'Rename/move entry\r\n%s' % (dn)),
      form.applAnchor('delete','Delete',sid,[('dn',dn)],title=u'Delete entry and/or subtree\r\n%s' % (dn)),
      form.applAnchor('passwd','Password',sid,[('dn',dn),('passwd_who',dn)],title=u'Set password for entry\r\n%s' % (dn)),
      form.applAnchor('groupadm','Groups',sid,[('dn',dn)],title=u'Change group membership of entry\r\n%s' % (dn)),
      form.applAnchor(
        'add','Clone',sid,
        [
          ('dn',parent_dn),
          ('add_clonedn',dn),
          ('in_ft',u'Template'),
        ],
        title=u'Clone entry\r\n%s\r\nbeneath %s' % (dn,parent_dn)),
    ])

  if vcard_link:
    result.append(form.applAnchor('read','vCard',sid,[('dn',dn),('read_output','vcard')],title=u'Export entry\r\n%s\r\nas vCard' % (dn_disp)))

  if dds_link:
    result.append(form.applAnchor('dds','Refresh',sid,[('dn',dn)],title=u'Refresh dynamic entry %s' % (dn_disp)))

  current_audit_context = ls.getAuditContext(ls.currentSearchRoot)
  if not current_audit_context is None:
    accesslog_any_filterstr = logdb_filter(u'auditObject',dn,entry_uuid)
    accesslog_write_filterstr = logdb_filter(u'auditWriteObject',dn,entry_uuid)
    result.extend([
      form.applAnchor(
        'search','Audit access',sid,
        [
          ('dn',current_audit_context),
          ('filterstr',accesslog_any_filterstr),
          ('scope',str(ldap0.SCOPE_ONELEVEL)),
        ],
        title=u'Complete audit trail for entry\r\n%s' % (dn),
      ),
      form.applAnchor(
        'search','Audit writes',sid,
        [
          ('dn',current_audit_context),
          ('filterstr',accesslog_write_filterstr),
          ('scope',str(ldap0.SCOPE_ONELEVEL)),
        ],
        title=u'Audit trail of write access to entry\r\n%s' % (dn),
      ),
    ])

  try:
    changelog_dn = ls.rootDSE['changelog'][0].decode(ls.charset)
  except KeyError:
    pass
  else:
    changelog_filterstr = logdb_filter(u'changeLogEntry',dn,entry_uuid)
    result.append(
      form.applAnchor(
        'search','Change log',sid,
        [
          ('dn',changelog_dn),
          ('filterstr',changelog_filterstr),
          ('scope',str(ldap0.SCOPE_ONELEVEL)),
        ],
        title=u'Audit trail of write access to current entry',
      )
    )

  try:
    monitor_context_dn = ls.rootDSE['monitorContext'][0]
  except KeyError:
    pass
  else:
    result.append(form.applAnchor(
      'search','User conns',sid,
      [
        ('dn',monitor_context_dn),
        ('filterstr','(&(objectClass=monitorConnection)(monitorConnectionAuthzDN=%s))' % (escape_filter_chars(dn))),
        ('scope',str(ldap0.SCOPE_SUBTREE)),
      ],
      title=u'Find connections of this user in monitor database',
    ))

  return result # ContextMenuSingleEntry()


def WhoAmITemplate(sid,form,ls,dn,who=None,entry=None):
  if who==None:
    if hasattr(ls,'who') and ls.who:
      who = ls.who
      entry = ls.userEntry
    else:
      return 'anonymous'
  if web2ldap.ldaputil.base.is_dn(who):
    # Fall-back is to display the DN
    result = DisplayDN(sid,form,ls,who,commandbutton=0)
    # Determine relevant templates dict
    sub_schema = ls.retrieveSubSchema(
      dn,
      web2ldap.app.cnf.GetParam(ls,'_schema',None),
      web2ldap.app.cnf.GetParam(ls,'supplement_schema',None),
      web2ldap.app.cnf.GetParam(ls,'schema_strictcheck',True),
    )
    bound_as_templates = ldap0.cidict.cidict(web2ldap.app.cnf.GetParam(
      ls.ldapUrl(ls.getSearchRoot(who)),'boundas_template',{}
    ))
    # Read entry if necessary
    if entry==None:
      read_attrs = set(['objectClass'])
      for oc in bound_as_templates.keys():
        read_attrs.update(GrabKeys(bound_as_templates[oc]).keys)
      try:
        ldap_result = ls.readEntry(who,attrtype_list=list(read_attrs))
      except ldap0.LDAPError:
        entry = {}
      else:
        if ldap_result:
          _,entry = ldap_result[0]
        else:
          entry = {}
    if entry:
      display_entry = web2ldap.app.read.DisplayEntry(sid,form,ls,dn,sub_schema,entry,'readSep',1)
      user_structural_oc = display_entry.entry.get_structural_oc()
      for oc in bound_as_templates.keys():
        if sub_schema.getoid(ldap0.schema.models.ObjectClass,oc)==user_structural_oc:
          try:
            result = bound_as_templates[oc] % display_entry
          except KeyError:
            pass
  else:
    result = form.utf2display(who)
  return result # WhoAmITemplate()



def MainMenu(sid,form,ls,dn):
  """
  Returns list of main menu items
  """
  cl = []

  if ls!=None and ls.uri!=None:

    if dn:
      parent_dn = web2ldap.ldaputil.base.parent_dn(dn)
      cl.append(
        form.applAnchor(
          'search','Up',sid,
          (
            ('dn',parent_dn),
            ('scope',web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
            ('searchform_mode',u'adv'),
            ('search_attr',u'objectClass'),
            ('search_option',web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS),
            ('search_string',''),
          ),
          title=u'List direct subordinates of %s' % (parent_dn or u'Root DSE'),
        )
      )

    cl.extend((
      form.applAnchor(
        'search','Down',sid,
        (
          ('dn',dn),
          ('scope',web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
          ('searchform_mode',u'adv'),
          ('search_attr',u'objectClass'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS),
          ('search_string',''),
        ),
          title=u'List direct subordinates of %s' % (dn or u'Root DSE'),
      ),
      form.applAnchor('searchform','Search',sid,
        (('dn',dn),),
        title=u'Enter search criteria in input form',
      ),
    ))

    cl.append(
      form.applAnchor(
        'dit',
        'Tree',
        sid,[('dn',dn)],
        title=u'Display tree around %s' % (dn or u'Root DSE'),
        anchor_id=dn_anchor_hash(dn)
      ),
    )

    cl.append(
      form.applAnchor(
        'read',
        'Read',
        sid,[('dn',dn),('read_nocache',u'1')],
        title=u'Display entry %s' % (dn or u'Root DSE')
      ),
    )

    cl.extend((
      form.applAnchor(
        'add','New entry',sid,
        [
          ('dn',dn),
        ],
        title=u'Add a new entry below of %s' % (dn or u'Root DSE')
      ),
      form.applAnchor('conninfo','ConnInfo',sid,[('dn',dn)],title=u'Show information about HTTP and LDAP connections'),
      form.applAnchor('ldapparams','Params',sid,[('dn',dn)],title=u'Tweak parameters used for LDAP operations (controls etc.)'),
      form.applAnchor('login','Bind',sid,[('dn',dn)],title=u'Login to directory'),
      form.applAnchor('oid','Schema',sid,[('dn',dn)],title=u'Browse/view subschema'),
    ))

    cl.append(form.applAnchor('disconnect','Disconnect',sid,[],title=u'Disconnect from LDAP server'))

  else:

    cl.append(form.applAnchor('','Connect',None,[],title=u'New connection to LDAP server'))

  return cl # MainMenu()


def DITNavigationList(sid,outf,form,ls,dn):
  dn_list=explode_dn(dn)
  result = [
    form.applAnchor(
      'read',
      form.utf2display(dn_list[i] or '[Root DSE]'),
      sid,
      [
        ('dn',','.join(dn_list[i:])),
      ],
      title=u'Jump to %s' % (u','.join(dn_list[i:])),
    )
    for i in range(len(dn_list))
  ]
  result.append(
    form.applAnchor(
      'read',
      '[Root DSE]',
      sid,
      [
        ('dn',''),
      ],
      title=u'Jump to root DSE',
    )
  )
  return result # DITNavigationList()


def TopSection(sid,outf,command,form,ls,dn,title,main_menu_list,context_menu_list=[],main_div_id='Message'):

  # First send the HTTP header
  Header(outf,form)

  # Read the template file for TopSection
  top_template_str = web2ldap.app.gui.ReadTemplate(form,ls,'top_template',u'top section')

  script_name = escapeHTML(form.script_name)

  template_dict = {
    'main_div_id':main_div_id,
    'accept_charset':form.accept_charset,
    'refresh_time':str(web2ldapcnf.session_remove+10),
    'sid':sid or '',
    'title_text':title,
    'script_name':script_name,
    'web2ldap_version':escapeHTML(web2ldap.__about__.__version__),
    'command':command,
    'ldap_url':'',
    'ldap_uri':'-/-',
    'description':'',
    'who':'-/-',
    'dn':'-/-',
    'dit_navi':'-/-',
    'main_menu':CommandTableString(main_menu_list,div_id='MainMenu',separator='\n',semantic_tag=None),
    'context_menu':CommandTableString(context_menu_list,div_id='ContextMenu',separator='\n',semantic_tag=None),
  }
  template_dict.update([(k,escapeHTML(str(v))) for k,v in form.env.items()])

  if ls!=None and ls.uri!=None:

    if not dn or not web2ldap.ldaputil.base.is_dn(dn):
      dn = u''

    # Only output something meaningful if valid connection
    template_dict.update({
      'ldap_url':str(ls.ldapUrl(dn)),
      'ldap_uri':form.utf2display(ls.uri.decode('ascii')),
      'description':escapeHTML(web2ldap.app.cnf.GetParam(ls,'description',u'').encode(form.accept_charset)),
      'dit_navi':',\n'.join(DITNavigationList(sid,outf,form,ls,dn)),
      'dn':form.utf2display(dn),
    })
    template_dict['who'] =  WhoAmITemplate(sid,form,ls,dn)

  outf.write(top_template_str.format(**template_dict))

  return # TopSection()


def SimpleMessage(
  sid,outf,command,form,ls,dn,
  title=u'',message=u'',
  main_div_id='Message',
  main_menu_list=[],context_menu_list=[]
):
  TopSection(
    sid,outf,command,form,ls,dn,
    title,
    main_menu_list,
    context_menu_list=context_menu_list,
    main_div_id=main_div_id,
  )
  outf.write(message)
  web2ldap.app.gui.Footer(outf,form)
  return # SimpleMessage()


# Return a pretty HTML-formatted string describing a schema element
# referenced by name or OID
def SchemaElementName(sid,form,dn,schema,se_nameoroid,se_class,name_template=r'%s'):
  result = [name_template % (se_nameoroid.encode())]
  if se_class:
    se = schema.get_obj(se_class,se_nameoroid,None)
    if not se is None:
      result.append(form.applAnchor(
          'oid','&raquo;',sid,
          [ ('dn',dn),('oid',se.oid),('oid_class',ldap0.schema.SCHEMA_ATTR_MAPPING[se_class]) ]
      ))
  return '\n'.join(result)


def LDAPURLButton(sid,form,ls,data):
  if isinstance(data,LDAPUrl):
    l = data
  else:
    l = LDAPUrl(ldapUrl=data)
  command_func = {True:'read',False:'search'}[l.scope==ldap0.SCOPE_BASE]
  if l.hostport:
    command_text = 'Connect'
    return form.applAnchor(
      command_func,
      'Connect and %s' % (command_func),
      None,
      (('ldapurl',unicode(str(l))),)
    )
  else:
    command_text = {True:'Read',False:'Search'}[l.scope==ldap0.SCOPE_BASE]
    return form.applAnchor(
      command_func,command_text,sid,
      [
        ('dn',l.dn.decode(form.accept_charset)),
        ('filterstr',(l.filterstr or '(objectClass=*)').decode(form.accept_charset)),
        ('scope',unicode(l.scope or ldap0.SCOPE_SUBTREE)),
      ],
    )


def DataStr(sid,form,ls,dn,schema,attrtype_name,value,valueindex=0,commandbutton=0,entry=None):
  """
  Return a pretty HTML-formatted string of the attribute value
  """
  attr_instance = web2ldap.app.schema.syntaxes.syntax_registry.attrInstance(sid,form,ls,dn,schema,attrtype_name,value,entry)
  try:
    result = attr_instance.displayValue(valueindex,commandbutton)
  except UnicodeError:
    attr_instance = web2ldap.app.schema.syntaxes.OctetString(sid,form,ls,dn,schema,attrtype_name,value,entry)
    result = attr_instance.displayValue(valueindex,commandbutton)
  return result


def AttributeTypeSelectField(
  form,ls,sub_schema,
  field_name,field_desc,
  attr_list,
  default_attr_options=None
):
  """
  Return pyweblib.forms.Select instance for choosing attribute type names
  """
  attr_options_dict = {}
  for attr_type in (map(unicode,default_attr_options or []) or sub_schema.sed[ldap0.schema.models.AttributeType].keys())+attr_list:
    attr_type_se = sub_schema.get_obj(ldap0.schema.models.AttributeType,attr_type)
    if attr_type_se:
      if attr_type_se.names:
        attr_type_name = unicode(attr_type_se.names[0],ls.charset)
      else:
        attr_type_name = unicode(attr_type)
      if attr_type_se.desc:
        try:
          attr_type_desc = unicode(attr_type_se.desc,ls.charset)
        except UnicodeDecodeError:
          attr_type_desc = unicode(repr(attr_type_se.desc),'ascii')
      else:
        attr_type_desc = None
    else:
      attr_type_name = attr_type
      attr_type_desc = None
    attr_options_dict[attr_type_name] = (attr_type_name,attr_type_desc)
  sorted_attr_options = [
    (at,attr_options_dict[at][0],attr_options_dict[at][1])
    for at in sorted(attr_options_dict.keys(),key=unicode.lower)
  ]
  # Create a select field instance for attribute type name
  attr_select = pyweblib.forms.Select(
    field_name,field_desc,
    1,
    options=sorted_attr_options,
  )
  attr_select.setCharset(form.accept_charset)
  return attr_select


def gen_headers(content_type='text/html',charset='utf-8',more_headers=None):
  # Get current time as GMT (seconds since epoch)
  current_datetime = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime(time.time()))
  headers = []
  if content_type.startswith('text/'):
    content_type = '%s;charset=%s' % (content_type,charset)
  headers.append(('Content-Type',content_type))
  headers.append(('Date',current_datetime))
  headers.append(('Last-Modified',current_datetime))
  headers.append(('Expires',current_datetime))
  for h,v in web2ldapcnf.http_headers.items():
    headers.append((h,v))
  headers.extend(more_headers or [])
  return headers # Header()


def Header(outf,form,content_type='text/html',charset=None,more_headers=None):
  headers = gen_headers(content_type=content_type,charset=charset,more_headers=more_headers)
  if form.next_cookie:
    for _, cookie in form.next_cookie.items():
      headers.append(('Set-Cookie',str(cookie)[12:]))
  if form.env.get('HTTPS','off')=='on' and \
     'Strict-Transport-Security' not in web2ldapcnf.http_headers:
    headers.append(('Strict-Transport-Security','max-age=15768000 ; includeSubDomains'))
  outf.set_headers(headers)
  return headers # Header()


def Footer(f,form):
  f.write("""
    <p class="ScrollLink">
      <a href="#web2ldap_top">&uarr; TOP</a>
    </p>
    <a id="web2ldap_bottom"></a>
  </div>
  <div id="Footer">
    <footer>
    </footer>
  </div>
</body>
</html>
  """)


def SearchRootField(
  form,ls,dn,
  name='dn',
  text=u'Search Root',
  default=None,
  search_root_searchurl=None,
  naming_contexts=None
):
  """Prepare input field for search root"""

  def sortkey_func(d):
    try:
      dn,_ = d
    except ValueError:
      dn = d
    if dn:
      dn_list = web2ldap.ldaputil.base.explode_dn(dn.lower())
      dn_list.reverse()
      return ','.join(dn_list)
    else:
      return ''

  if dn:
    dn_select_list = [dn]+web2ldap.ldaputil.base.parent_dn_list(dn,ls.getSearchRoot(dn,naming_contexts=naming_contexts))
  else:
    dn_select_list = []
  dn_select_list = web2ldap.msbase.union(ls.namingContexts,dn_select_list)
  if search_root_searchurl:
    slu = ldap0.ldapurl.LDAPUrl(search_root_searchurl.encode(ls.charset))
    try:
      ldap_result = ls.l.search_s(
        slu.dn,
        slu.scope,
        slu.filterstr,
        attrlist=['1.1'],
      )
    except ldap0.LDAPError:
      pass
    else:
      dn_select_list = web2ldap.msbase.union(
        [
          ls.uc_decode(ldap_dn)[0]
          for ldap_dn,_ in ldap_result
          if ldap_dn!=None
        ],
        dn_select_list,
      )
  dn_select_list.append((u'',u'- World -'))
  dn_select_list = list(set(dn_select_list))
  dn_select_list.sort(key=sortkey_func)
#  srf = web2ldap.app.form.DataList(
  srf = pyweblib.forms.Select(
    name,text,1,
#    size=60,
    default=default or ls.getSearchRoot(dn),
    options=dn_select_list,
    ignoreCase=1
  )
  srf.setCharset(form.accept_charset)
  return srf # SearchRootField()


def ExceptionMsg(sid,outf,command,form,ls,dn,Heading,Msg):
  """
  Heading
    Unicode string with text for the <h1> heading
  Msg
    Raw string with HTML with text describing the exception
    (Security note: Must already be quoted/escaped!)
  """
  TopSection(sid,outf,command,form,ls,dn,'Error',MainMenu(sid,form,ls,dn),context_menu_list=[])
  if type(Msg)==unicode:
    Msg = Msg.encode(form.accept_charset)
  outf.write("""
      <h1>{heading}</h1>
      <p class="ErrorMessage">
        {error_msg}
      </p>
    """.format(
      heading=form.utf2display(Heading),
      error_msg=Msg,
    )
  )
  Footer(outf,form)
  return # ExceptionMsg()
