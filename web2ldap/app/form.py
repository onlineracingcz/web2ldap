# -*- coding: utf-8 -*-
"""
web2ldap.app.form: class for web2ldap input form handling

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import urllib,uuid,codecs,re,Cookie
try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO
from types import UnicodeType

import ldap0.ldif,ldap0.schema
from ldap0.pw import random_string

import pyweblib.forms
from pyweblib.forms import escapeHTML

import web2ldap.ldaputil.base,web2ldap.ldapsession
import web2ldapcnf
import web2ldap.app.core,web2ldap.app.gui,web2ldap.app.passwd,web2ldap.app.searchform,web2ldap.app.ldapparams,web2ldap.app.session
# OID description dictionary from configuration directory
from web2ldap.ldaputil.oidreg import oid as oid_desc_reg
from web2ldap.app.session import session_store

CONNTYPE2URLSCHEME = {
  0:'ldap',
  1:'ldap',
  2:'ldaps',
  3:'ldapi',
}


class Web2LDAPForm(pyweblib.forms.Form):

  cookie_length = web2ldapcnf.cookie_length
  cookie_max_age = web2ldapcnf.cookie_max_age
  cookie_domain = web2ldapcnf.cookie_domain
  cookie_name_prefix = 'web2ldap_'

  def __init__(self,inf,env):
    pyweblib.forms.Form.__init__(self,inf,env)
    self.script_name = env['SCRIPT_NAME']
    if env.has_key('HTTP_USER_AGENT'):
      self.browser_type,self.browser_version = pyweblib.helper.BrowserType(env['HTTP_USER_AGENT'])
    else:
      self.browser_type,self.browser_version = None,None
    self.determineCharset()
    self.initializeForm()
    # For optional cookie handling
    try:
      self.cookies = Cookie.SimpleCookie(self.env['HTTP_COOKIE'])
    except KeyError:
      self.cookies = Cookie.SimpleCookie()
    self.next_cookie = Cookie.SimpleCookie()
    self.query_string = self._get_query_string(env)

  def _get_query_string(self,env):
    """
    Returns re-coded QUERY_STRING env var
    """
    try:
      query_string_u = env.get('QUERY_STRING','').decode(self.accept_charset)
    except UnicodeError:
      query_string_u = env.get('QUERY_STRING','').decode('iso-8859-1')
    return query_string_u.encode(self.accept_charset)

  def utf2display(self,value,tab_identiation='',sp_entity='&nbsp;&nbsp;',lf_entity='\n'):
    value = value or u''
    assert type(value)==UnicodeType, TypeError("Type of argument 'value' must be UnicodeType: value=%s" % repr(value))
    return escapeHTML(self.uc_encode(value,'replace')[0]).replace('\n',lf_entity).replace('\t',tab_identiation).replace('  ',sp_entity)

  def unsetCookie(self,c):
    if c!=None:
      assert len(c)==1,ValueError('More than one Morsel cookie instance in c: %d objects found' % (len(c)))
      cookie_name = c.keys()[0]
      c[cookie_name] = ''
      c[cookie_name]['max-age'] = 0
      self.next_cookie.update(c)
    return # unsetCookie()

  def get_cookie_domain(self):
    if self.cookie_domain:
      cookie_domain = self.cookie_domain
    elif 'SERVER_NAME' in self.env or 'HTTP_HOST' in self.env:
      cookie_domain = self.env.get('HTTP_HOST',self.env['SERVER_NAME']).split(':')[0]
    return cookie_domain

  def setNewCookie(self,name_suffix):
    if self.cookie_length:
      # Generate a randomized key and value
      cookie_key = random_string(alphabet=pyweblib.session.SESSION_ID_CHARS,length=self.cookie_length)
      cookie_name = ''.join((self.cookie_name_prefix,name_suffix))
      c = Cookie.SimpleCookie({
        cookie_name:cookie_key,
      })
      c[cookie_name]['path'] = self.script_name
      c[cookie_name]['domain'] = self.get_cookie_domain()
      c[cookie_name]['max-age'] = str(self.cookie_max_age)
      c[cookie_name]['httponly'] = None
      if self.env.get('HTTPS','off')=='on':
        c[cookie_name]['secure'] = None
      self.next_cookie.update(c)
    else:
      # Setting cookies disabled in configuration
      c = None
    return c # setNewCookie()

  def outFileObject(self,outf):
    """
    do something magic with output file object
    """
    return outf

  def determineCharset(self):
    self.accept_charset = 'utf-8'
    form_codec = codecs.lookup(self.accept_charset)
    self.uc_encode,self.uc_decode = form_codec[0],form_codec[1]
    return # determineCharset()

  def initializeForm(self):
    """
    Add the required fields
    """
    self.addGeneralFields()
    self.addCommandFields()

  def addGeneralFields(self):
    self.addField(pyweblib.forms.Input(
      'delsid',
      u'Old SID to be deleted',
      session_store.session_id_len,
      1,
      session_store.session_id_re.pattern
    ))
    self.addField(pyweblib.forms.Input('who',u'Bind DN/AuthcID',1000,1,u'.*',size=40))
    self.addField(pyweblib.forms.Input('cred',u'with Password',200,1,u'.*',size=15))
    self.addField(pyweblib.forms.Select('login_authzid_prefix',u'SASL AuthzID',1,options=[('','- no prefix -'),('u:','user-ID'),('dn:','DN')],default=''))
    self.addField(pyweblib.forms.Input('login_authzid',u'SASL AuthzID',1000,1,u'.*',size=20))
    self.addField(pyweblib.forms.Input('login_realm',u'SASL Realm',1000,1,u'.*',size=20))
    self.addField(AuthMechSelect('login_mech',u'Authentication mechanism'))
    self.addField(pyweblib.forms.Input('ldapurl',u'LDAP Url',1024,1,'[ ]*ldap(|i|s)://.*',size=30))
    self.addField(pyweblib.forms.Input('host',u'Host:Port',255,1,'(%s|[a-zA-Z0-9/._-]+)' % web2ldap.app.gui.host_pattern,size=30))
    self.addField(DistinguishedNameInput('dn','Distinguished Name'))
    self.addField(pyweblib.forms.Select(
      'scope','Scope',1,
      options=web2ldap.app.searchform.SEARCH_SCOPE_OPTIONS,
      default=web2ldap.app.searchform.SEARCH_SCOPE_STR_SUBTREE),
    )
    self.addField(DistinguishedNameInput('login_search_root','Login search root'))
    self.addField(pyweblib.forms.Input('login_filterstr',u'Login search filter string',300,1,'.*'))
    self.addField(pyweblib.forms.Select(
      'conntype','Connection type',1,
      options=[
        ('0','LDAP clear-text connection'),
        ('1','LDAP with StartTLS ext.op.'),
        ('2','LDAP over separate SSL port (LDAPS)'),
        ('3','LDAP over Unix domain socket (LDAPI)')
      ],
      default='0',
    ))

  def addCommandFields(self):
    pass

  def actionUrlHTML(self,command,sid):
    return '%s/%s%s' % (
      self.script_name,
      command,
      {0:'/%s' % sid,1:''}[sid is None],
    )

  def beginFormHTML(self,command,sid,method,target=None,enctype=None):
    target = {0:'target="%s"' % (target),1:''}[target is None]
    return """
      <form
        action="%s"
        method="%s"
        %s
        enctype="%s"
        accept-charset="%s"
      >
      """  % (
        self.actionUrlHTML(command,sid),
        method,target,
        enctype or 'application/x-www-form-urlencoded',
        self.accept_charset
      )

  def hiddenFieldHTML(self,name,value,desc):
    return web2ldap.app.gui.HIDDEN_FIELD % (
      name,
      self.utf2display(value,sp_entity='  '),
      self.utf2display(desc,sp_entity='&nbsp;&nbsp;'),
    )

  def hiddenInputHTML(self,ignoreFieldNames=None):
    """
    Return all input parameters as hidden fields in one HTML string.

    ignoreFieldNames
        Names of parameters to be excluded.
    """
    ignoreFieldNames=set(ignoreFieldNames or [])
    result = []
    for f in [
      self.field[p]
      for p in self.inputFieldNames
      if not p in ignoreFieldNames
    ]:
      for v in f.value:
        if not type(v)==UnicodeType:
          v = self.uc_decode(v)[0]
        result.append(self.hiddenFieldHTML(f.name,v,u''))
    return '\n'.join(result) # hiddenInputFieldString()

  def formHTML(
    self,command,submitstr,sid,method,form_parameters,
    extrastr='',
    target=None
  ):
    """
    Build the HTML text of a submit form
    """
    form_str = [self.beginFormHTML(command,sid,method,target)]
    for param_name,param_value in form_parameters:
      form_str.append(self.hiddenFieldHTML(param_name,param_value,u''))
    form_str.append("""
      <p>
      <input type="submit" value="%s">
      %s
      </p>
      </form>""" % (submitstr,extrastr)
    )
    return '\n'.join(form_str)

  def allInputFields(self,fields=None,ignoreFieldNames=None):
    """
    Return list with all former input parameters.

    ignoreFieldNames
        Names of parameters to be excluded.
    """
    ignoreFieldNames=set(ignoreFieldNames or [])
    result = list(fields) or []
    for f in [
      self.field[p]
      for p in self.declaredFieldNames
      if (p in self.inputFieldNames) and not (p in ignoreFieldNames)
    ]:
      for v in f.value:
        result.append((f.name,v))
    return result # allInputFields()

  def applAnchor(
    self,
    command,
    anchor_text,
    sid,
    form_parameters,
    target=None,
    title=None,
    anchor_id=None,
  ):
    """
    Build the HTML text of a anchor with form parameters
    """
    assert isinstance(command, str), TypeError('command must be string, but was %r', command)
    assert isinstance(anchor_text, str), TypeError('anchor_text must be string, but was %r', anchor_text)
    assert sid is None or isinstance(sid, str), TypeError('sid must be None or string, but was %r', sid)
    assert anchor_id is None or isinstance(anchor_id, unicode), TypeError('anchor_id must be None or unicode, but was %r', anchor_id)
    assert target is None or isinstance(target, str), TypeError('target must be None or string, but was %r', target)
    assert title is None or isinstance(title, unicode), TypeError('title must be None or unicode, but was %r', title)
    target_attr = ''
    if target:
      target_attr = ' target="%s"' % (target)
    title_attr = ''
    if title:
      title_attr = ' title="%s"' % (self.utf2display(title).replace(' ','&nbsp;'))
    if anchor_id:
      anchor_id = '#%s' % (self.utf2display(anchor_id))
    res = '<a class="CommandLink"%s%s href="%s?%s%s">%s</a>' % (
      target_attr,
      title_attr,
      self.actionUrlHTML(command,sid),
      '&amp;'.join([
        '%s=%s' % (param_name,urllib.quote(self.uc_encode(param_value)[0]))
        for param_name,param_value in form_parameters
      ]),
      anchor_id or '',
      anchor_text,
    )
    assert isinstance(res, str), TypeError('res must be string, but was %r', res)
    return res


class Web2LDAPNullForm(Web2LDAPForm):
  pass


class SearchAttrs(pyweblib.forms.Input):

  def __init__(self,name='search_attrs',text=u'Attributes to be read'):
    pyweblib.forms.Input.__init__(self,name,text,1000,1,ur'[@*+0-9.\w,_;-]+')

  def setValue(self,value):
    value = ','.join(
      filter(
        None,
        map(
          str.strip,
          value.replace(' ',',').split(',')
        )
      )
    )
    pyweblib.forms.Input.setValue(self,value)


class Web2LDAPForm_searchform(Web2LDAPForm):

  def addCommandFields(self):
    self.addField(pyweblib.forms.Input('search_submit',u'Search form submit button',6,1,'(Search|[+-][0-9]+)'))
    self.addField(pyweblib.forms.Select('searchform_mode',u'Search form mode',1,options=[(u'base',u'Base'),(u'adv',u'Advanced'),(u'exp',u'Expert')],default=u'base'))
    self.addField(DistinguishedNameInput('search_root','Search root'))
    self.addField(pyweblib.forms.Input(
      'filterstr',
      u'Search filter string',
      1200,
      1,
      '.*',
      size=90,
    ))
    self.addField(pyweblib.forms.Input('searchform_template',u'Search form template name',60,web2ldapcnf.max_searchparams,u'[a-zA-Z0-9. ()_-]+'))
    self.addField(
      pyweblib.forms.Select(
        'search_resnumber',u'Number of results to display',1,
        options=[(u'0',u'unlimited'),(u'10',u'10'),(u'20',u'20'),(u'50',u'50'),(u'100',u'100'),(u'200',u'200')],
        default=u'10'
      )
    )
    self.addField(
      pyweblib.forms.Select(
        'search_lastmod',u'Interval of last creation/modification',1,
        options=[
          (u'-1',u'-'),
          (u'10',u'10 sec.'),
          (u'60',u'1 min.'),
          (u'600',u'10 min.'),
          (u'3600',u'1 hour'),
          (u'14400',u'4 hours'),
          (u'43200',u'12 hours'),
          (u'86400',u'24 hours'),
          (u'172800',u'2 days'),
          (u'604800',u'1 week'),
          (u'2419200',u'4 weeks'),
          (u'6048000',u'10 weeks'),
          (u'31536000',u'1 year'),
        ],
        default=u'-1'
      )
    )
    self.addField(InclOpAttrsCheckbox('search_opattrs',u'Request operational attributes',default="yes",checked=0))
    self.addField(pyweblib.forms.Select('search_mode',u'Search Mode',1,options=[ur'(&%s)',ur'(|%s)']))
    self.addField(pyweblib.forms.Input('search_attr',u'Attribute(s) to be searched',100,web2ldapcnf.max_searchparams,ur'[\w,_;-]+'))
    self.addField(pyweblib.forms.Input('search_mr',u'Matching Rule',100,web2ldapcnf.max_searchparams,ur'[\w,_;-]+'))
    self.addField(pyweblib.forms.Select('search_option',u'Search option',web2ldapcnf.max_searchparams,options=web2ldap.app.searchform.search_options))
    self.addField(pyweblib.forms.Input('search_string',u'Search string',600,web2ldapcnf.max_searchparams,u'.*',size=60))
    self.addField(SearchAttrs())


class Web2LDAPForm_search(Web2LDAPForm_searchform):
  def addCommandFields(self):
    Web2LDAPForm_searchform.addCommandFields(self)
    self.addField(pyweblib.forms.Input('search_resminindex',u'Minimum index of search results',10,1,u'[0-9]+'))
    self.addField(pyweblib.forms.Input('search_resnumber',u'Number of results to display',3,1,u'[0-9]+'))
    self.addField(ExportFormatSelect('search_output'))


class Web2LDAPForm_conninfo(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(pyweblib.forms.Select('conninfo_flushcaches',u'Flush caches',1,options=['0','1'],default=0))

class Web2LDAPForm_ldapparams(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(pyweblib.forms.Select('ldapparams_submit',u'Submit type',1,options=(u'Apply',u''),default=u''))
    self.addField(pyweblib.forms.Select('ldapparam_all_controls',u'List all controls',1,options=(u'0',u'1'),default=u'0'))
    self.addField(
      pyweblib.forms.Input(
        'ldapparam_enable_control',
        u'Enable LDAPv3 Boolean Control',
        50,1,u'([0-9]+.)*[0-9]+',
      )
    )
    self.addField(
      pyweblib.forms.Input(
        'ldapparam_disable_control',
        u'Disable LDAPv3 Boolean Control',
        50,1,u'([0-9]+.)*[0-9]+',
      )
    )
    self.addField(
      pyweblib.forms.Select(
        'ldap_deref',u'Dereference aliases',maxValues=1,default=str(ldap0.DEREF_NEVER),
        options=[
          (unicode(ldap0.DEREF_NEVER),u'never'),
          (unicode(ldap0.DEREF_SEARCHING),u'searching'),
          (unicode(ldap0.DEREF_FINDING),u'finding'),
          (unicode(ldap0.DEREF_ALWAYS),u'always'),
        ]
      )
    )

class AttributeValueInput(pyweblib.forms.Input):
  def _encodeValue(self,value):
    return value

class Web2LDAPForm_input(Web2LDAPForm):
  """Base class for entry data input not directly used"""
  def addCommandFields(self):
    self.addField(pyweblib.forms.Input('in_oc',u'Object classes',60,40,u'[a-zA-Z0-9.-]+'))
    self.addField(pyweblib.forms.Select('in_ft',u'Type of input form',1,options=['Template','Table','LDIF','OC'],default='Template'))
    self.addField(pyweblib.forms.Input(
      'in_mr',
      u'Add/del row',
      8,1,
      '(Template|Table|LDIF|[+-][0-9]+)',
    ))
    self.addField(pyweblib.forms.Select('in_oft',u'Type of input form',1,options=[u'Template',u'Table',u'LDIF'],default=u'Template'))
    self.addField(AttributeType('in_at',u'Attribute type',web2ldapcnf.input_maxattrs))
    self.addField(AttributeType('in_avi',u'Value index',web2ldapcnf.input_maxattrs))
    self.addField(
      AttributeValueInput(
        'in_av',u'Attribute Value',
        web2ldapcnf.input_maxfieldlen,
        web2ldapcnf.input_maxattrs,
        ('.*',re.U|re.M|re.S)
      )
    )
    self.addField(LDIFTextArea('in_ldif',u'LDIF data'))

class Web2LDAPForm_add(Web2LDAPForm_input):
  def addCommandFields(self):
    Web2LDAPForm_input.addCommandFields(self)
    self.addField(pyweblib.forms.Input('add_rdn','RDN of new entry',255,1,u'.*',size=50))
    self.addField(DistinguishedNameInput('add_clonedn','DN of template entry'))
    self.addField(pyweblib.forms.Input('add_template',u'LDIF template name',60,web2ldapcnf.max_searchparams,u'.+'))
    self.addField(pyweblib.forms.Input('add_basedn',u'Base DN of new entry',1024,1,u'.*',size=50))
    self.addField(pyweblib.forms.Select(
      'in_ocf',u'Object class form mode',1,
      options=[
        (u'tmpl',u'LDIF templates'),
        (u'exp',u'Object class selection')
      ],
      default=u'tmpl'
    ))

class Web2LDAPForm_modify(Web2LDAPForm_input):
  def addCommandFields(self):
    Web2LDAPForm_input.addCommandFields(self)
    self.addField(AttributeType('in_oldattrtypes',u'Old attribute types',web2ldapcnf.input_maxattrs))
    self.addField(AttributeType('in_wrtattroids',u'Writeable attribute types',web2ldapcnf.input_maxattrs))
    self.addField(pyweblib.forms.Input('in_assertion',u'Assertion filter string',2000,1,'.*',required=0))

class Web2LDAPForm_dds(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(pyweblib.forms.Input('dds_renewttlnum',u'Request TTL number',12,1,'[0-9]+',default=''))
    self.addField(pyweblib.forms.Select(
      'dds_renewttlfac',
      u'Request TTL factor',1,
      options=(
        (u'1',u'seconds'),
        (u'60',u'minutes'),
        (u'3600',u'hours'),
        (u'86400',u'days'),
      ),
      default='1'
    ))

class Web2LDAPForm_bulkmod(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(pyweblib.forms.Input('bulkmod_submit',u'Search form submit button',6,1,u'(Next>>|<<Back|Apply|Cancel|[+-][0-9]+)'))
    bulkmod_ctrl_options=[
      (control_oid,oid_desc_reg.get(control_oid,(control_oid,))[0])
      for control_oid,control_spec in web2ldap.app.ldapparams.AVAILABLE_BOOLEAN_CONTROLS.items()
      if '**all**' in control_spec[0] or '**write**' in control_spec[0] or 'modify' in control_spec[0]
    ]
    self.addField(
      pyweblib.forms.Select(
        'bulkmod_ctrl',
        u'Extended controls',
        len(bulkmod_ctrl_options),
        options=bulkmod_ctrl_options,
        default=[],
        size=min(8,len(bulkmod_ctrl_options)),
        multiSelect=1,
      )
    )
    self.addField(pyweblib.forms.Input('filterstr',u'Search filter string for searching entries to be deleted',1200,1,'.*'))
    self.addField(pyweblib.forms.Input(
      'bulkmod_modrow',
      u'Add/del row',
      8,1,
      '(Template|Table|LDIF|[+-][0-9]+)',
    ))
    self.addField(AttributeType('bulkmod_at',u'Attribute type',web2ldapcnf.input_maxattrs))
    self.addField(
      pyweblib.forms.Select(
        'bulkmod_op',
        u'Modification type',
        web2ldapcnf.input_maxattrs,
        options=(
          (u'',u''),
          (unicode(ldap0.MOD_ADD),u'add'),
          (unicode(ldap0.MOD_DELETE),u'delete'),
          (unicode(ldap0.MOD_REPLACE),u'replace'),
          (unicode(ldap0.MOD_INCREMENT),u'increment'),
        ),
        default=u'',
      )
    )
    self.addField(
      AttributeValueInput(
        'bulkmod_av',u'Attribute Value',
        web2ldapcnf.input_maxfieldlen,
        web2ldapcnf.input_maxattrs,
        ('.*',re.U|re.M|re.S),
        size=30,
      )
    )
    self.addField(DistinguishedNameInput('bulkmod_newsuperior','New superior DN'))
    self.addField(pyweblib.forms.Checkbox('bulkmod_cp',u'Copy entries',1,default="yes",checked=0))


class Web2LDAPForm_delete(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(pyweblib.forms.Select('delete_confirm',u'Confirmation',1,options=['yes','no'],default='no'))
    delete_ctrl_options=[
      (control_oid,oid_desc_reg.get(control_oid,(control_oid,))[0])
      for control_oid,control_spec in web2ldap.app.ldapparams.AVAILABLE_BOOLEAN_CONTROLS.items()
      if '**all**' in control_spec[0] or '**write**' in control_spec[0] or 'delete' in control_spec[0]
    ]
    delete_ctrl_options.append((web2ldap.ldapsession.CONTROL_TREEDELETE,u'Tree Deletion'))
    self.addField(
      pyweblib.forms.Select(
        'delete_ctrl',
        u'Extended controls',
        len(delete_ctrl_options),
        options=delete_ctrl_options,
        default=[],
        size=min(8,len(delete_ctrl_options)),
        multiSelect=1,
      )
    )
    self.addField(pyweblib.forms.Input('filterstr',u'Search filter string for searching entries to be deleted',1200,1,'.*'))
    self.addField(pyweblib.forms.Input('delete_attr',u'Attribute to be deleted',255,100,u'[\w_;-]+'))

class Web2LDAPForm_rename(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(pyweblib.forms.Input('rename_newrdn',u'New RDN',255,1,web2ldap.ldaputil.base.rdn_pattern,size=50))
    self.addField(DistinguishedNameInput('rename_newsuperior','New superior DN'))
    self.addField(pyweblib.forms.Checkbox('rename_delold',u'Delete old',1,default="yes",checked=1))
    self.addField(
      pyweblib.forms.Input(
        'rename_newsupfilter',
        u'Filter string for searching new superior entry',300,1,'.*',
        default=u'(|(objectClass=organization)(objectClass=organizationalUnit))',
        size=50,
      )
    )
    self.addField(DistinguishedNameInput('rename_searchroot','Search root under which to look for new superior entry.'))
    self.addField(pyweblib.forms.Input('rename_supsearchurl',u'LDAP URL for searching new superior entry',100,1,'.*',size=30))

class Web2LDAPForm_passwd(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(
      pyweblib.forms.Select(
        'passwd_action',
        u'Password action',
        1,
        options=[ (action,short_desc) for action,short_desc,_ in web2ldap.app.passwd.PASSWD_ACTIONS ],
        default='setuserpassword'
    ))
    self.addField(DistinguishedNameInput('passwd_who',u'Password DN'))
    self.addField(pyweblib.forms.Field('passwd_oldpasswd',u'Old password',100,1,'.*'))
    self.addField(pyweblib.forms.Field('passwd_newpasswd',u'New password',100,2,'.*'))
    self.addField(pyweblib.forms.Select('passwd_scheme',u'Password hash scheme',1,options=web2ldap.app.passwd.available_hashtypes,default=web2ldap.app.passwd.available_hashtypes[-1]))
    self.addField(pyweblib.forms.Checkbox('passwd_ntpasswordsync',u'Sync ntPassword for Samba',1,default="yes",checked=1))
    self.addField(pyweblib.forms.Checkbox('passwd_settimesync',u'Sync password setting times',1,default="yes",checked=1))
    self.addField(pyweblib.forms.Checkbox('passwd_forcechange',u'Force password change',1,default="yes",checked=0))
    self.addField(pyweblib.forms.Checkbox('passwd_inform',u'Password change inform action',1,default="display_url",checked=0))

class Web2LDAPForm_read(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(pyweblib.forms.Input('filterstr',u'Search filter string when reading single entry',1200,1,'.*'))
    self.addField(pyweblib.forms.Select('read_nocache',u'Force fresh read',1,options=['0','1'],default=0))
    self.addField(pyweblib.forms.Input('read_attr',u'Read attribute',255,100,u'[\w_;-]+'))
    self.addField(pyweblib.forms.Select('read_attrmode',u'Read attribute',1,options=[u'view',u'load']))
    self.addField(pyweblib.forms.Input('read_attrindex',u'Read attribute',255,1,u'[0-9]+'))
    self.addField(pyweblib.forms.Input('read_attrmimetype',u'MIME type',255,1,u'[\w.-]+/[\w.-]+'))
    self.addField(pyweblib.forms.Select('read_output',u'Read output format',1,options=['table','vcard','template'],default='template'))
    self.addField(SearchAttrs())
    self.addField(pyweblib.forms.Input('read_expandattr',u'Attributes to be read',1000,1,ur'[*+\w,_;-]+'))

class Web2LDAPForm_groupadm(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(DistinguishedNameInput('groupadm_searchroot','Group search root'))
    self.addField(pyweblib.forms.Input('groupadm_name',u'Group name',100,1,u'.*',size=30))
    self.addField(DistinguishedNameInput('groupadm_add','Add to group',300))
    self.addField(DistinguishedNameInput('groupadm_remove','Remove from group',300))
    self.addField(pyweblib.forms.Select('groupadm_view',u'Group list view',1,options=[('0','none of the'),('1','only member'),('2','all')],default='1'))

class Web2LDAPForm_login(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(DistinguishedNameInput('login_who',u'Bind DN'))

class Web2LDAPForm_locate(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(
      pyweblib.forms.Input('locate_name',u'Location name',500,1,u'.*',size=25)
    )

class Web2LDAPForm_oid(Web2LDAPForm):
  def addCommandFields(self):
    self.addField(OIDInput('oid',u'OID'))
    self.addField(pyweblib.forms.Select('oid_class','Schema element class',1,options=ldap0.schema.SCHEMA_ATTRS,default=''))

class Web2LDAPForm_dit(Web2LDAPForm):
  pass


FORM_CLASS = {
  '':Web2LDAPForm,
  'monitor':Web2LDAPNullForm,
  'urlredirect':Web2LDAPNullForm,
  'disconnect':Web2LDAPNullForm,
}

_FORM_CLASS_NAME_PREFIX = 'Web2LDAPForm_'
_COMMAND_STR_OFFSET = len(_FORM_CLASS_NAME_PREFIX)

for _name in dir():
  if _name.startswith(_FORM_CLASS_NAME_PREFIX):
    c = eval(_name)
    try:
      command = _name[_COMMAND_STR_OFFSET:]
    except IndexError:
      pass
    else:
      FORM_CLASS[command] = c
      del command



class DistinguishedNameInput(pyweblib.forms.Input):
  """Input field class for LDAP DNs."""

  def __init__(self,name='dn',text='DN',maxValues=1,required=0,default=''):
    pyweblib.forms.Input.__init__(
      self,name,text,1024,maxValues,'',
      size=70,required=required,default=default
    )

  def _validateFormat(self,value):
    if value and not web2ldap.ldaputil.base.is_dn(value):
      raise pyweblib.forms.InvalidValueFormat(
        self.name,
        self.text.encode(self.charset),
        value.encode(self.charset)
      )


class LDIFTextArea(pyweblib.forms.Textarea):
  """A single multi-line input field for LDIF data"""

  def __init__(
    self,name='in_ldif',text='LDIF data',required=0,max_entries=1
  ):
    pyweblib.forms.Textarea.__init__(
      self,
      name,text,web2ldapcnf.ldif_maxbytes,1,'^.*$',
      required=required,
    )
    self._max_entries = max_entries
    self.allRecords = []

  def getLDIFRecords(self):
    if self.value:
      return list(ldap0.ldif.LDIFParser.fromstring(
        '\n'.join(self.value).encode(self.charset),
        ignored_attr_types=[],
        process_url_schemes=web2ldapcnf.ldif_url_schemes
      ).parse(max_entries=self._max_entries))
    else:
      return []


class OIDInput(pyweblib.forms.Input):

  def __init__(self,name,text,default=None):
    pyweblib.forms.Input.__init__(
      self,name,text,
      512,1,u'[a-zA-Z0-9_.;*-]+',
      default=default,
      required=0,size=30
    )


class ObjectClassSelect(pyweblib.forms.Select):
  """Select field class for choosing the object class(es)"""
  def __init__(
    self,
    name='in_oc',
    text='Object classes',
    options=None,
    default=None,
    required=0,
    accesskey='',
    size=12,            # Size of displayed select field
  ):
    select_default = default or []
    select_default.sort(key=str.lower)
    additional_options = [ i for i in options or [] if not i in select_default ]
    additional_options.sort(key=str.lower)
    select_options = select_default[:]
    select_options.extend(additional_options)
    pyweblib.forms.Select.__init__(
      self,
      name,text,maxValues=200,
      required=required,
      options=select_options,
      default=select_default,
      accessKey=accesskey,
      size=size,
      ignoreCase=1,
      multiSelect=1
    )
    self.setRegex('[\w]+')
    self.maxLen = 200


class DateTime(pyweblib.forms.Input):
  """
  <input type="datetime"> and friends
  """

  def __init__(
    self,name,text,maxLen,maxValues,pattern,required=0,default=None,accessKey='',
    inputType='datetime',step='60'
  ):
    self.inputType = inputType
    self.size = maxLen
    self.step = step
    pyweblib.forms.Input.__init__(
      self,name,text,maxLen,maxValues,pattern,required,default,accessKey,
    )

  def inputHTML(self,default=None,id_value=None,title=None):
    return self.inputHTMLTemplate % (
      '<input type="%s" %stitle="%s" name="%s" %s maxlength="%d" size="%d" step="%d" value="%s">' % (
        self.inputType,
        self.idAttrStr(id_value),
        self.titleHTML(title),
        self.name,
        self._accessKeyAttr(),
        self.maxLen,
        self.size,
        self.step,
        self._defaultHTML(default),
      )
    )


class DataList(pyweblib.forms.Input,pyweblib.forms.Select):
  """
  Input field combined with HTML5 <datalist>

  Quite hackish ;-)
  """

  def __init__(
    self,name,text,maxLen=100,maxValues=1,pattern='.*',required=0,default=None,accessKey='',
    options=None,size=None,ignoreCase=0,
  ):
    pyweblib.forms.Input.__init__(
      self,name,text,maxLen,maxValues,pattern,required,default,accessKey,
    )
#    if size==None:
#      # FIX ME!
#      size = max(map(lambda x:max(len(x),len(x[1])),options or []))
    self.size        = size or 20
    self.multiSelect = 0
    self.ignoreCase  = ignoreCase
    self.setOptions(options)
    self.setDefault(default)

  def inputHTML(self,default=None,id_value=None,title=None):
    datalist_id = str(uuid.uuid4())
    s = [ self.inputHTMLTemplate % (
      '<input %stitle="%s" name="%s" %s maxlength="%d" size="%d" value="%s" list="%s">' % (
        self.idAttrStr(id_value),
        self.titleHTML(title),
        self.name,
        self._accessKeyAttr(),
        self.maxLen,
        self.size,
        self._defaultHTML(default),
        datalist_id,
      )
    )]
    s.append(pyweblib.forms.Select.inputHTML(
        self,
        default=default,
        id_value=datalist_id,
        title=title
      ).replace('<select ','<datalist ').replace('</select>','</datalist>')
    )
    return '\n'.join(s)


class ExportFormatSelect(pyweblib.forms.Select):
  """Select field class for choosing export format"""

  def __init__(
    self,
    name='search_output',
    text=u'Export format',
    options=None,
    default='ldif1',
    required=0,
  ):
    default_options = [
      (u'table',u'Table/template'),
      (u'raw',u'Raw DN list'),
      (u'print',u'Printable'),
      (u'ldif',u'LDIF (Umich)'),
      (u'ldif1',u'LDIFv1 (RFC2849)'),
      (u'csv',u'CSV'),
    ]
    if web2ldap.app.search.ExcelWriter:
      default_options.append((u'excel',u'Excel'))
    pyweblib.forms.Select.__init__(
      self,
      name,text,1,
      options=options or default_options,
      default=default,
      required=required,
      size=1,
    )


class AttributeType(pyweblib.forms.Input):

  def __init__(self,name,text,maxValues):
    pyweblib.forms.Input.__init__(
      self,name,text,500,maxValues,
      web2ldap.ldaputil.base.attr_type_pattern,required=0,size=30
    )


class InclOpAttrsCheckbox(pyweblib.forms.Checkbox):

  def __init__(self,name,text,default='yes',checked=0):
    pyweblib.forms.Checkbox.__init__(self,name,text,1,default=default,checked=checked)


class AuthMechSelect(pyweblib.forms.Select):
  """Select field class for choosing the bind mech"""

  supported_bind_mechs = {
    '':'Simple Bind',
    'DIGEST-MD5':'SASL Bind: DIGEST-MD5',
    'CRAM-MD5':'SASL Bind: CRAM-MD5',
    'PLAIN':'SASL Bind: PLAIN',
    'LOGIN':'SASL Bind: LOGIN',
    'GSSAPI':'SASL Bind: GSSAPI',
    'EXTERNAL':'SASL Bind: EXTERNAL',
    'OTP':'SASL Bind: OTP',
    'NTLM':'SASL Bind: NTLM',
    'SCRAM-SHA-1':'SASL Bind: SCRAM-SHA-1',
  }

  def __init__(
    self,
    name='login_mech',
    text=u'Authentication mechanism',
    default=None,
    required=0,
    accesskey='',
    size=1,            # Size of displayed select field
  ):
    pyweblib.forms.Select.__init__(
      self,
      name,text,maxValues=1,
      required=required,
      options=None,
      default=default or [],
      accessKey=accesskey,
      size=size,
      ignoreCase=0,
      multiSelect=0
    )

  def setOptions(self,options):
    options_dict = {}
    options_dict[''] = self.supported_bind_mechs['']
    for o in options or self.supported_bind_mechs.keys():
      o_upper = o.upper()
      if self.supported_bind_mechs.has_key(o_upper):
        options_dict[o_upper] = self.supported_bind_mechs[o_upper]
    pyweblib.forms.Select.setOptions(self,options_dict.items())
