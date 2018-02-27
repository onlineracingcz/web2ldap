# -*- coding: utf-8 -*-
"""
web2ldap.app.schema.syntaxes: classes for known attribute types

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import sys,re,imghdr,sndhdr,urllib,uuid,datetime,time,json,xml.etree.ElementTree
from collections import defaultdict
from xml.etree.ElementTree import ParseError as XMLParseError
from types import StringType,UnicodeType,ClassType,TupleType

import ipaddress

import ldap0,ldap0.ldapurl,ldap0.schema

import pyweblib.forms

import web2ldap.msbase
import web2ldap.mspki.asn1helper
import web2ldap.ldaputil.base
import web2ldap.app.viewer,web2ldap.app.form,web2ldap.app.gui,web2ldap.app.cnf
import web2ldap.utctime
from web2ldap.ldaputil.base import is_dn


# Detect Python Imaging Library (PIL)
try:
  from PIL import Image as PILImage
except ImportError:
  PILImage = None

try:
  from cStringIO import StringIO
except ImportError:
  from StringIO import StringIO

try:
  from web2ldap.ldaputil.oidreg import oid as oid_desc_reg
except ImportError:
  oid_desc_reg = {}


class SyntaxRegistry:

  def __init__(self):
    self.oid2syntax = ldap0.cidict.cidict()
    self.at2syntax = defaultdict(dict)

  def registerSyntaxClass(self,c):
    if type(c) is ClassType and hasattr(c,'oid'):
# FIX ME!
# A better approach for unique syntax plugin class registration which
# allows overriding older registration is needed.
      if c.oid in self.oid2syntax and c!=self.oid2syntax[c.oid]:
        raise ValueError('Failed to register syntax class %s.%s with OID %s, already registered by %s.%s' % (
          c.__module__,
          c.__name__,
          repr(c.oid),
          self.oid2syntax[c.oid].__module__,
          self.oid2syntax[c.oid].__name__,
        ))
      self.oid2syntax[c.oid] = c

  def registerAttrType(self,syntax_oid,attrTypes,structural_oc_oids=None):
    structural_oc_oids = filter(None,map(str.strip,structural_oc_oids or [])) or [None]
    for a in attrTypes:
      a = a.strip()
      for oc_oid in structural_oc_oids:
# FIX ME!
# A better approach for unique attribute type registration which
# allows overriding older registration is needed.
        if a in self.at2syntax and oc_oid in self.at2syntax[a]:
          sys.stderr.write('WARNING: Registering attribute type %s with syntax %s overrides existing registration with syntax %s\n' % (
            repr(a),
            repr(syntax_oid),
            repr(self.at2syntax[a]),
          ))
        self.at2syntax[a][oc_oid] = syntax_oid

  def syntaxClass(self,schema,attrtype_nameoroid,structural_oc=None):
    attrtype_oid = schema.getoid(ldap0.schema.models.AttributeType,attrtype_nameoroid.strip())
    if structural_oc:
      structural_oc_oid = schema.getoid(ldap0.schema.models.ObjectClass,structural_oc.strip())
    else:
      structural_oc_oid = None
    syntax_oid = LDAPSyntax.oid
    try:
      syntax_oid = self.at2syntax[attrtype_oid][structural_oc_oid]
    except KeyError:
      try:
        syntax_oid = self.at2syntax[attrtype_oid][None]
      except KeyError:
        attrtype_se = schema.get_inheritedobj(ldap0.schema.models.AttributeType,attrtype_oid,['syntax'])
        if attrtype_se and attrtype_se.syntax:
          syntax_oid = attrtype_se.syntax
    try:
      syntax_class = self.oid2syntax[syntax_oid]
    except KeyError:
      syntax_class = LDAPSyntax
    return syntax_class

  def attrInstance(self,sid,form,ls,dn,schema,attrType,attrValue,entry=None):
    if entry:
      structural_oc = entry.get_structural_oc()
    else:
      structural_oc = None
    syntax_class = self.syntaxClass(schema,attrType,structural_oc)
    attr_instance = syntax_class(sid,form,ls,dn,schema,attrType,attrValue,entry)
    return attr_instance


url_pattern  = r'^(ftp|http|https|news|snews|ldap|ldaps|mailto):(|//)[^ ]*'
url_regex  = re.compile(url_pattern)
labeleduri_regex = re.compile(url_pattern+r' .*')
timestamp_pattern = r'^([0-9]){12,14}((\.|,)[0-9]+)*(Z|(\+|-)[0-9]{4})$'
timestamp_regex  = re.compile(timestamp_pattern)
mail_pattern = r'^[\w@.+=/_ ()-]+@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*$'
mail_regex = re.compile(mail_pattern)


####################################################################
# Classes of known syntaxes
####################################################################


class LDAPSyntaxValueError(ValueError):
  pass


class LDAPSyntaxRegexNoMatch(LDAPSyntaxValueError):
  pass


class LDAPSyntax:
  oid=''
  desc='Any LDAP syntax'
  inputSize = 50
  maxLen = web2ldap.app.cnf.misc.input_maxfieldlen
  maxValues = web2ldap.app.cnf.misc.input_maxattrs
  mimeType = 'application/octet-stream'
  fileExt = 'bin'
  editable = 1
  reObj = None
  searchSep = '<br>'
  readSep = '<br>'
  fieldSep = '<br>'
  fieldCountAssert = 1
  inputComposeTemplate = '{0}'
  simpleSanitizers = tuple()
  showValueButton = True

  def __init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=None):
    self.attrType = attrType
    assert type(attrValue)==StringType or attrValue is None, \
      TypeError(
        "%s(): attrtype=%r Argument 'attrValue' must be StringType or None, was: %r" % (
          self.__class__.__name__,
          attrType,
          attrValue,
        )
      )
    self.attrValue = attrValue
    self._sid = sid
    self._form = form
    self._ls = ls
    self._schema = schema
    assert type(dn)==UnicodeType, "Argument 'dn' must be UnicodeType"
    self._dn = dn
    assert entry is None or isinstance(entry,ldap0.schema.models.Entry), \
      TypeError('entry must be ldaputil.schema.Entry but is %s' % (entry.__class__.__name__))
    self._entry = entry or ldap0.schema.models.Entry(self._schema,None,{})

  def setAttrValue(self,attrValue):
    self.validate(attrValue)
    self.attrValue = attrValue

  def sanitizeInput(self,attrValue):
    """
    Transforms the HTML form input field values into LDAP string
    representations and returns raw binary string.

    This is the inverse of LDAPSyntax.formValue().

    When using this method one MUST NOT assume that the whole entry is
    present.
    """
    for sani_func in self.simpleSanitizers:
      attrValue = sani_func(attrValue)
    return attrValue

  def transmute(self,attrValues):
    """
    This method can be implemented to transmute attribute values and has
    to handle LDAP string representations (raw binary strings).

    This method has access to the whole entry after processing all input.

    Implementors should be prepared that this method could be called
    more than once. If there's nothing to change then simply return the
    same value list.

    Exceptions KeyError or IndexError are caught by the calling code to
    re-iterate invoking this method.
    """
    return attrValues

  def _regexValidate(self,attrValue):
    if self.reObj and (self.reObj.match(attrValue) is None):
      raise LDAPSyntaxRegexNoMatch, \
        "Class %s: %s does not match pattern %s." % (
          self.__class__.__name__,repr(attrValue[0:]),repr(self.reObj.pattern)
        )
    return # _regexValidate()

  def _validate(self,attrValue):
    return True

  def validate(self,attrValue):
    if attrValue:
      if not self._validate(attrValue):
        raise LDAPSyntaxValueError, \
          "Class %s: %s does not comply to syntax (attr type %s)." % (
            self.__class__.__name__,repr(attrValue),repr(self.attrType)
          )
      self._regexValidate(attrValue)

  def valueButton(self,command,row,mode,link_text=None):
    """
    return HTML markup of [+] or [-] submit buttons for adding/removing
    attribute values

    row
      row number in input table
    mode
      '+' or '-'
    link_text
      optionally override displayed link link_text
    """
    link_text = link_text or mode
    if not self.showValueButton or \
      self.maxValues<=1 or \
      len(self._entry.get(self.attrType,[]))>=self.maxValues:
      return ''
    se = self._schema.get_obj(ldap0.schema.models.AttributeType,self.attrType)
    if se and se.single_value:
      return ''
    return '<button formaction="%s#in_a_%s" type="submit" name="in_mr" value="%s%d">%s</button>' % (
      self._form.actionUrlHTML(command,self._sid),
      self._form.utf2display(self._ls.uc_decode(self.attrType)[0]),
      mode,row,link_text
    )

  def formValue(self):
    """
    Transform LDAP string representations to HTML form input field
    values. Returns Unicode string to be encoded with the browser's
    accepted charset.

    This is the inverse of LDAPSyntax.sanitizeInput().
    """
    try:
      result = self._ls.uc_decode(self.attrValue or '')[0]
    except UnicodeDecodeError:
      result = u'!!!snipped because of UnicodeDecodeError!!!'
    return result

  def mergeInput(self,input_values):
    assert len(input_values)==self.fieldCountAssert,ValueError('Received %d instead of %d input_values' % (len(input_values),self.fieldCountAssert))
    return self.inputComposeTemplate.format(*input_values)

  def formFields(self):
    return (self.formField(),)

  def formField(self):
    input_field = pyweblib.forms.Input(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,default=None,size=min(self.maxLen,self.inputSize)
    )
    input_field.charset = self._form.accept_charset
    input_field.setDefault(self.formValue())
    return input_field

  def getMimeType(self):
    return self.mimeType

  def displayValue(self,valueindex=0,commandbutton=0):
    if ldap0.ldapurl.isLDAPUrl(self.attrValue):
      displayer_class = LDAPUrl
    elif url_regex.search(self.attrValue)!=None:
      displayer_class = Uri
    elif timestamp_regex.match(self.attrValue)!=None:
      displayer_class = GeneralizedTime
    elif mail_regex.match(self.attrValue)!=None:
      displayer_class = RFC822Address
    else:
      displayer_class = DirectoryString
    # Crude hack
    self_class = self.__class__
    self.__class__ = displayer_class
    result = displayer_class.displayValue(self,valueindex,commandbutton)
    self.__class__ = self_class
    return result


class Binary(LDAPSyntax):
  oid = '1.3.6.1.4.1.1466.115.121.1.5'
  desc = 'Binary'
  editable = 0

  def formField(self):
    f = pyweblib.forms.File(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,default=self.attrValue,size=50
    )
    f.mimeType = self.mimeType
    return f

  def displayValue(self,valueindex=0,commandbutton=0):
    return '%d bytes | %s' % (
      len(self.attrValue),
      self._form.applAnchor(
        'read','View/Load',self._sid,
        [('dn',self._dn),('read_attr',self.attrType),('read_attrindex',str(valueindex))]
      )
    )


class Audio(Binary):
  oid = '1.3.6.1.4.1.1466.115.121.1.4'
  desc = 'Audio'
  mimeType = 'audio/basic'
  fileExt = 'au'

  def _validate(self,attrValue):
    f = StringIO(attrValue)
    res = sndhdr.test_au(attrValue,f)
    return res!=None

  def displayValue(self,valueindex=0,commandbutton=0):
    mimetype = self.getMimeType()
    return """
      <embed
        type="%s"
        autostart="false"
        src="%s/read/%s?dn=%s&amp;read_attr=%s&amp;read_attrindex=%d"
      >
      %d bytes of audio data (%s)
      """ % (
        mimetype,
        self._form.script_name,self._sid,
        urllib.quote(self._dn.encode(self._form.accept_charset)),
        urllib.quote(self.attrType),
        valueindex,
        len(self.attrValue),
        mimetype
      )


class DirectoryString(LDAPSyntax):
  oid = '1.3.6.1.4.1.1466.115.121.1.15'
  desc = 'Directory String'
  html_tmpl = '{av}'

  def _validate(self,attrValue):
    try:
      _ = self._ls.uc_encode(self._ls.uc_decode(attrValue)[0])[0]
    except UnicodeError:
      return False
    else:
      return True

  def sanitizeInput(self,attrValue):
    return LDAPSyntax.sanitizeInput(self,self._ls.uc_encode(self._form.uc_decode(attrValue)[0])[0])

  def displayValue(self,valueindex=0,commandbutton=0):
    return self.html_tmpl.format(
      av=self._form.utf2display(self._ls.uc_decode(self.attrValue)[0])
    )


class DistinguishedName(DirectoryString):
  oid = '1.3.6.1.4.1.1466.115.121.1.12'
  desc = 'Distinguished Name'
  isBindDN = False
  hasSubordinates = False
  noSubordinateAttrs = set(map(str.lower,[
    'subschemaSubentry',
  ]))
  ref_attrs = None

  def _validate(self,attrValue):
    return is_dn(self._ls.uc_decode(attrValue)[0])

  def _has_subordinates(self):
    return self.hasSubordinates and not self.attrType.lower() in self.noSubordinateAttrs

  def _additional_links(self):
    attr_value_u = self._ls.uc_decode(self.attrValue)[0]
    r = []
    if self.attrType.lower()!='entrydn':
      r.append(self._form.applAnchor('read','Read',self._sid,[('dn',attr_value_u)]))
    if self._has_subordinates():
      r.append(self._form.applAnchor(
        'search','Down',self._sid,
        (
          ('dn',attr_value_u),
          ('scope',web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
          ('filterstr',u'(objectClass=*)'),
        )
      ))
    if self.isBindDN:
      ldap_url_obj = self._ls.ldapUrl('',add_login=False)
      r.append(
        self._form.applAnchor(
          'login',
          'Bind as',
          None,
          [
            ('ldapurl',str(ldap_url_obj).decode('ascii')),
            ('dn',self._dn),
            ('login_who',attr_value_u),
          ],
          title=u'Connect and bind new session as\r\n%s' % (attr_value_u)
        ),
      )
    # If self.ref_attrs is not empty then add links for searching back-linking entries
    for ref_attr_tuple in self.ref_attrs or tuple():
      try:
        ref_attr,ref_text,ref_dn,ref_oc,ref_title = ref_attr_tuple
      except ValueError:
        ref_oc = None
        ref_attr,ref_text,ref_dn,ref_title = ref_attr_tuple
      ref_attr = ref_attr or self.attrType
      ref_dn = ref_dn or self._dn
      ref_title = ref_title or u'Search %s entries referencing entry %s in attribute %s' % (
        ref_oc,attr_value_u,ref_attr,
      )
      r.append(self._form.applAnchor(
        'search',self._form.utf2display(ref_text),self._sid,
        (
          ('dn',ref_dn),
          ('search_root',self._ls.currentSearchRoot),
          ('searchform_mode','adv'),
          ('search_attr','objectClass'),
          (
            'search_option',{
              True:web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS,
              False:web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL,
            }[ref_oc is None]
          ),
          ('search_string',ref_oc or u''),
          ('search_attr',ref_attr),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string',attr_value_u),
        ),
        title=ref_title,
      ))
    return r

  def displayValue(self,valueindex=0,commandbutton=0):
    attr_value_u = self._ls.uc_decode(self.attrValue)[0]
    r = [
      web2ldap.app.gui.DisplayDN(
        self._sid,
        self._form,
        self._ls,
        attr_value_u,
        commandbutton=0,
      )
    ]
    if commandbutton:
      r.extend(self._additional_links())
    return web2ldap.app.cnf.misc.command_link_separator.join(r)


class BindDN(DistinguishedName):
  oid = 'BindDN-oid'
  desc = 'A Distinguished Name used to bind to a directory'
  isBindDN = True


class AuthzDN(DistinguishedName):
  oid = 'AuthzDN-oid'
  desc = 'Authz Distinguished Name'

  def displayValue(self,valueindex=0,commandbutton=0):
    result = DistinguishedName.displayValue(self,valueindex,commandbutton)
    if commandbutton:
      simple_display_str = DistinguishedName.displayValue(self,valueindex,commandbutton=0)
      whoami_display_str = web2ldap.app.gui.WhoAmITemplate(
        self._sid,self._form,self._ls,self._dn,
        who=self.attrValue.decode(self._ls.charset)
      )
      if whoami_display_str!=simple_display_str:
        result = '<br>'.join((whoami_display_str,result))
    return result


class NameAndOptionalUID(DistinguishedName):
  oid = '1.3.6.1.4.1.1466.115.121.1.34'
  desc = 'Name And Optional UID'

  def _splitDNandUID(self,v):
    try:
      sep_ind = v.rindex(u'#')
    except ValueError:
      dn = v
      uid = None
    else:
      dn = v[0:sep_ind]
      uid = v[sep_ind+1:]
    return dn,uid

  def _validate(self,attrValue):
    dn,_ = self._splitDNandUID(self._ls.uc_decode(attrValue)[0])
    return is_dn(dn)

  def displayValue(self,valueindex=0,commandbutton=0):
    value = self.attrValue.split('#')
    dn_str = web2ldap.app.gui.DisplayDN(
      self._sid,self._form,self._ls,self._ls.uc_decode(self.attrValue)[0],commandbutton=commandbutton
    )
    if len(value)==1 or not value[1]:
      return dn_str
    else:
      return web2ldap.app.cnf.misc.command_link_separator.join([self._form.utf2display(self._ls.uc_decode(value[1])),dn_str])


class BitString(DirectoryString):
  oid = '1.3.6.1.4.1.1466.115.121.1.6'
  desc = 'Bit String'
  reObj=re.compile("^'[01]+'B$")


class IA5String(DirectoryString):
  oid = '1.3.6.1.4.1.1466.115.121.1.26'
  desc = 'IA5 String'

  def _validate(self,attrValue):
    try:
      _ = attrValue.decode('ascii').encode('ascii')
    except UnicodeError:
      return False
    else:
      return True


class GeneralizedTime(IA5String):
  oid = '1.3.6.1.4.1.1466.115.121.1.24'
  desc = 'Generalized Time'
  inputSize = 24
  maxLen=24
  reObj=timestamp_regex
  timeDefault = None
  notBefore = None
  notAfter = None
  formValueFormat = r'%Y-%m-%dT%H:%M:%SZ'
  dtFormats = (
    r'%Y%m%d%H%M%SZ',
    r'%Y-%m-%dT%H:%M:%SZ',
    r'%Y-%m-%dT%H:%MZ',
    r'%Y-%m-%dT%H:%M:%S+00:00',
    r'%Y-%m-%dT%H:%M:%S-00:00',
    r'%Y-%m-%d %H:%M:%SZ',
    r'%Y-%m-%d %H:%MZ',
    r'%Y-%m-%d %H:%M',
    r'%Y-%m-%d %H:%M:%S+00:00',
    r'%Y-%m-%d %H:%M:%S-00:00',
    r'%d.%m.%YT%H:%M:%SZ',
    r'%d.%m.%YT%H:%MZ',
    r'%d.%m.%YT%H:%M:%S+00:00',
    r'%d.%m.%YT%H:%M:%S-00:00',
    r'%d.%m.%Y %H:%M:%SZ',
    r'%d.%m.%Y %H:%MZ',
    r'%d.%m.%Y %H:%M',
    r'%d.%m.%Y %H:%M:%S+00:00',
    r'%d.%m.%Y %H:%M:%S-00:00',
  )
  acceptableDateformats = (
    r'%Y-%m-%d',
    r'%d.%m.%Y',
    r'%m/%d/%Y',
  )
  dtDisplayFormat = '<time datetime="%Y-%m-%dT%H:%M:%SZ">%A (%W. week) %Y-%m-%d %H:%M:%S+00:00</time>'

  def _validate(self,attrValue):
    try:
      dt = web2ldap.utctime.strptime(attrValue)
    except ValueError:
      return False
    else:
      return (self.notBefore==None or self.notBefore<=dt) and \
             (self.notAfter==None or self.notAfter>=dt)

  def formValue(self):
    if self.attrValue:
      try:
        dt = datetime.datetime.strptime(self.attrValue,r'%Y%m%d%H%M%SZ')
      except ValueError:
        result = IA5String.formValue(self)
      else:
        result = unicode(datetime.datetime.strftime(dt,self.formValueFormat))
    else:
      result = u''
    return result

  def sanitizeInput(self,attrValue):
    attrValue = attrValue.strip().upper()
    # Special cases first
    if attrValue in ('N','NOW'):
      return datetime.datetime.strftime(datetime.datetime.utcnow(),r'%Y%m%d%H%M%SZ')
    if self.timeDefault:
      date_format = r'%Y%m%d'+self.timeDefault+'Z'
      if attrValue in ('T','TODAY'):
        return datetime.datetime.strftime(datetime.datetime.utcnow(),date_format)
      elif attrValue in ('Y','YESTERDAY'):
        return datetime.datetime.strftime(datetime.datetime.today()-datetime.timedelta(1),date_format)
      elif attrValue in ('T','TOMORROW'):
        return datetime.datetime.strftime(datetime.datetime.today()-datetime.timedelta(1),date_format)
    # Try to parse various datetime syntaxes
    for time_format in self.dtFormats:
      try:
        dt = datetime.datetime.strptime(attrValue,time_format)
      except ValueError:
        result = None
      else:
        result = datetime.datetime.strftime(dt,r'%Y%m%d%H%M%SZ')
        break
    if result==None and self.timeDefault:
      for time_format in self.acceptableDateformats or []:
        try:
          dt = datetime.datetime.strptime(attrValue,time_format)
        except ValueError:
          result = IA5String.sanitizeInput(self,attrValue)
        else:
          result = datetime.datetime.strftime(dt,r'%Y%m%d'+self.timeDefault+'Z')
          break
    return result # sanitizeInput()

  def displayValue(self,valueindex=0,commandbutton=0):
    try:
      dt_utc = web2ldap.utctime.strptime(self.attrValue)
    except ValueError:
      return IA5String.displayValue(self,valueindex,commandbutton)
    try:
      dt_utc_str = dt_utc.strftime(self.dtDisplayFormat)
    except ValueError:
      return IA5String.displayValue(self,valueindex,commandbutton)
    if not commandbutton:
      return dt_utc_str
    current_time = datetime.datetime.utcnow()
    time_span = (current_time-dt_utc).total_seconds()
    return '{dt_utc} ({av})<br>{timespan_disp} {timespan_comment}'.format(
      dt_utc=dt_utc_str,
      av=self._form.utf2display(self._ls.uc_decode(self.attrValue)[0]),
      timespan_disp=self._form.utf2display(web2ldap.app.gui.ts2repr(Timespan.time_divisors,u' ',abs(time_span))),
      timespan_comment={
        1:'ago',
        0:'',
        -1:'ahead',
      }[cmp(time_span,0)]
    )

#  def formField(self):
#    form_value = self.formValue()
#    return web2ldap.app.form.DateTime(
#      self.attrType,
#      ': '.join([self.attrType,self.desc]),
#      self.maxLen,self.maxValues,'.*',default=form_value,step=1
#    )


class NotBefore(GeneralizedTime):
  oid = 'NotBefore-oid'
  desc = 'A not-before timestamp by default starting at 00:00:00'
  timeDefault = '000000'


class NotAfter(GeneralizedTime):
  oid = 'NotAfter-oid'
  desc = 'A not-after timestamp by default ending at 23:59:59'
  timeDefault = '235959'


class UTCTime(GeneralizedTime):
  oid = '1.3.6.1.4.1.1466.115.121.1.53'
  desc = 'UTC Time'


class NullTerminatedDirectoryString(DirectoryString):
  oid = 'NullTerminatedDirectoryString-oid'
  desc = 'Directory String terminated by null-byte'

  def sanitizeInput(self,attrValue):
    return attrValue+chr(0)

  def _validate(self,attrValue):
    return attrValue.endswith(chr(0))

  def formValue(self):
    return self._ls.uc_decode((self.attrValue or chr(0))[:-1])[0]

  def displayValue(self,valueindex=0,commandbutton=0):
    return self._form.utf2display(self._ls.uc_decode((self.attrValue or chr(0))[:-1])[0])


class OtherMailbox(DirectoryString):
  oid = '1.3.6.1.4.1.1466.115.121.1.39'
  desc = 'Other Mailbox'
  charset = 'ascii'


class Integer(IA5String):
  oid = '1.3.6.1.4.1.1466.115.121.1.27'
  desc = 'Integer'
  inputSize = 12
  minValue = None
  maxValue = None

  def __init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=None):
    IA5String.__init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry)
    if self.maxValue!=None:
      self.maxLen = len(str(self.maxValue))

  def _maxlen(self,form_value):
    min_value_len = max_value_len = form_value_len = 0
    if self.minValue!=None:
      min_value_len = len(str(self.minValue))
    if self.maxValue!=None:
      max_value_len = len(str(self.maxValue))
    if form_value!=None:
      form_value_len = len(form_value.encode(self._ls.charset))
    return max(self.inputSize,form_value_len,min_value_len,max_value_len)

  def _validate(self,attrValue):
    try:
      intValue = int(attrValue)
    except ValueError:
      return False
    else:
      min_value,max_value = self.minValue,self.maxValue
      return (min_value==None or intValue>=min_value) and (max_value==None or intValue<=max_value)

  def sanitizeInput(self,attrValue):
    try:
      return str(int(attrValue))
    except ValueError:
      return attrValue

  def formField(self):
    form_value = self.formValue()
    max_len = self._maxlen(form_value)
    return pyweblib.forms.Input(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      max_len,self.maxValues,'[0-9]*',default=form_value,size=min(self.inputSize,max_len)
    )


IntegerRange = Integer


class IPHostAddress(IA5String):
  oid = 'IPHostAddress-oid'
  desc = 'string representation of IPv4 or IPv6 address'
  # Class in module ipaddr which parses address/network values
  addr_class = None
  simpleSanitizers = (
    str.strip,
  )

  def _validate(self,attrValue):
    try:
      addr = ipaddress.ip_address(attrValue.decode('ascii'))
    except Exception:
      return False
    else:
      return self.addr_class == None or isinstance(addr,self.addr_class)


class IPv4HostAddress(IPHostAddress):
  oid = 'IPv4HostAddress-oid'
  desc = 'string representation of IPv4 address'
  addr_class = ipaddress.IPv4Address


class IPv6HostAddress(IPHostAddress):
  oid = 'IPv6HostAddress-oid'
  desc = 'string representation of IPv6 address'
  addr_class = ipaddress.IPv6Address


class IPNetworkAddress(IPHostAddress):
  oid = 'IPNetworkAddress-oid'
  desc = 'string representation of IPv4 or IPv6 network address/mask'

  def _validate(self,attrValue):
    try:
      addr = ipaddress.ip_network(attrValue.decode('ascii'), strict=False)
    except Exception:
      return False
    else:
      return self.addr_class == None or isinstance(addr,self.addr_class)


class IPv4NetworkAddress(IPNetworkAddress):
  oid = 'IPv4NetworkAddress-oid'
  desc = 'string representation of IPv4 network address/mask'
  addr_class = ipaddress.IPv4Network


class IPv6NetworkAddress(IPNetworkAddress):
  oid = 'IPv6NetworkAddress-oid'
  desc = 'string representation of IPv6 network address/mask'
  addr_class = ipaddress.IPv6Network


class IPServicePortNumber(Integer):
  oid = 'IPServicePortNumber-oid'
  desc = 'Port number for an UDP- or TCP-based service'
  minValue = 0
  maxValue = 65535


class MacAddress(IA5String):
  oid = 'MacAddress-oid'
  desc = 'MAC address in hex-colon notation'
  minLen = 17
  maxLen = 17
  reObj=re.compile(r'^([0-9a-f]{2}\:){5}[0-9a-f]{2}$')

  def sanitizeInput(self,attrValue):
    attr_value = attrValue.translate(None,'.-: ').lower().strip()
    if len(attr_value)==12:
      return ':'.join([ attr_value[i*2:i*2+2] for i in range(6) ])
    else:
      return attrValue


class Uri(DirectoryString):
  """
  see RFC 2079
  """
  oid = 'Uri-OID'
  desc = 'URI'
  reObj = url_regex
  simpleSanitizers = (
    str.strip,
  )

  def displayValue(self,valueindex=0,commandbutton=0):
    attr_value = self._ls.uc_decode(self.attrValue)[0]
    try:
      url,label = attr_value.split(u' ',1)
    except ValueError:
      url,label = attr_value,attr_value
      display_url = u''
    else:
      display_url = u' (%s)' % (url)
    if ldap0.ldapurl.isLDAPUrl(url):
      return '<a href="%s?%s">%s%s</a>' % (
        self._form.script_name,
        self._form.utf2display(url),
        self._form.utf2display(label),
        self._form.utf2display(display_url),
      )
    else:
      return '<a href="%s/urlredirect/%s?%s">%s%s</a>' % (
        self._form.script_name,
        self._sid,
        self._form.utf2display(url),
        self._form.utf2display(label),
        self._form.utf2display(display_url),
      )


class Image(Binary):
  oid = 'Image-OID'
  desc = 'Image base class'
  mimeType = 'application/octet-stream'
  fileExt = 'bin'
  imageFormat = None
  inline_maxlen = 630 # max. number of bytes to use data: URI instead of external URL

  def _validate(self,attrValue):
    return imghdr.what(None,attrValue)==self.imageFormat.lower()

  def sanitizeInput(self,attrValue):
    if not self._validate(attrValue) and PILImage:
      f = StringIO(attrValue)
      f2 = StringIO()
      try:
        try:
          im = PILImage.open(f)
          im.save(f2,self.imageFormat)
        except (IOError,ValueError):
          attrValue = None
        else:
          attrValue = f2.getvalue()
      finally:
        f.close()
    return attrValue

  def displayValue(self,valueindex=0,commandbutton=0):
    maxwidth,maxheight = 100,150
    width,height = None,None
    size_attr_html = ''
    if PILImage:
      f = StringIO(self.attrValue)
      try:
        im = PILImage.open(f)
      except IOError:
        pass
      else:
        width,height = im.size
        if width>maxwidth:
          size_attr_html = 'width="%d" height="%d"' % (maxwidth,int(float(maxwidth)/width*height))
        elif height>maxheight:
          size_attr_html = 'width="%d" height="%d"' % (int(float(maxheight)/height*width),maxheight)
        else:
          size_attr_html = 'width="%d" height="%d"' % (width,height)
    attr_value_len = len(self.attrValue)
    img_link = "%s/read/%s?dn=%s&amp;read_attr=%s&amp;read_attrindex=%d&amp;read_attrmode=load&amp" % (
      self._form.script_name,self._sid,
      urllib.quote(self._dn.encode(self._form.accept_charset)),
      urllib.quote(self.attrType),
      valueindex,
    )
    if attr_value_len<=self.inline_maxlen:
      return """
        <a href="%s">
          <img
            src="data:%s;base64,\n%s"
            alt="%d bytes of image data" %s>
        </a>
        """ % (img_link,self.mimeType,self.attrValue.encode('base64'),attr_value_len,size_attr_html)
    else:
      return """
        <a href="%s">
          <img
            src="%s"
            alt="%d bytes of image data" %s>
        </a>
        """ % (
        img_link,img_link,attr_value_len,size_attr_html,
      )


class JPEGImage(Image):
  oid = '1.3.6.1.4.1.1466.115.121.1.28'
  desc = 'JPEG image'
  mimeType = 'image/jpeg'
  fileExt = 'jpg'
  imageFormat = 'JPEG'


class PhotoG3Fax(Binary):
  oid = '1.3.6.1.4.1.1466.115.121.1.23'
  desc = 'Photo (G3 fax)'
  mimeType = 'image/g3fax'
  fileExt = 'tif'


class OID(IA5String):
  oid = '1.3.6.1.4.1.1466.115.121.1.38'
  desc = 'OID'
  reObj=re.compile(r'^([a-zA-Z]+[a-zA-Z0-9;-]*|[0-2]?\.([0-9]+\.)*[0-9]+)$')

  def valueButton(self,command,row,mode,link_text=None):
    at = self.attrType.lower()
    if at=='objectclass' or \
       at=='structuralobjectclass' or \
       at=='2.5.4.0' or \
       at=='2.5.21.9':
      return ''
    return IA5String.valueButton(self,command,row,mode,link_text=link_text)

  def sanitizeInput(self,attrValue):
    attrValue = attrValue.strip()
    if attrValue.startswith('{') and attrValue.endswith('}'):
      try:
        attrValue = web2ldap.ldaputil.base.ietf_oid_str(attrValue)
      except ValueError:
        pass
    return attrValue

  def displayValue(self,valueindex=0,commandbutton=0):
    try:
      name,description,reference = oid_desc_reg[self.attrValue]
    except (KeyError,ValueError):
      try:
        se = self._schema.get_obj(ldap0.schema.models.ObjectClass,self.attrValue,raise_keyerror=1)
      except KeyError:
        try:
          se = self._schema.get_obj(ldap0.schema.models.AttributeType,self.attrValue,raise_keyerror=1)
        except KeyError:
            return IA5String.displayValue(self,valueindex,commandbutton)
        else:
          return web2ldap.app.gui.SchemaElementName(
            self._sid,self._form,self._dn,self._schema,self.attrValue,ldap0.schema.models.AttributeType,name_template=r'%s'
          )
      else:
        name_template = {
          0:r'%s <em>STRUCTURAL</em>',
          1:r'%s <em>ABSTRACT</em>',
          2:r'%s <em>AUXILIARY</em>'
        }[se.kind]
      # objectClass attribute is displayed with different function
      return web2ldap.app.gui.SchemaElementName(
        self._sid,self._form,self._dn,self._schema,self.attrValue,ldap0.schema.models.ObjectClass,
        name_template=name_template
      )
    else:
      return '<strong>%s</strong> (%s):<br>%s (see %s)' % (
        self._form.utf2display(name),
        IA5String.displayValue(self,valueindex,commandbutton),
        self._form.utf2display(description),
        self._form.utf2display(reference)
      )


class LDAPUrl(Uri):
  oid = 'LDAPUrl-oid'
  desc = 'LDAP URL'

  def _command_ldap_url(self,ldap_url):
    return ldap_url

  def displayValue(self,valueindex=0,commandbutton=0):
    try:
      if commandbutton:
        commandbuttonstr = web2ldap.app.gui.LDAPURLButton(
          self._sid,
          self._form,
          self._ls,
          self._command_ldap_url(self.attrValue),
        )
      else:
        commandbuttonstr = ''
      return '<table><tr><td>%s</td><td><a href="%s">%s</a></td></tr></table>' % (
               commandbuttonstr,
               self._form.utf2display(self._ls.uc_decode(self.attrValue)[0]),
               self._form.utf2display(self._ls.uc_decode(self.attrValue)[0])
             )
    except ValueError:
      return '<strong>Not a valid LDAP URL:</strong> %s' % self._form.utf2display(repr(self.attrValue))


class OctetString(Binary):
  oid = '1.3.6.1.4.1.1466.115.121.1.40'
  desc = 'Octet String'
  editable = 1
  minInputRows = 1  # minimum number of rows for input field
  maxInputRows = 15 # maximum number of rows for in input field
  bytes_split = 16

  def sanitizeInput(self,attrValue):
    attrValue = attrValue.translate(None,': ,\r\n')
    try:
      result_str = attrValue.decode('hex')
    except TypeError as e:
      raise LDAPSyntaxValueError('Illegal human-readable OctetString representation: %s' % e)
    return result_str

  def displayValue(self,valueindex=0,commandbutton=0):
    lines = [
      '<tr><td><code>%0.6X</code></td><td><code>%s</code></td><td><code>%s</code></td></tr>'% (
        i*self.bytes_split,
        ':'.join(x.encode('hex').upper() for x in c),
        self._form.utf2display(unicode(web2ldap.msbase.ascii_dump(c),'ascii')),
      )
      for i,c in enumerate(web2ldap.msbase.chunks(self.attrValue,self.bytes_split))
    ]
    return '\n<table class="HexDump">\n%s\n</table>\n' % ('\n'.join(lines))

  def formValue(self):
    return unicode('\r\n'.join(
      web2ldap.msbase.chunks(
        ':'.join(x.encode('hex').upper() for x in self.attrValue or ''),
        self.bytes_split*3
      )
    ))

  def formField(self):
    form_value = self.formValue()
    return pyweblib.forms.Textarea(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      10000,1,
      None,
      default=form_value,
      rows=max(self.minInputRows,min(self.maxInputRows,form_value.count('\r\n'))),
      cols=49
    )


class MultilineText(DirectoryString):
  oid = 'MultilineText-oid'
  desc = 'Multiple lines of text'
  reObj=re.compile('^.*$',re.S+re.M)
  lineSep = u'\r\n'
  mimeType = 'text/plain'
  cols = 66
  minInputRows = 1  # minimum number of rows for input field
  maxInputRows = 30 # maximum number of rows for in input field

  def _split_lines(self,v):
    if self.lineSep:
      return v.split(self.lineSep)
    else:
      return [v]

  def sanitizeInput(self,attrValue):
    return attrValue.replace(u'\r',u'').replace(u'\n',self.lineSep).encode(self._ls.charset)

  def displayValue(self,valueindex=0,commandbutton=0):
    lines = [
      self._form.utf2display(l)
      for l in self._split_lines(self._ls.uc_decode(self.attrValue)[0])
    ]
    return '<br>'.join(lines)

  def formValue(self):
    splitted_lines = self._split_lines(self._ls.uc_decode(self.attrValue or '')[0])
    return u'\r\n'.join(splitted_lines)

  def formField(self):
    form_value=self.formValue()
    return pyweblib.forms.Textarea(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,
      None,
      default=form_value,
      rows=max(self.minInputRows,min(self.maxInputRows,form_value.count('\r\n'))),
      cols=self.cols
    )


class PreformattedMultilineText(MultilineText):
  oid = 'PreformattedMultilineText-oid'
  cols = 66
  tab_identiation='&nbsp;&nbsp;&nbsp;&nbsp;'
#  whitespace_cleaning = unicode.rstrip
  whitespace_cleaning = None

  def sanitizeInput(self,attrValue):
    if self.whitespace_cleaning is None:
      return attrValue
    return self.lineSep.join([
      self.whitespace_cleaning(l)
      for l in self._split_lines(attrValue.decode(self._form.accept_charset))
    ]).encode(self._ls.charset)

  def displayValue(self,valueindex=0,commandbutton=0):
    lines = [
      self._form.utf2display(l,self.tab_identiation)
      for l in self._split_lines(self._ls.uc_decode(self.attrValue)[0])
    ]
    return '<code>%s</code>' % '<br>'.join(lines)


class PostalAddress(MultilineText):
  oid = '1.3.6.1.4.1.1466.115.121.1.41'
  desc = 'Postal Address'
  lineSep = ' $ '
  cols = 40

  def _split_lines(self,value):
    return [ v.strip() for v in value.split(self.lineSep.strip()) ]

  def sanitizeInput(self,attrValue):
    return attrValue.replace('\r','').replace('\n',self.lineSep)


class PrintableString(DirectoryString):
  oid = '1.3.6.1.4.1.1466.115.121.1.44'
  desc = 'Printable String'
  reObj= re.compile("^[a-zA-Z0-9'()+,.=/:? -]*$")
  charset = 'ascii'

class NumericString(PrintableString):
  oid = '1.3.6.1.4.1.1466.115.121.1.36'
  desc = 'Numeric String'
  reObj= re.compile('^[ 0-9]+$')


class EnhancedGuide(PrintableString):
  oid = '1.3.6.1.4.1.1466.115.121.1.21'
  desc = 'Enhanced Search Guide'


class Guide(EnhancedGuide):
  oid = '1.3.6.1.4.1.1466.115.121.1.25'
  desc = 'Search Guide'


class TelephoneNumber(PrintableString):
  oid = '1.3.6.1.4.1.1466.115.121.1.50'
  desc = 'Telephone Number'
  reObj= re.compile('^[0-9+x(). /-]+$')


class FacsimileTelephoneNumber(TelephoneNumber):
  oid = '1.3.6.1.4.1.1466.115.121.1.22'
  desc = 'Facsimile Number'
  reObj= re.compile('^[0-9+x(). /-]+(\$(twoDimensional|fineResolution|unlimitedLength|b4Length|a3Width|b4Width|uncompressed))*$')


class TelexNumber(PrintableString):
  oid = '1.3.6.1.4.1.1466.115.121.1.52'
  desc = 'Telex Number'
  reObj= re.compile("^[a-zA-Z0-9'()+,.=/:?$ -]*$")

class TeletexTerminalIdentifier(PrintableString):
  oid = '1.3.6.1.4.1.1466.115.121.1.51'
  desc = 'Teletex Terminal Identifier'


class ObjectGUID(LDAPSyntax):
  oid = 'ObjectGUID-oid'
  desc = 'Object GUID'
  charset = 'ascii'

  def displayValue(self,valueindex=0,commandbutton=0):
    objectguid_str = ''.join(['%02X' % ord(c) for c in self.attrValue])
    return ldap0.ldapurl.LDAPUrl(
      ldapUrl=self._ls.uri,
      dn='GUID=%s' % (objectguid_str),
      who=None,cred=None
    ).htmlHREF(
      hrefText=objectguid_str,
      hrefTarget=None
    )


class Date(IA5String):
  oid = 'Date-oid'
  desc = 'Date in syntax specified by class attribute storageFormat'
  maxLen = 10
  storageFormat = '%Y-%m-%d'
  acceptableDateformats = (
    '%Y-%m-%d',
    '%d.%m.%Y',
    '%m/%d/%Y',
  )

  def _validate(self,attrValue):
    try:
      datetime.datetime.strptime(attrValue,self.storageFormat)
    except ValueError:
      return 0
    else:
      return 1

  def sanitizeInput(self,attrValue):
    attrValue = attrValue.strip()
    for time_format in self.acceptableDateformats:
      try:
        time_tuple = datetime.datetime.strptime(attrValue,time_format)
      except ValueError:
        result = attrValue
      else:
        result = datetime.datetime.strftime(time_tuple,self.storageFormat)
        break
    return result # sanitizeInput()


class NumstringDate(Date):
  oid = 'NumstringDate-oid'
  desc = 'Date in syntax YYYYMMDD'
  reObj = re.compile('^[0-9]{4}[0-1][0-9][0-3][0-9]$')
  storageFormat = '%Y%m%d'


class ISO8601Date(Date):
  oid = 'ISO8601Date-oid'
  desc = 'Date in syntax YYYY-MM-DD, see ISO 8601'
  reObj = re.compile('^[0-9]{4}-[0-1][0-9]-[0-3][0-9]$')
  storageFormat = '%Y-%m-%d'


class SecondsSinceEpoch(Integer):
  oid = 'SecondsSinceEpoch-oid'
  desc = 'Seconds since epoch (1970-01-01 00:00:00)'

  def displayValue(self,valueindex=0,commandbutton=0):
    int_str = Integer.displayValue(self,valueindex,commandbutton)
    try:
      return '%s (%s)' % (
        web2ldap.utctime.strftimeiso8601(time.gmtime(float(self.attrValue))).encode('ascii'),
        int_str,
      )
    except ValueError:
      return int_str


class DaysSinceEpoch(Integer):
  oid = 'DaysSinceEpoch-oid'
  desc = 'Days since epoch (1970-01-01)'

  def displayValue(self,valueindex=0,commandbutton=0):
    int_str = Integer.displayValue(self,valueindex,commandbutton)
    try:
      return '%s (%s)' % (
        web2ldap.utctime.strftimeiso8601(time.gmtime(float(self.attrValue)*86400)).encode('ascii'),
        int_str,
      )
    except ValueError:
      return int_str


class Timespan(Integer):
  oid = 'Timespan-oid'
  desc = 'Time span in seconds'
  inputSize = LDAPSyntax.inputSize
  time_divisors = (
    (u'weeks',604800),
    (u'days',86400),
    (u'hours',3600),
    (u'mins',60),
    (u'secs',1),
  )
  sep = u','

  def sanitizeInput(self,attrValue):
    if attrValue:
      try:
        result = str(web2ldap.app.gui.repr2ts(self.time_divisors,self.sep,attrValue))
      except ValueError:
        result = Integer.sanitizeInput(self,attrValue)
    else:
      result = attrValue
    return result

  def formValue(self):
    if not self.attrValue:
      return self.attrValue
    try:
      result = web2ldap.app.gui.ts2repr(self.time_divisors,self.sep,int(self.attrValue))
    except ValueError:
      result = Integer.formValue(self)
    return result

  def displayValue(self,valueindex=0,commandbutton=0):
    try:
      result = self._form.utf2display('%s (%s)' % (
        web2ldap.app.gui.ts2repr(self.time_divisors,self.sep,int(self.attrValue)),
        Integer.displayValue(self,valueindex,commandbutton)
      ))
    except ValueError:
      result = Integer.displayValue(self,valueindex,commandbutton)
    return result


class SelectList(DirectoryString):
  """
  Base class for dictionary based select lists which
  should not be used directly
  """
  oid = 'SelectList-oid'
  attr_value_dict = {} # Mapping attribute value to attribute description
  input_fallback = True # Fallback to normal input field if attr_value_dict is empty

  def _get_attr_value_dict(self):
    # Enable empty value in any case
    attr_value_dict = {
      u'':u'-/-',
    }
    attr_value_dict.update(self.attr_value_dict)
    return attr_value_dict

  def _sorted_select_options(self):
    # First generate a set of all other currently available attribute values
    attr_value_u = DirectoryString.formValue(self)
    # Initialize a dictionary with all options
    d = self._get_attr_value_dict()
    # Remove other existing values from the options dict
    for v in self._entry.get(self.attrType,[]):
      v = self._ls.uc_decode(v)[0]
      if v!=attr_value_u:
        try:
          del d[v]
        except KeyError:
          pass
    # Add the current attribute value if needed
    if not attr_value_u in d:
      d[attr_value_u] = attr_value_u
    # Finally return the sorted option list
    result = []
    for k,v in d.items():
      if type(v)==UnicodeType:
        result.append((k,v,None))
      elif type(v)==TupleType:
        result.append((k,v[0],v[1]))
    return sorted(
      result,
      key=lambda x:x[1].lower()
    )

  def _validate(self,attrValue):
    attr_value_dict = self._get_attr_value_dict()
    return self._ls.uc_decode(attrValue)[0] in attr_value_dict

  def displayValue(self,valueindex=0,commandbutton=0):
    attr_value_str = DirectoryString.displayValue(self,valueindex,commandbutton)
    attr_value_dict = self._get_attr_value_dict()
    try:
      attr_value_desc=attr_value_dict[self.attrValue]
    except KeyError:
      return attr_value_str
    else:
      try:
        attr_text,attr_title = attr_value_desc
      except ValueError:
        attr_text,attr_title = attr_value_desc,None
      if attr_text==attr_value_str:
        return attr_value_str
      else:
        if attr_title:
          tag_tmpl = '<span title="{attr_title}">{attr_text}: {attr_value}</span>'
        else:
          tag_tmpl = '{attr_text}: {attr_value}'
        return tag_tmpl.format(
          attr_value = attr_value_str,
          attr_text = self._form.utf2display(attr_text),
          attr_title = self._form.utf2display(attr_title or u'')
        )

  def formField(self):
    attr_value_dict = self._get_attr_value_dict()
    if self.input_fallback and \
       (not attr_value_dict or not filter(None,attr_value_dict.keys())):
      return DirectoryString.formField(self)
    else:
      f = pyweblib.forms.Select(
        self.attrType,
        ': '.join([self.attrType,self.desc]),1,
        options=self._sorted_select_options(),
        default=self.formValue(),
        required=0
      )
      f.charset=self._form.accept_charset
      return f


class PropertiesSelectList(SelectList):
  oid = 'PropertiesSelectList-oid'
  properties_pathname = None
  properties_charset = 'utf-8'
  properties_delimiter = u'='

  def _get_attr_value_dict(self):
    attr_value_dict = SelectList._get_attr_value_dict(self)
    real_path_name = web2ldap.app.gui.GetVariantFilename(
      self.properties_pathname,
      self._form.accept_language
    )
    f = open(real_path_name,'rb')
    for line in f.readlines():
      line = line.decode(self.properties_charset).strip()
      if line and not line.startswith('#'):
        key,value = line.split(self.properties_delimiter)
        attr_value_dict[key.strip()] = value.strip()
    return attr_value_dict # _readProperties()


class DynamicValueSelectList(SelectList,DirectoryString):
  oid = 'DynamicValueSelectList-oid'
  ldap_url = None
  valuePrefix = ''
  valueSuffix = ''

  def __init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=None):
    self.lu_obj = ldap0.ldapurl.LDAPUrl(self.ldap_url)
    self.minLen = len(self.valuePrefix)+len(self.valueSuffix)
    SelectList.__init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry)

  def _determineFilter(self):
    return self.lu_obj.filterstr or '(objectClass=*)'

  def _searchReferencedEntry(self,attrValue):
    search_dn = self._determineSearchDN(self._dn,self.lu_obj.dn)
    attr_value = attrValue[len(self.valuePrefix):-len(self.valueSuffix) or None]
    search_filter = '(&%s(%s=%s))' % (
      self._determineFilter(),
      self.lu_obj.attrs[0],
      attr_value,
    )
    try:
      ldap_result = self._ls.l.search_s(
        self._ls.uc_encode(search_dn)[0],
        self.lu_obj.scope,
        search_filter,
        attrlist=self.lu_obj.attrs,
        sizelimit=2,
      )
    except (
      ldap0.NO_SUCH_OBJECT,
      ldap0.CONSTRAINT_VIOLATION,
      ldap0.INSUFFICIENT_ACCESS,
      ldap0.REFERRAL,
      ldap0.SIZELIMIT_EXCEEDED,
      ldap0.TIMELIMIT_EXCEEDED,
    ):
      return None
    else:
      # Filter out LDAP referrals
      ldap_result = [
        (dn,entry)
        for dn,entry in ldap_result
        if dn!=None
      ]
      if ldap_result and len(ldap_result)==1:
        return ldap_result[0]
      else:
        return None

  def _validate(self,attrValue):
    if not attrValue.startswith(self.valuePrefix) or \
       not attrValue.endswith(self.valueSuffix) or \
       len(attrValue)<self.minLen or (self.maxLen!=None and len(attrValue)>self.maxLen):
      return 0
    return self._searchReferencedEntry(attrValue)!=None

  def displayValue(self,valueindex=0,commandbutton=0):
    if commandbutton and self.lu_obj.attrs:
      ref_result = self._searchReferencedEntry(self.attrValue)
      if ref_result:
        ref_dn,ref_entry = ref_result
        try:
          attr_value_desc=self._ls.uc_decode(ref_entry[self.lu_obj.attrs[1]][0])[0]
        except (KeyError,IndexError):
          display_text,link_html = '',''
        else:
          if self.lu_obj.attrs[0].lower()==self.lu_obj.attrs[1].lower():
            display_text = ''
          else:
            display_text = self._form.utf2display(attr_value_desc+u':')
          if commandbutton:
            link_html = self._form.applAnchor(
              'read','&raquo;',self._sid,
              [('dn',self._ls.uc_decode(ref_dn)[0])],
            )
          else:
            link_html = ''
      else:
        display_text,link_html = '',''
    else:
      display_text,link_html = '',''
    return ' '.join((
      display_text,
      DirectoryString.displayValue(self,valueindex,commandbutton),
      link_html,
    ))

  def _determineSearchDN(self,current_dn,ldap_url_dn):
    ldap_url_dn = self._ls.uc_decode(ldap_url_dn)[0]
    if ldap_url_dn=='_':
      result_dn = self._ls.getSearchRoot(current_dn or self._dn or self._ls._dn)
    elif ldap_url_dn=='.':
      result_dn = current_dn
    elif ldap_url_dn=='..':
      result_dn = web2ldap.ldaputil.base.ParentDN(current_dn)
    elif ldap_url_dn.endswith(',_'):
      result_dn = ','.join((ldap_url_dn[:-2],self._ls.getSearchRoot(self._dn)))
    elif ldap_url_dn.endswith(',.'):
      result_dn = ','.join((ldap_url_dn[:-2],current_dn))
    elif ldap_url_dn.endswith(',..'):
      result_dn = ','.join((ldap_url_dn[:-3],web2ldap.ldaputil.base.ParentDN(current_dn)))
    else:
      result_dn = ldap_url_dn
    if result_dn.endswith(','):
      result_dn = result_dn[:-1]
    return result_dn # _determineSearchDN()

  def _get_attr_value_dict(self):
    attr_value_dict = SelectList._get_attr_value_dict(self)
    if self.lu_obj.hostport:
      # New connection to separate server
      # not implemented yet!
      pass
    else:
      search_dn = self._determineSearchDN(self._dn,self.lu_obj.dn)
      search_scope = self.lu_obj.scope or ldap0.SCOPE_BASE
      search_attrs = (self.lu_obj.attrs or []) + ['description','info']
      # Use the existing LDAP connection as current user
      try:
        ldap_result = self._ls.l.search_s(
          self._ls.uc_encode(search_dn)[0],
          search_scope,
          filterstr=self._determineFilter(),
          attrlist=search_attrs,
        )
      except (
        ldap0.NO_SUCH_OBJECT,
        ldap0.SIZELIMIT_EXCEEDED,
        ldap0.TIMELIMIT_EXCEEDED,
        ldap0.PARTIAL_RESULTS,
        ldap0.INSUFFICIENT_ACCESS,
        ldap0.CONSTRAINT_VIOLATION,
        ldap0.REFERRAL,
      ):
        return {}
    if search_scope==ldap0.SCOPE_BASE:
      dn_r,entry_r=ldap_result[0]
      # When reading a single entry we build the map from a single multi-valued attribute
      assert len(self.lu_obj.attrs or [])==1,"attrlist in ldap_url must be of length 1 if scope is base"
      list_attr = self.lu_obj.attrs[0]
      attr_values_u = [
        ''.join((
          self.valuePrefix,
          self._ls.uc_decode(attr_value)[0],
          self.valueSuffix,
        ))
        for attr_value in entry_r[list_attr]
      ]
      attr_value_dict=dict([ (u,u) for u in attr_values_u ])
    else:
      if not self.lu_obj.attrs:
        option_value_map,option_text_map = (None,None)
      elif len(self.lu_obj.attrs)==1:
        option_value_map,option_text_map = (None,self.lu_obj.attrs[0])
      elif len(self.lu_obj.attrs)>=2:
        option_value_map,option_text_map = self.lu_obj.attrs[:2]
      for dn_r,entry_r in ldap_result:
        # Check whether it's a real search result (ignore search continuations)
        if not dn_r is None:
          entry_r[None] = [dn_r]
          try:
            option_value = ''.join((
              self.valuePrefix,
              self._ls.uc_decode(entry_r[option_value_map][0])[0],
              self.valueSuffix,
            ))
          except KeyError:
            pass
          else:
            try:
              option_text = self._ls.uc_decode(entry_r[option_text_map][0])[0]
            except KeyError:
              option_text = option_value
            option_title = entry_r.get('description',entry_r.get('info',['']))[0]
            if option_title:
              option_title = self._ls.uc_decode(option_title)[0]
              attr_value_dict[option_value] = (option_text,option_title)
            else:
              attr_value_dict[option_value] = option_text
    return attr_value_dict # _get_attr_value_dict()


class DynamicDNSelectList(DynamicValueSelectList,DistinguishedName):
  oid = 'DynamicDNSelectList-oid'

  def _readReferencedEntry(self,dn):
    try:
      ldap_result = self._ls.readEntry(
        dn.decode(self._ls.charset),
        attrtype_list=self.lu_obj.attrs,
        search_filter=self._determineFilter(),
      )
    except (
      ldap0.NO_SUCH_OBJECT,
      ldap0.CONSTRAINT_VIOLATION,
      ldap0.INSUFFICIENT_ACCESS,
      ldap0.INVALID_DN_SYNTAX,
      ldap0.REFERRAL,
    ):
      return None
    else:
      if ldap_result:
        return ldap_result[0][1]
      else:
        return None

  def _validate(self,attrValue):
    return self._readReferencedEntry(attrValue)!=None

  def displayValue(self,valueindex=0,commandbutton=0):
    if commandbutton and self.lu_obj.attrs:
      ref_entry = self._readReferencedEntry(self.attrValue) or {}
      try:
        attr_value_desc=self._ls.uc_decode(ref_entry[self.lu_obj.attrs[0]][0])[0]
      except (KeyError,IndexError):
        display_text = ''
      else:
        display_text = self._form.utf2display(attr_value_desc+u': ')
    else:
      display_text = ''
    return ''.join((
      display_text,
      DistinguishedName.displayValue(self,valueindex,commandbutton)
    ))


class Boolean(SelectList,IA5String):
  oid = '1.3.6.1.4.1.1466.115.121.1.7'
  desc = 'Boolean'
  attr_value_dict = {
    u'TRUE':u'TRUE',
    u'FALSE':u'FALSE',
  }

  def _get_attr_value_dict(self):
    attr_value_dict = SelectList._get_attr_value_dict(self)
    if self.attrValue and self.attrValue.lower()==self.attrValue:
      for k,v in attr_value_dict.items():
        del attr_value_dict[k]
        attr_value_dict[k.lower()] = v.lower()
    return attr_value_dict

  def _validate(self,attrValue):
    if not self.attrValue and attrValue.lower()==attrValue:
      return SelectList._validate(self,attrValue.upper())
    else:
      return SelectList._validate(self,attrValue)

  def displayValue(self,valueindex=0,commandbutton=0):
    return IA5String.displayValue(self,valueindex,commandbutton)


class CountryString(SelectList):
  oid = '1.3.6.1.4.1.1466.115.121.1.11'
  desc = 'Two letter country string as listed in ISO 3166-2'
  attr_value_dict = web2ldap.app.cnf.countries.c_dict
  simpleSanitizers = (
    str.strip,
  )


class DeliveryMethod(PrintableString):
  oid = '1.3.6.1.4.1.1466.115.121.1.14'
  desc = 'Delivery Method'
  pdm = '(any|mhs|physical|telex|teletex|g3fax|g4fax|ia5|videotex|telephone)'
  reObj= re.compile('^%s[ $]*%s$' % (pdm,pdm))


class BitArrayInteger(MultilineText,Integer):
  oid = 'BitArrayInteger-oid'
  flag_desc_table = tuple()
  true_false_desc={1:'+',0:'-'}
  minValue=0

  def __init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=None):
    Integer.__init__(self,sid,form,ls,dn,schema,attrType,attrValue)
    self.flag_desc2int=dict(self.flag_desc_table)
    self.flag_int2desc=dict([(j,i) for i,j in self.flag_desc_table])
    self.maxValue=sum([j for i,j in self.flag_desc_table])
    self.minInputRows=self.maxInputRows=max(len(self.flag_desc_table),1)

  def sanitizeInput(self,attrValue):
    try:
      result = int(attrValue)
    except ValueError:
      result = 0
      for row in attrValue.split('\n'):
        row=row.strip()
        try:
          flag_set,flag_desc=row[0],row[1:]
        except IndexError:
          pass
        else:
          if flag_set=='+':
            try:
              result=result|self.flag_desc2int[flag_desc]
            except KeyError:
              pass
    return str(result)

  def formValue(self):
    attr_value_int=int(self.attrValue or 0)
    flag_lines = [
      ''.join((
        self.true_false_desc[int((attr_value_int&flag_int)>0)],
        flag_desc
      ))
      for flag_desc,flag_int in self.flag_desc_table
    ]
    return u'\r\n'.join(flag_lines)

  def formField(self):
    form_value=self.formValue()
    return pyweblib.forms.Textarea(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,
      None,
      default=form_value,
      rows=max(self.minInputRows,min(self.maxInputRows,form_value.count('\n'))),
      cols=max([len(desc) for desc,_ in self.flag_desc_table])+1
    )

  def displayValue(self,valueindex=0,commandbutton=0):
    attrValue_int = int(self.attrValue)
    return """%s<br>
    <table summary="Flags">
    <tr><th>Property flag</th><th>Value</th><th>Status</th></tr>
    %s
    </table>
    """ % (
      Integer.displayValue(self,valueindex,commandbutton),
      '\n'.join([
        '<tr><td>%s</td><td>%s</td><td>%s</td></tr>' % (
          desc,
          hex(flag_value),
          {0:'-',1:'on'}[int((attrValue_int & flag_value)>0)]
        )
        for desc,flag_value in self.flag_desc_table
      ])
    )


class GSER(DirectoryString):
  oid = 'GSER-oid'
  desc = 'GSER syntax (see RFC 3641)'


class UUID(IA5String):
  oid = '1.3.6.1.1.16.1'
  desc = 'UUID'
  reObj = re.compile('^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')

  def sanitizeInput(self,attrValue):
    try:
      return str(uuid.UUID(attrValue.replace(':','')))
    except ValueError:
      return attrValue


class DNSDomain(IA5String):
  oid = 'DNSDomain-oid'
  desc = 'DNS domain name (see RFC 1035)'
  reObj = re.compile('^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*$')
  maxLen = min(255,IA5String.maxLen) # (see https://tools.ietf.org/html/rfc2181#section-11)
  simpleSanitizers = (
    str.lower,
    str.strip,
  )

  def sanitizeInput(self,attrValue):
    attrValue = IA5String.sanitizeInput(self,attrValue)
    return '.'.join([
      dc.encode('idna')
      for dc in attrValue.decode(self._form.accept_charset).split(u'.')
    ])

  def formValue(self):
    try:
      result = u'.'.join([
        dc.decode('idna')
        for dc in (self.attrValue or '').split('.')
      ])
    except UnicodeDecodeError:
      result = u'!!!snipped because of UnicodeDecodeError!!!'
    return result

  def displayValue(self,valueindex=0,commandbutton=0):
    if self.attrValue.decode('ascii')!=self.attrValue.decode('idna'):
      return '%s (%s)' % (
        IA5String.displayValue(self,valueindex,commandbutton),
        self._form.utf2display(self.formValue())
      )
    else:
      return IA5String.displayValue(self,valueindex,commandbutton)


class RFC822Address(IA5String,DNSDomain):
  oid = 'RFC822Address-oid'
  desc = 'RFC 822 mail address'
  reObj = re.compile(mail_pattern)
  html_tmpl = '<a href="mailto:{av}">{av}</a>'

  def __init__(self,sid,form,ls,dn,schema,attrType,attrValue,entry=None):
    IA5String.__init__(self,sid,form,ls,dn,schema,attrType,attrValue)

  def formValue(self):
    if not self.attrValue:
      return IA5String.formValue(self)
    try:
      localpart,domainpart = self.attrValue.rsplit('@')
    except ValueError:
      return IA5String.formValue(self)
    else:
      dns_domain = DNSDomain(self._sid,self._form,self._ls,self._dn,self._schema,None,domainpart)
      return '@'.join((
        localpart.decode(self._ls.charset),
        dns_domain.formValue()
      ))

  def sanitizeInput(self,attrValue):
    try:
      localpart,domainpart = attrValue.rsplit('@')
    except ValueError:
      return attrValue
    else:
      return '@'.join((
        localpart,
        DNSDomain.sanitizeInput(self,domainpart)
      ))


class DomainComponent(DNSDomain):
  oid = 'DomainComponent-oid'
  desc = 'DNS domain name component'
  reObj = re.compile('^[a-zA-Z0-9_-]+$')
  maxLen = min(63,DNSDomain.maxLen) # (see https://tools.ietf.org/html/rfc2181#section-11)


class YesNoIntegerFlag(SelectList):
  oid = 'YesNoIntegerFlag-oid'
  desc = '0 means no, 1 means yes'
  attr_value_dict = {
    u'0':u'no',
    u'1':u'yes',
  }


class OnOffFlag(SelectList):
  oid = 'OnOffFlag-oid'
  desc = 'Only values "on" or "off" are allowed'
  attr_value_dict = {
    u'on':u'on',
    u'off':u'off',
  }


class JSONValue(PreformattedMultilineText):
  oid = 'JSONValue-oid'
  desc = 'JSON data'
  lineSep = '\n'
  mimeType = 'application/json'

  def _validate(self,attrValue):
    try:
       json.loads(attrValue)
    except ValueError:
      return False
    else:
      return True

  def _split_lines(self,val):
    try:
      obj = json.loads(val)
    except ValueError:
      return PreformattedMultilineText._split_lines(self,val)
    return PreformattedMultilineText._split_lines(
        self,
        self._ls.uc_decode(
            json.dumps(obj,indent=4,separators=(',', ': '))
        )[0]
    )


class XmlValue(PreformattedMultilineText):
  oid = 'XmlValue-oid'
  desc = 'XML data'
  lineSep = '\n'
  mimeType = 'text/xml'

  def _validate(self,attrValue):
    try:
      xml.etree.ElementTree.XML(attrValue)
    except XMLParseError:
      return False
    else:
      return True


try:
  # Try to import optional module pisces
  from pisces import asn1

except ImportError:
  # Fall-back class is Binary
  ASN1Object = Binary

else:

  class ASN1Object(Binary):
    oid = 'ASN1Object-oid'
    desc = 'BER encoded ASN.1 data'

    def displayValue(self,valueindex=0,commandbutton=0):
      asn1obj = asn1.parse(self.attrValue)
      return ''.join((
        '<code>',
        self._form.utf2display(
          str(asn1obj).decode('utf-8').replace('{','\n{').replace('}','}\n')
        ).replace('  ','&nbsp;&nbsp;').replace('\n','<br>'),
        '</code>'
      ))

  class DumpASN1CfgOID(OID):
    oid = 'DumpASN1Cfg-oid'
    desc = "OID registered in Peter Gutmann's dumpasn1.cfg"

    def displayValue(self,valueindex=0,commandbutton=0):
      attrValue = self.attrValue.encode('ascii')
      try:
        pisces_oid = asn1.OID(tuple(map(int,attrValue.split('.'))))
        desc = web2ldap.mspki.asn1helper.GetOIDDescription(
          pisces_oid,
          web2ldap.mspki.asn1helper.oids,
          includeoid=1
        )
      except ValueError:
        return self._form.utf2display(self.attrValue)
      else:
        return desc


class AlgorithmOID(OID):
  """
  This base-class class is used for OIDs of cryptographic algorithms
  """
  oid = 'AlgorithmOID-oid'


class HashAlgorithmOID(SelectList,AlgorithmOID):
  oid = 'HashAlgorithmOID-oid'
  desc = 'values from https://www.iana.org/assignments/hash-function-text-names/'
  attr_value_dict = {
    u'1.2.840.113549.2.2':u'md2',         # [RFC3279]
    u'1.2.840.113549.2.5':u'md5',         # [RFC3279]
    u'1.3.14.3.2.26':u'sha-1',            # [RFC3279]
    u'2.16.840.1.101.3.4.2.4':u'sha-224', # [RFC4055]
    u'2.16.840.1.101.3.4.2.1':u'sha-256', # [RFC4055]
    u'2.16.840.1.101.3.4.2.2':u'sha-384', # [RFC4055]
    u'2.16.840.1.101.3.4.2.3':u'sha-512', # [RFC4055]
  }


class HMACAlgorithmOID(SelectList,AlgorithmOID):
  oid = 'HMACAlgorithmOID-oid'
  desc = 'values from RFC 2898'
  attr_value_dict = {
    # from RFC 2898
    u'1.2.840.113549.2.7':u'hmacWithSHA1',
    u'1.2.840.113549.2.8':u'hmacWithSHA224',
    u'1.2.840.113549.2.9':u'hmacWithSHA256',
    u'1.2.840.113549.2.10':u'hmacWithSHA384',
    u'1.2.840.113549.2.11':u'hmacWithSHA512',
  }


class ComposedAttribute(LDAPSyntax):
  """
  This mix-in plugin class composes attribute values from other attribute values.

  One can define an ordered sequence of string templates in class
  attribute ComposedDirectoryString.compose_templates.
  See examples in module web2ldap.app.plugins.inetorgperson.

  Obviously this only works for single value attributes.
  """
  oid = 'ComposedDirectoryString-oid'
  compose_templates = None

  class single_value_dict(dict):

    def __init__(self,entry=None):
      dict.__init__(self)
      entry = entry or {}
      for k,v in entry.items():
        self.__setitem__(k,v)

    def __setitem__(self,k,v):
      if v and v[0]:
        dict.__setitem__(self,k,v[0])

  def formValue(self):
    # Return a dummy value that attribute seen when calling .transmute()
    return u''

  def transmute(self,attrValues):
    e = self.single_value_dict(self._entry)
    for t in self.compose_templates:
      try:
        attr_values = [t.format(**e)]
      except KeyError:
        continue
      else:
        break
    else:
      attr_values = attrValues
    return attr_values

  def formField(self):
    input_field = pyweblib.forms.HiddenInput(
      self.attrType,
      ': '.join([self.attrType,self.desc]),
      self.maxLen,self.maxValues,None,
      default=self.formValue()
    )
    input_field.charset = self._form.accept_charset
    return input_field


class LDAPv3ResultCode(SelectList):
  oid = 'LDAPResultCode-oid'
  desc = 'LDAPv3 declaration of resultCode in (see RFC 4511)'
  attr_value_dict = {
    u'0':u'success',
    u'1':u'operationsError',
    u'2':u'protocolError',
    u'3':u'timeLimitExceeded',
    u'4':u'sizeLimitExceeded',
    u'5':u'compareFalse',
    u'6':u'compareTrue',
    u'7':u'authMethodNotSupported',
    u'8':u'strongerAuthRequired',
    u'9':u'reserved',
    u'10':u'referral',
    u'11':u'adminLimitExceeded',
    u'12':u'unavailableCriticalExtension',
    u'13':u'confidentialityRequired',
    u'14':u'saslBindInProgress',
    u'16':u'noSuchAttribute',
    u'17':u'undefinedAttributeType',
    u'18':u'inappropriateMatching',
    u'19':u'constraintViolation',
    u'20':u'attributeOrValueExists',
    u'21':u'invalidAttributeSyntax',
    u'32':u'noSuchObject',
    u'33':u'aliasProblem',
    u'34':u'invalidDNSyntax',
    u'35':u'reserved for undefined isLeaf',
    u'36':u'aliasDereferencingProblem',
    u'48':u'inappropriateAuthentication',
    u'49':u'invalidCredentials',
    u'50':u'insufficientAccessRights',
    u'51':u'busy',
    u'52':u'unavailable',
    u'53':u'unwillingToPerform',
    u'54':u'loopDetect',
    u'64':u'namingViolation',
    u'65':u'objectClassViolation',
    u'66':u'notAllowedOnNonLeaf',
    u'67':u'notAllowedOnRDN',
    u'68':u'entryAlreadyExists',
    u'69':u'objectClassModsProhibited',
    u'70':u'reserved for CLDAP',
    u'71':u'affectsMultipleDSAs',
    u'80':u'other',
  }


# Set up the central syntax registry instance
syntax_registry = SyntaxRegistry()
# Register all syntax classes in this module
for symbol_name in dir():
  syntax_registry.registerSyntaxClass(eval(symbol_name))
