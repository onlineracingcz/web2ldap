# -*- coding: utf-8 -*-
"""
web2ldap.app.read: Read single entry and output as HTML or vCard

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import pyweblib.forms

import ldap0.schema
from ldap0.cidict import cidict

import web2ldap.ldaputil.schema
import web2ldap.app.core,web2ldap.app.cnf,web2ldap.app.gui,web2ldap.app.read,web2ldap.app.schema,web2ldap.app.viewer
from web2ldap.msbase import union,GrabKeys
from web2ldap.app.session import session_store
from web2ldap.ldaputil.schema import SchemaElementOIDSet


class vCardEntry(web2ldap.ldaputil.schema.Entry):

  def __init__(self,schema,entry,ldap_charset='utf-8',out_charset='utf-8'):
    web2ldap.ldaputil.schema.Entry.__init__(self,schema,None,entry)
    self._ldap_charset = ldap_charset
    self._out_charset = out_charset

  def __getitem__(self,nameoroid):
    if web2ldap.app.schema.no_humanreadable_attr(self._s,nameoroid):
      return ''
    else:
      try:
        values = ldap0.schema.models.Entry.__getitem__(self,nameoroid)
      except KeyError:
        return ''
      else:
        return unicode(values[0],self._ldap_charset).encode(self._out_charset)


def get_vcard_template(ls,form,object_classes):
  template_dict = cidict(
    web2ldap.app.cnf.GetParam(ls,'vcard_template',{})
  )
  current_oc_set = set([ s.lower() for s in object_classes ])
  template_oc = list(current_oc_set.intersection(template_dict.data.keys()))
  if not template_oc:
    return None
  else:
    return web2ldap.app.gui.GetVariantFilename(template_dict[template_oc[0]],form.accept_language)


def generate_vcard(template_str,vcard_entry):
  template_lines_new = []
  for l in template_str.split('\n'):
    attr_types = GrabKeys(l).keys
    if attr_types:
      for attr_type in attr_types:
        if vcard_entry.has_key(attr_type):
          template_lines_new.append(l.strip())
          break
    else:
      template_lines_new.append(l.strip())
  return '\r\n'.join(template_lines_new) % vcard_entry

class DisplayEntry(web2ldap.ldaputil.schema.Entry):

  def __init__(self,sid,form,ls,dn,schema,entry,sep_attr,commandbutton):
    assert type(dn)==type(u'')
    web2ldap.ldaputil.schema.Entry.__init__(self,schema,dn.encode(ls.charset),entry)
    self.sid = sid
    self.form = form
    self.ls = ls
    self.dn = dn
    self.entry = web2ldap.ldaputil.schema.Entry(schema,dn.encode(ls.charset),entry)
    self.structuralObjectClass = self.entry.get_structural_oc()
    self.invalid_attrs = set()
    self.sep_attr = sep_attr
    self.commandbutton = commandbutton

  def __getitem__(self,nameoroid):
    try:
      values = web2ldap.ldaputil.schema.Entry.__getitem__(self,nameoroid)
    except KeyError:
      return ''
    result = []
    syntax_se = web2ldap.app.schema.syntaxes.syntax_registry.syntaxClass(self._s,nameoroid,self.structuralObjectClass)
    for i in range(len(values)):
      attr_instance = syntax_se(self.sid,self.form,self.ls,self.dn,self._s,nameoroid,values[i],self.entry)
      try:
        attr_value_html = attr_instance.displayValue(valueindex=i,commandbutton=self.commandbutton)
      except UnicodeError:
        # Fall back to hex-dump output
        attr_instance = web2ldap.app.schema.syntaxes.OctetString(self.sid,self.form,self.ls,self.dn,self._s,nameoroid,values[i],self.entry)
        attr_value_html = attr_instance.displayValue(valueindex=i,commandbutton=1)
      try:
        attr_instance.validate(values[i])
      except web2ldap.app.schema.syntaxes.LDAPSyntaxValueError:
        attr_value_html = '<s>%s</s>' % (attr_value_html)
        self.invalid_attrs.add(nameoroid)
      result.append(attr_value_html)
    if self.sep_attr!=None:
      value_sep = getattr(attr_instance,self.sep_attr)
      return value_sep.join(result)
    else:
      return result

  def get_html_templates(self,cnf_key):
    read_template_dict = cidict(web2ldap.app.cnf.GetParam(self.ls,cnf_key,{}))
    # This gets all object classes no matter what
    all_object_class_oid_set = self.object_class_oid_set()
    # Initialize the set with only the STRUCTURAL object class of the entry
    object_class_oid_set = SchemaElementOIDSet(self._s,ldap0.schema.models.ObjectClass,[])
    structural_oc = self.get_structural_oc()
    if structural_oc:
      object_class_oid_set.add(structural_oc)
    # Now add the other AUXILIARY and ABSTRACT object classes
    for oc in all_object_class_oid_set:
      oc_obj = self._s.get_obj(ldap0.schema.models.ObjectClass,oc)
      if oc_obj==None or oc_obj.kind!=0:
        object_class_oid_set.add(oc)
    template_oc = object_class_oid_set.intersection(read_template_dict.data.keys())
    return template_oc.names(),read_template_dict # get_html_templates()


  def template_output(self,outf,cnf_key,display_duplicate_attrs=True):
    # Determine relevant HTML templates
    template_oc,read_template_dict = self.get_html_templates(cnf_key)
    # Sort the object classes by object class category
    structural_oc,abstract_oc,auxiliary_oc = web2ldap.app.schema.object_class_categories(self._s,template_oc)
    template_oc = structural_oc+auxiliary_oc+abstract_oc
    # Templates defined => display the entry with the help of the template
    used_templates = []
    displayed_attrs = set()
    for oc in template_oc:
      try:
        read_template_filename = read_template_dict[oc]
      except KeyError:
        outf.write('<p class="ErrorMessage">Template file for object class <var>%s</var> not found.</p>' % repr(oc))
      else:
        read_template_filename = web2ldap.app.gui.GetVariantFilename(read_template_filename,self.form.accept_language)
        if not read_template_filename in used_templates:
          used_templates.append(read_template_filename)
          if read_template_filename:
            try:
              template_file = open(read_template_filename,'rb')
              template_str = template_file.read()
              template_file.close()
            except IOError:
              outf.write('<p class="ErrorMessage">I/O error during reading template file for object class <var>%s</var>.</p>' % repr(oc))
            else:
              try:
                template_attr_oid_set = set([
                  self._s.getoid(ldap0.schema.models.AttributeType,attr_type_name)
                  for attr_type_name in GrabKeys(template_str)()
                ])
              except TypeError:
                outf.write('<p class="ErrorMessage">Type error during reading template file for object class <var>%s</var>.</p>' % repr(oc))
              else:
                if display_duplicate_attrs or not displayed_attrs.intersection(template_attr_oid_set):
                  outf.write(template_str % self)
                  displayed_attrs.update(template_attr_oid_set)
          else:
            outf.write('<p class="ErrorMessage">Template file for object class <var>%s</var> not found.</p>' % repr(oc))
    return displayed_attrs # template_output()

def getOperationAttrsTemplate(ls,accept_language):
  template_pathname = web2ldap.app.cnf.GetParam(ls,'read_operationalattrstemplate',None)
  if not template_pathname:
    return ''
  template_filename = web2ldap.app.gui.GetVariantFilename(
    template_pathname,accept_language
  )
  return open(template_filename,'r').read()


def PrintAttrList(sid,outf,ls,form,dn,sub_schema,entry,attrs,Comment):
  """
  Send a table of attributes to outf
  """
  # Determine which attributes are shown
  show_attrs = [
    a
    for a in attrs
    if entry.has_key(a)
  ]
  if not show_attrs:
    # There's nothing to display => exit
    return
  show_attrs.sort(key=str.lower)
  # Determine which attributes are shown expanded or collapsed
  read_expandattr_set = set([
    at.strip().lower()
    for at in form.getInputValue('read_expandattr',[u''])[0].split(',')
  ])
  if u'*' in read_expandattr_set:
    read_tablemaxcount_dict = {}
  else:
    read_tablemaxcount_dict = ldap0.cidict.cidict(web2ldap.app.cnf.GetParam(ls,'read_tablemaxcount',{}))
    for at in read_expandattr_set:
      try:
        del read_tablemaxcount_dict[at]
      except KeyError:
        pass
  outf.write('<h2>%s</h2>\n<table class="ReadAttrTable">\n' % (Comment))
  # Set separation of attribute values inactive
  entry.sep = None
  for attr_type_name in show_attrs:
    attr_type_anchor_id = 'readattr_%s' % form.utf2display(unicode(attr_type_name))
    attr_type_str = web2ldap.app.gui.SchemaElementName(sid,form,dn,sub_schema,attr_type_name,ldap0.schema.models.AttributeType,name_template=r'<var>%s</var>')
    attr_value_disp_list = entry[attr_type_name] or ['<strong>&lt;Empty attribute value list!&gt;</strong>']
    attr_value_count = len(attr_value_disp_list)
    dt_list = [
      '<span id="%s">%s</span>\n' % (attr_type_anchor_id,attr_type_str),
    ]
    read_tablemaxcount = min(read_tablemaxcount_dict.get(attr_type_name,attr_value_count),attr_value_count)
    if attr_value_count>1:
      if attr_value_count>read_tablemaxcount:
        dt_list.append(form.applAnchor(
          'read',
          '(%d of %d values)' % (read_tablemaxcount,attr_value_count),
          sid,
          [
            ('dn',dn),
            ('read_expandattr',','.join(set(list(read_expandattr_set)+[attr_type_name]))),
          ],
          anchor_id=unicode(attr_type_anchor_id)
        ))
      else:
        dt_list.append('(%d values)' % (attr_value_count))
    if web2ldap.app.schema.no_humanreadable_attr(sub_schema,attr_type_name):
      if not web2ldap.app.schema.no_userapp_attr(sub_schema,attr_type_name):
        dt_list.append(form.applAnchor(
          'delete','Delete',sid,
          [('dn',dn),('delete_attr',attr_type_name)]
        ))
      dt_list.append(form.applAnchor(
        'read','Save to disk',sid,
        [
          ('dn',dn),
          ('read_attr',attr_type_name),
          ('read_attrmode','load'),
          ('read_attrmimetype','application/octet-stream'),
          ('read_attrindex','0'),
        ],
      ))
    dt_str = '<br>'.join(dt_list)
    outf.write('<tr class="ReadAttrTableRow"><td class="ReadAttrType" rowspan="%d">\n%s\n</td>\n<td class="ReadAttrValue">%s</td></tr>\n' % (
      read_tablemaxcount,
      dt_str,
      attr_value_disp_list[0]
    ))
    if read_tablemaxcount>=2:
      for i in range(1,read_tablemaxcount):
        outf.write('<tr class="ReadAttrTableRow">\n<td class="ReadAttrValue">%s</td></tr>\n' % (
          attr_value_disp_list[i]
        ))
  outf.write('</table>\n')
  return # PrintAttrList()


def w2l_Read(
  sid,outf,command,form,ls,dn,
  wanted_attrs,
  read_attrmode = None,
  read_attrmimetype = None,
):

  sub_schema = ls.retrieveSubSchema(
    dn,
    web2ldap.app.cnf.GetParam(ls,'_schema',None),
    web2ldap.app.cnf.GetParam(ls,'supplement_schema',None),
    web2ldap.app.cnf.GetParam(ls,'schema_strictcheck',True),
  )

  read_output = form.getInputValue('read_output',[u'template'])[0]
  filterstr = form.getInputValue('filterstr',[u'(objectClass=*)'])[0]

  read_nocache = int(form.getInputValue('read_nocache',['0'])[0])

  # Specific attributes requested with form parameter read_attr?
  wanted_attrs = [
    a.strip().encode('ascii')
    for a in form.getInputValue('read_attr',wanted_attrs)
  ]
  wanted_attr_set = web2ldap.ldaputil.schema.SchemaElementOIDSet(sub_schema,ldap0.schema.models.AttributeType,wanted_attrs)
  wanted_attrs = wanted_attr_set.names()

  # Specific attributes requested with form parameter search_attrs?
  search_attrs = form.getInputValue('search_attrs',[''])[0]
  if search_attrs:
    wanted_attrs.extend([
      a.strip().encode('ascii') for a in search_attrs.split(',')
    ])

  # Determine how to get all attributes including the operational attributes

  operational_attrs_template = getOperationAttrsTemplate(
    ls,form.accept_language
  )

  # Read the entry's data
  search_result = ls.readEntry(
    dn,
    wanted_attrs or {0:None,1:['*','+']}[ls.supportsAllOpAttr],
    search_filter=filterstr,
    no_cache=read_nocache
  )

  if not search_result:
    raise web2ldap.app.core.ErrorExit(u'Empty search result.')

  dn = search_result[0][0].decode(ls.charset)
  entry = web2ldap.ldaputil.schema.Entry(sub_schema,dn,search_result[0][1])

  requested_attrs = [
    at
    for at in union(
      GrabKeys(operational_attrs_template)(),
      web2ldap.app.cnf.GetParam(ls,'requested_attrs',[]),
    )
    if not at in entry and sub_schema.get_obj(ldap0.schema.models.AttributeType,at)!=None
  ]
  if not wanted_attrs and requested_attrs:
    try:
      search_result = ls.readEntry(dn,requested_attrs,search_filter=filterstr,no_cache=read_nocache)
    except (
        ldap0.NO_SUCH_ATTRIBUTE,
        ldap0.INSUFFICIENT_ACCESS,
    ):
      # Catch and ignore complaints of server about not knowing attribute
      pass
    else:
      if search_result:
        entry.update(search_result[0][1])

  display_entry = DisplayEntry(sid,form,ls,dn,sub_schema,entry,'readSep',1)

  # Save session into database mainly for storing LDAPSession cache
  session_store.storeSession(sid,ls)

  if len(wanted_attrs)==1 and \
     not wanted_attrs[0] in ('*','+'):

    # Display a single binary attribute either with a registered
    # viewer or just by sending the data blob with appropriate MIME-type

    attr_type = wanted_attrs[0]

    if not entry.has_key(attr_type):

      if entry.has_key(attr_type+';binary'):
        attr_type = attr_type+';binary'
      else:
        raise web2ldap.app.core.ErrorExit(
          u'Attribute <em>%s</em> not in entry.' % (form.utf2display(attr_type.decode('ascii')))
        )

    # Send a single binary attribute with appropriate MIME-type
    read_attrindex = int(form.getInputValue('read_attrindex',['0'])[0])
    # Determine if user wants to view or download the binary attribute value
    read_attrmode = form.getInputValue('read_attrmode',[read_attrmode or 'view'])[0]
    syntax_se = web2ldap.app.schema.syntaxes.syntax_registry.syntaxClass(sub_schema,attr_type,entry.get_structural_oc())

    if (read_attrmode=='view') and \
       hasattr(syntax_se,'oid') and \
       web2ldap.app.viewer.viewer_func.has_key(syntax_se.oid):
      # Nice displaying of binary attribute with viewer class
      web2ldap.app.gui.TopSection(
        sid,outf,command,form,ls,dn,'',
        web2ldap.app.gui.MainMenu(sid,form,ls,dn),
        context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(sid,form,ls,dn)
      )
      web2ldap.app.viewer.viewer_func[syntax_se.oid](
        sid,outf,command,form,dn,attr_type,entry,read_attrindex
      )
      web2ldap.app.gui.Footer(outf,form)
    else:
      # We have to create an instance to be able to call its methods
      attr_instance = syntax_se(sid,form,ls,dn,sub_schema,attr_type,None,entry)
      # Determine (hopefully) appropriate MIME-type
      read_attrmimetype = form.getInputValue('read_attrmimetype',[attr_instance.getMimeType()])[0]
      # Determine (hopefully) appropriate file extension
      read_filename = form.getInputValue(
        'read_filename',
        ['web2ldap-export.%s' % (attr_instance.fileExt)]
      )[0]
      # Output send the binary attribute value to the browser
      web2ldap.app.viewer.DisplayBinaryAttribute(
        sid,outf,form,dn,attr_type,entry,
        index=read_attrindex,
        mimetype=read_attrmimetype,
        attachment_filename=read_filename
      )
    return

  if read_output in (u'table',u'template'):

    # Display the whole entry

    web2ldap.app.gui.TopSection(
      sid,outf,command,form,ls,dn,'',
      web2ldap.app.gui.MainMenu(sid,form,ls,dn),
      context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(
        sid,form,ls,dn,
        vcard_link=not get_vcard_template(ls,form,entry.get('objectClass',[])) is None,
        dds_link='dynamicObject' in entry.get('objectClass',[]),
        entry_uuid=entry.get('entryUUID',[None])[0]
      )
    )

    export_field = web2ldap.app.form.ExportFormatSelect('search_output')
    export_field.charset = form.accept_charset

    # List of already displayed attributes

    outf.write('%s\n' % (
      form.formHTML(
        'search','Export',sid,'GET',
        [
          ('dn',dn),
          ('scope',unicode(0)),
          ('filterstr',u'(objectClass=*)'),
          ('search_resnumber',u'0'),
          ('search_attrs',u','.join(map(unicode,wanted_attrs))),
        ],
        extrastr = export_field.inputHTML()+'Incl. op. attrs.:'+web2ldap.app.form.InclOpAttrsCheckbox('search_opattrs',u'Request operational attributes',default="yes",checked=0).inputHTML(),
        target='web2ldapexport',
      ),
    ))

    if read_output==u'template':

      ############################################################
      # Template display
      ############################################################

      displayed_attrs = display_entry.template_output(outf,'read_template')

    elif read_output==u'table':

      displayed_attrs = {}

    # Display the DN if no templates were used
    if not displayed_attrs:
      if not dn:
        outf.write('<h1>Root DSE</h1>')
      else:
        h1_display_name = entry.get('displayName',entry.get('cn',['']))[0].decode(ls.charset) or web2ldap.ldaputil.base.SplitRDN(dn)[0]
        outf.write(
          '<h1>{0}</h1>\n<p class="EntryDN">{1}</p>\n'.format(
            form.utf2display(h1_display_name),
            display_entry['entryDN'],
          )
        )


    ##############################################################
    # Raw display
    ##############################################################

    required_attrs_dict,allowed_attrs_dict = entry.attribute_types(raise_keyerror=0)

    # Sort the attributes into different lists according to schema their information
    required_attrs = []
    allowed_attrs = []
    collective_attrs = []
    nomatching_attrs = []
    for a in entry.keys():
      at_se = sub_schema.get_obj(ldap0.schema.models.AttributeType,a,None)
      if at_se is None:
        nomatching_attrs.append(a)
      else:
        at_oid = at_se.oid
        if at_oid in displayed_attrs:
          continue
        if required_attrs_dict.has_key(at_oid):
          required_attrs.append(a)
        elif allowed_attrs_dict.has_key(at_oid):
          allowed_attrs.append(a)
        else:
          if at_se.collective:
            collective_attrs.append(a)
          else:
            nomatching_attrs.append(a)

    display_entry.sep_attr = None
    PrintAttrList(sid,outf,ls,form,dn,sub_schema,display_entry,required_attrs,'Required Attributes')
    PrintAttrList(sid,outf,ls,form,dn,sub_schema,display_entry,allowed_attrs,'Allowed Attributes')
    PrintAttrList(sid,outf,ls,form,dn,sub_schema,display_entry,collective_attrs,'Collective Attributes')
    PrintAttrList(sid,outf,ls,form,dn,sub_schema,display_entry,nomatching_attrs,'Various Attributes')
    display_entry.sep_attr = 'readSep'

    # Display operational attributes with template as footer
    if read_output==u'template':
      display_entry.sep = '<br>'
      outf.write(operational_attrs_template % display_entry)

    outf.write("""%s\n%s\n%s<p>\n%s\n
        <input type=submit value="Request"> attributes:
        <input name="search_attrs" value="%s" size="40" maxlength="255">
    </p></form>
    """ % (
      form.beginFormHTML('read',sid,'GET'),
      form.hiddenFieldHTML('read_nocache',u'1',u''),
      form.hiddenFieldHTML('dn',dn,u''),
      form.hiddenFieldHTML('read_output',read_output,u''),
      ','.join([
        form.utf2display(unicode(a,ls.charset),sp_entity='  ')
        for a in wanted_attrs or {0:['*'],1:['*','+']}[ls.supportsAllOpAttr]
      ])
    ))

    web2ldap.app.gui.Footer(outf,form)

  elif read_output=='vcard':

    ##############################################################
    # vCard export
    ##############################################################

    vcard_template_filename = get_vcard_template(ls,form,entry.get('objectClass',[]))

    if vcard_template_filename:

      # Templates defined => display the entry with the help of a template

      try:
          template_str = open(vcard_template_filename,'r').read()
      except IOError:
        raise web2ldap.app.core.ErrorExit(u'I/O error during reading vCard template file!')
      else:
        vcard_filename = u'web2ldap-vcard'
        for vcard_name_attr in ('displayName','cn','o'):
          try:
            vcard_filename = entry[vcard_name_attr][0].decode(ls.charset)
          except (KeyError,IndexError):
            pass
          else:
            break
        display_entry = vCardEntry(sub_schema,entry)
        display_entry['dn'] = [dn.encode(ls.charset)]
        web2ldap.app.gui.Header(
          outf,
          form,
          content_type='text/x-vcard',
          more_headers=[
            (
              'Content-Disposition',
              'inline; filename=%s.vcf' % (vcard_filename.encode(form.accept_charset))
            ),
          ],
        )
        outf.write(generate_vcard(template_str,display_entry))

    else:
      raise web2ldap.app.core.ErrorExit(u'No vCard template file found for object class(es) of this entry.')
