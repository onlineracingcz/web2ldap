# -*- coding: utf-8 -*-
"""
web2ldap.app.schema.viewer -  Display LDAPv3 schema

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import types,ldap0,web2ldap.app.gui

from ldap0.schema.subentry import \
  SCHEMA_ATTRS,SCHEMA_CLASS_MAPPING,SCHEMA_ATTR_MAPPING
from ldap0.schema.models import \
  LDAPSyntax,AttributeType,ObjectClass,MatchingRule,MatchingRuleUse,DITContentRule,DITStructureRule,NameForm

from pyweblib.forms import escapeHTML

OBSOLETE_TEMPL = {
  0:'%s',
  1:'<s>%s</s>',
}

def LinkText(se,charset):
  names = map(escapeHTML,se.__dict__.get('names',(())))
  obsolete = se.__dict__.get('obsolete',0)
  if len(names)==1:
    link_text = names[0]
  elif len(names)>1:
    link_text = '%s (alias %s)' % (names[0],', '.join(names[1:]))
  elif isinstance(se,LDAPSyntax) and not (se.desc is None):
    link_text = unicode(escapeHTML(se.desc),'utf-8').encode(charset)
  else:
    link_text = escapeHTML(se.oid)
  return OBSOLETE_TEMPL[obsolete] % link_text


def displayNameOrOID(sid,form,dn,schema,se_nameoroid,se_class):
  se = schema.get_obj(se_class,se_nameoroid,default=None)
  if se:
    link_text = LinkText(se,form.accept_charset)
    return form.applAnchor(
      'oid',link_text,sid,[
        ('dn',dn),('oid',se.oid),
        ('oid_class',SCHEMA_ATTR_MAPPING[se_class])
      ]
    )
  else:
    return se_nameoroid


def displayNameOrOIDList(sid,form,dn,schema,se_names,se_class):

  link_texts = []
  for se_nameoroid in se_names:
    se = schema.get_obj(se_class,se_nameoroid,default=None)
    if se:
      link_text = LinkText(se,form.accept_charset)
      try:
        schema_id = se.oid
      except AttributeError:
        schema_id = se.ruleid
      anchor = form.applAnchor(
        'oid',link_text,sid,[
          ('dn',dn),
          ('oid',schema_id),
          ('oid_class',SCHEMA_ATTR_MAPPING[se_class])
        ]
      )
      link_texts.append((link_text,anchor))
    else:
      link_texts.append((se_nameoroid,se_nameoroid))
  link_texts.sort(key=lambda x:x[0].lower())
  return [ i[1] for i in link_texts ]


def HTMLSchemaTree(sid,outf,form,dn,schema,se_class,se_tree,se_oid,level):
  """HTML output for browser"""
  outf_lines = ['<dl>']
  se_obj = schema.get_obj(se_class,se_oid)
  if se_obj!=None:
    display_id = (se_obj.names or (se_oid,))[0]
    outf_lines.append("""
    <dt><strong>%s</strong></dt>
    """ % (displayNameOrOID(sid,form,dn,schema,display_id,se_class)))
  if se_tree[se_oid]:
    outf_lines.append('<dd>')
    for sub_se_oid in se_tree[se_oid]:
      outf_lines.extend(HTMLSchemaTree(sid,outf,form,dn,schema,se_class,se_tree,sub_se_oid,level+1))
    outf_lines.append('</dd>')
  else:
    outf_lines.append('<dd></dd>')
  outf_lines.append('</dl>')
  return outf_lines

def SchemaContextMenu(sid,form,ls,dn):
  """Build context menu with schema-related items"""
  context_menu_list = []
  subschemaSubentryDN = None
  try:
    subschemaSubentryDN = ls.l.search_subschemasubentry_s(dn.encode(ls.charset))
    subschemaSubentry = ls.retrieveSubSchema(dn,None,None,False)
  except ldap0.LDAPError:
    pass
  else:
    if subschemaSubentryDN is not None:
      form_param_list = [
        ('dn',subschemaSubentryDN.decode(ls.charset)),
        ('filterstr',u'(objectClass=subschema)'),
      ]
      for schema_attr in SCHEMA_ATTRS+['objectClass','cn']:
        form_param_list.append(('read_attr',schema_attr))
      context_menu_list.append(form.applAnchor('read','Subschema Subentry',sid,form_param_list,title=u'Directly read the subschema subentry'))
    if subschemaSubentry:
      se_class_attrs = [
        SCHEMA_ATTR_MAPPING[se_class]
        for se_class in subschemaSubentry.sed.keys()
        if subschemaSubentry.sed[se_class]
      ]
      se_class_attrs.sort(key=str.lower)
      for se_class_attr in se_class_attrs:
        context_menu_list.append(
          form.applAnchor('oid',se_class_attr,sid,[('dn',dn),('oid_class',se_class_attr)],title=u'Browse all %s' % (se_class_attr))
        )
  return context_menu_list


class DisplaySchemaElement:
  type_desc = 'Abstract Schema Element'
  detail_attrs = ()

  def __init__(self,sub_schema,se):
    self.s = sub_schema
    self.se = se
    try:
      schema_id = self.se.oid
    except AttributeError:
      schema_id = self.se.ruleid
    self.sei = sub_schema.get_inheritedobj(self.se.__class__,schema_id,[])

  def displayDetails(self,sid,outf,form,dn):
    outf_lines = []
    for text,class_attr,se_class in self.detail_attrs:
      class_attr_value = self.sei.__dict__.get(class_attr,None)
      if class_attr_value is None:
        continue
      else:
        if type(class_attr_value)==types.TupleType or \
           type(class_attr_value)==types.ListType:
          class_attr_value_list = list(class_attr_value)
          class_attr_value_list.sort(key=str.lower)
        else:
          class_attr_value_list = [class_attr_value]
        if se_class is None:
          value_output = ', '.join([
            form.utf2display(unicode(v,'utf-8'),sp_entity=' ',lf_entity='<br>') for v in class_attr_value_list
          ])
        else:
          value_output = ', '.join(displayNameOrOIDList(sid,form,dn,self.s,class_attr_value_list,se_class))
        outf_lines.append('<dt>%s</dt>\n<dd>\n%s\n</dd>\n' % (text,value_output))
    return outf_lines # displayDetails()

  def display(self,sid,outf,form,ls,dn):
    ms_ad_schema_link = ''
    if 'schemaNamingContext' in ls.rootDSE:
      try:
        result = ls.l.search_s(
          ls.rootDSE['schemaNamingContext'][0],
          ldap0.SCOPE_SUBTREE,
          '(|(&(objectClass=attributeSchema)(attributeID=%s))(&(objectClass=classSchema)(governsID=%s)))' % (self.se.oid,self.se.oid),
          attrlist=['cn']
        )
      except ldap0.LDAPError:
        pass
      else:
        if result:
          ad_schema_dn,ad_schema_entry = result[0]
          ms_ad_schema_link = '<dt>Schema Definition Entry (MS AD)</dt>\n<dd>\n%s\n</dd>\n' % (
            form.applAnchor(
              'read',ad_schema_entry['cn'][0],sid,
              [
                ('dn',ad_schema_dn),
              ],
          ))
    obsolete = self.se.__dict__.get('obsolete',0)
    web2ldap.app.gui.TopSection(
      sid,outf,'oid',form,ls,dn,
      '%s %s (%s)' % (
        self.type_desc,
        ', '.join(
          self.se.__dict__.get('names',(()))
        ),
        self.se.oid
      ),
      web2ldap.app.gui.MainMenu(sid,form,ls,dn),
      context_menu_list=SchemaContextMenu(sid,form,ls,dn)
    )
    outf.write("""
    %s
    <h1>%s <em>%s</em> (%s)</h1>
    Try to look it up:
    <a id="alvestrand_oid" href="%s/urlredirect/%s?http://www.alvestrand.no/objectid/%s.html">[Alvestrand]</a>
    <a id="oid-info_oid" href="%s/urlredirect/%s?http://www.oid-info.com/get/%s">[oid-info.com]</a>
    <dl>
    <dt>Schema element string:</dt>
    <dd><code>%s</code></dd>
    %s
    %s
    </dl>
    """ % (
      OIDInputForm(form,sid,dn,''),
      self.type_desc,
      OBSOLETE_TEMPL[obsolete] % (
        ", ".join(
          self.se.__dict__.get('names',(()))
        )
      ),
      self.se.oid,
      form.script_name,sid,self.se.oid,
      form.script_name,sid,self.se.oid,
      form.utf2display(unicode(str(self.se),'utf-8')),
      ms_ad_schema_link,
      ''.join(self.displayDetails(sid,outf,form,dn)),
    ))
    web2ldap.app.gui.Footer(outf,form)


class DisplayObjectClass(DisplaySchemaElement):
  type_desc = 'Object class'
  detail_attrs = (
    ('Description','desc',None),
    ('Derived from','sup',ObjectClass),
  )

  def __init__(self,sub_schema,se):
    DisplaySchemaElement.__init__(self,sub_schema,se)
    self.sei = sub_schema.get_inheritedobj(self.se.__class__,self.se.oid,['kind'])

  def displayDetails(self,sid,outf,form,dn):
    outf_lines = DisplaySchemaElement.displayDetails(self,sid,outf,form,dn)
    must,may = self.s.attribute_types([self.se.oid],raise_keyerror=0)
    # Display all required and allowed attributes
    outf_lines.append('<dt>Kind of object class:</dt><dd>\n%s&nbsp;</dd>\n' % (
      {0:' STRUCTURAL',1:' ABSTRACT',2:' AUXILIARY'}[self.sei.kind]
    ))
    # Display all required and allowed attributes
    outf_lines.append('<dt>All required attributes:</dt><dd>\n%s&nbsp;</dd>\n' % (
      ', '.join(displayNameOrOIDList(sid,form,dn,self.s,must.keys(),AttributeType))
    ))
    outf_lines.append('<dt>All allowed attributes:</dt><dd>\n%s&nbsp;</dd>\n' % (
      ', '.join(displayNameOrOIDList(sid,form,dn,self.s,may.keys(),AttributeType))
    ))

    # Display relationship to DIT content rule(s)

    # normally only in case of a STRUCTURAL object class)
    content_rule = self.s.get_obj(DITContentRule,self.se.oid)
    if content_rule:
      outf_lines.append('<dt>Governed by DIT content rule:</dt><dd>\n%s&nbsp;</dd>\n' % (
        displayNameOrOID(sid,form,dn,self.s,content_rule.oid,DITContentRule)
      ))
      outf_lines.append('<dt>Applicable auxiliary object classes:</dt><dd>\n%s&nbsp;</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,content_rule.aux,ObjectClass))
      ))

    # normally only in case of a AUXILIARY object class
    dcr_list = []
    structural_oc_list = []
    for _,content_rule in self.s.sed[DITContentRule].items():
      for aux_class_name in content_rule.aux:
        aux_class_oid = self.s.getoid(ObjectClass,aux_class_name)
        if aux_class_oid==self.se.oid:
          dcr_list.append(content_rule.oid)
          structural_oc_list.append(content_rule.oid)
    if dcr_list:
      outf_lines.append('<dt>Referring DIT content rules:</dt><dd>\n%s&nbsp;</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,dcr_list,DITContentRule))
      ))
    if structural_oc_list:
      outf_lines.append('<dt>Allowed with structural object classes:</dt><dd>\n%s&nbsp;</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,structural_oc_list,ObjectClass))
      ))

    # Display name forms which regulates naming for this object class
    oc_ref_list = []
    for nf_oid,name_form_se in self.s.sed[NameForm].items():
      name_form_oc = name_form_se.oc.lower()
      se_names = set([o.lower() for o in self.sei.names])
      if name_form_se.oc==self.sei.oid or name_form_oc in se_names:
        oc_ref_list.append(nf_oid)
    if oc_ref_list:
      outf_lines.append('<dt>Applicable name forms:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,oc_ref_list,NameForm))
      ))

    # Display tree of derived object classes
    outf_lines.append('<dt>Object class tree:</dt>\n')
    outf_lines.append('<dd>\n')
    try:
      oc_tree = self.s.tree(ObjectClass)
    except KeyError as e:
      outf_lines.append('<strong>Missing schema elements referenced:<pre>%s</pre></strong>\n' % form.utf2display(str(e)))
    else:
      if oc_tree.has_key(self.se.oid) and oc_tree[self.se.oid]:
        outf_lines.extend(HTMLSchemaTree(sid,outf,form,dn,self.s,ObjectClass,oc_tree,self.se.oid,0))
    outf_lines.append('&nbsp;</dd>\n')
    # Display a link for searching entries by object class
    outf_lines.append('<dt>Search entries</dt>\n<dd>\n%s\n</dd>\n' % (
      form.applAnchor(
        'searchform',
        '(objectClass=%s)' % form.utf2display(unicode((self.se.names or [self.se.oid])[0])),
        sid,
        [
          ('dn',dn),
          ('searchform_mode',u'adv'),
          ('search_attr',u'objectClass'),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
          ('search_string',unicode((self.se.names or [self.se.oid])[0])),
        ],
        title=u'Search entries by object class',
    )))
    return outf_lines # displayDetails()

class DisplayAttributeType(DisplaySchemaElement):
  type_desc = 'Attribute type'
  detail_attrs = (
    ('Description','desc',None),
    ('Syntax','syntax',LDAPSyntax),
    ('Derived from','sup',AttributeType),
    ('Equality matching rule','equality',MatchingRule),
    ('Sub-string matching rule','substr',MatchingRule),
    ('Ordering matching rule','ordering',MatchingRule),
  )

  def __init__(self,sub_schema,se):
    DisplaySchemaElement.__init__(self,sub_schema,se)
    try:
      self.sei = sub_schema.get_inheritedobj(self.se.__class__,self.se.oid,['syntax','equality','substr','ordering'])
    except KeyError:
      # If the schema element referenced by SUP is not present
      self.sei = sub_schema.get_obj(self.se.__class__,self.se.oid)

  def displayDetails(self,sid,outf,form,dn):

    outf_lines = DisplaySchemaElement.displayDetails(self,sid,outf,form,dn)

    at_oid = self.se.oid
    syntax_oid = self.sei.syntax

    outf_lines.append('<dt>Usage:</dt>\n<dd>\n%s\n</dd>\n' % (
      {
        0:'userApplications',
        1:'directoryOperation',
        2:'distributedOperation',
        3:'dSAOperation',
      }[self.se.usage]
    ))

    if syntax_oid!=None:

      ####################################
      # Display applicable matching rules
      ####################################

      mr_use_se = self.s.get_obj(MatchingRuleUse,syntax_oid)

      applies_dict = {}
      for mr_oid,mr_use_se in self.s.sed[MatchingRuleUse].items():
        applies_dict[mr_oid] = {}
        mr_use_se = self.s.get_obj(MatchingRuleUse,mr_oid)
        for a in mr_use_se.applies:
          applies_dict[mr_oid][self.s.getoid(AttributeType,a)] = None
      # Display list of attribute types for which this matching rule is applicable
      mr_applicable_for = [
        mr_oid
        for mr_oid in self.s.sed[MatchingRule].keys()
        if applies_dict.has_key(mr_oid) and applies_dict[mr_oid].has_key(at_oid)
      ]
      if mr_applicable_for:
        outf_lines.append('<dt>Applicable matching rules:</dt>\n<dd>\n%s\n</dd>\n' % (
          ', '.join(displayNameOrOIDList(sid,form,dn,self.s,mr_applicable_for,MatchingRule))
        ))

    ###################################################################
    # Display DIT content rules which reference attributes of this type
    ###################################################################
    attr_type_ref_list = []
    for oc_oid,object_class_se in self.s.sed[ObjectClass].items():
      object_class_se = self.s.get_obj(ObjectClass,oc_oid)
      for dcr_at in object_class_se.must+object_class_se.may:
        if dcr_at==at_oid or dcr_at in self.sei.names:
          attr_type_ref_list.append(oc_oid)
    if attr_type_ref_list:
      outf_lines.append('<dt>Directly referencing object classes:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,attr_type_ref_list,ObjectClass))
      ))

    ###################################################################
    # Display object classes which may contain attributes of this type
    ###################################################################
    all_object_classes = self.s.sed[ObjectClass].keys()
    attr_type_ref_list = []
    for oc_oid in all_object_classes:
      must,may = self.s.attribute_types([oc_oid],raise_keyerror=0)
      if must.has_key(at_oid) or may.has_key(at_oid):
        attr_type_ref_list.append(oc_oid)
    if attr_type_ref_list:
      outf_lines.append('<dt>Usable in these object classes:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,attr_type_ref_list,ObjectClass))
      ))

    ###################################################################
    # Display DIT content rules which reference attributes of this type
    ###################################################################
    attr_type_ref_list = []
    for dcr_oid,dit_content_rule_se in self.s.sed[DITContentRule].items():
      dit_content_rule_se = self.s.get_obj(DITContentRule,dcr_oid)
      for dcr_at in dit_content_rule_se.must+dit_content_rule_se.may+dit_content_rule_se.nots:
        if dcr_at==at_oid or dcr_at in self.sei.names:
          attr_type_ref_list.append(dcr_oid)
    if attr_type_ref_list:
      outf_lines.append('<dt>Referencing DIT content rules:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,attr_type_ref_list,DITContentRule))
      ))

    ########################################################################
    # Display name forms which uses this attribute type for naming an entry
    ########################################################################
    attr_type_ref_list = []
    for nf_oid,name_form_se in self.s.sed[NameForm].items():
      name_form_se = self.s.get_obj(NameForm,nf_oid)
      for nf_at in name_form_se.must+name_form_se.may:
        if nf_at==at_oid or nf_at in self.sei.names:
          attr_type_ref_list.append(nf_oid)
    if attr_type_ref_list:
      outf_lines.append('<dt>Referencing name forms:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,attr_type_ref_list,NameForm))
      ))

    #########################################
    # Output attribute type inheritance tree
    #########################################
    outf_lines.append('<dt>Attribute type tree:</dt>\n<dd>\n')
    # Display tree of derived attribute types
    try:
      at_tree = self.s.tree(AttributeType)
    except KeyError as e:
      outf_lines.append('<strong>Missing schema elements referenced:<pre>%s</pre></strong>\n' % form.utf2display(str(e)))
    else:
      if at_tree.has_key(at_oid) and at_tree[at_oid]:
        outf_lines.extend(HTMLSchemaTree(sid,outf,form,dn,self.s,AttributeType,at_tree,at_oid,0))
    # Display a link for searching entries by attribute presence
    outf_lines.append('</dd>\n<dt>Search entries</dt>\n<dd>\n%s\n</dd>\n' % (
      form.applAnchor(
        'searchform',
        '(%s=*)' % form.utf2display(unicode((self.se.names or [self.se.oid])[0])),
        sid,
        [
          ('dn',dn),
          ('searchform_mode',u'adv'),
          ('search_attr',unicode((self.se.names or [self.se.oid])[0])),
          ('search_option',web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS),
          ('search_string',''),
        ],
        title=u'Search entries by attribute presence',
    )))

    #########################################
    # Output registered plugin class name
    #########################################
    outf_lines.append("""
      <dt>Associated plugin class(es):</dt>
      <dd>
        <table>
          <tr><th>Structural<br>object class</th><th>Plugin class</th>""")
    for structural_oc in web2ldap.app.schema.syntaxes.syntax_registry.at2syntax[at_oid].keys() or [None]:
      syntax_class = web2ldap.app.schema.syntaxes.syntax_registry.syntaxClass(self.s,at_oid,structural_oc)
      if structural_oc:
        oc_text = displayNameOrOID(sid,form,dn,self.s,structural_oc,ObjectClass)
      else:
        oc_text = '-any-'
      outf_lines.append('<tr><td>%s</td><td>%s.%s</td></th>\n' % (
        oc_text,
        form.utf2display(unicode(syntax_class.__module__)),
        form.utf2display(unicode(syntax_class.__name__)),
      ))
    outf_lines.append('</table>\n</dd>\n')
    return outf_lines # displayDetails()


class DisplayLDAPSyntax(DisplaySchemaElement):
  type_desc = 'LDAP Syntax'
  detail_attrs = (
    ('Description','desc',None),
  )

  def displayDetails(self,sid,outf,form,dn):
    outf_lines = DisplaySchemaElement.displayDetails(self,sid,outf,form,dn)
    # Display list of attribute types which directly reference this syntax
    syntax_using_at_list = [
      at_oid
      for at_oid in self.s.sed[AttributeType].keys()
      if self.s.get_syntax(at_oid)==self.se.oid
    ]
    if syntax_using_at_list:
      outf_lines.append('<dt>Referencing attribute types:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,syntax_using_at_list,AttributeType))
      ))
    syntax_ref_mr_list = [
      mr_oid
      for mr_oid in self.s.listall(MatchingRule,[('syntax',self.se.oid)])
    ]
    if syntax_ref_mr_list:
      outf_lines.append('<dt>Referencing matching rules:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,syntax_ref_mr_list,MatchingRule))
      ))
    try:
      x_subst = self.se.x_subst
    except AttributeError:
      pass
    else:
      if x_subst:
        outf_lines.append('<dt>Substituted by:</dt>\n<dd>\n%s\n</dd>\n' % (
          displayNameOrOID(sid,form,dn,self.s,x_subst,LDAPSyntax)
        ))
    #########################################
    # Output registered plugin class name
    #########################################
    syntax_class = web2ldap.app.schema.syntaxes.syntax_registry.oid2syntax.get(self.se.oid,web2ldap.app.schema.syntaxes.LDAPSyntax)
    outf_lines.append('<dt>Associated syntax class</dt>\n<dd>\n%s\n</dd>\n' % (
      '.'.join((syntax_class.__module__,syntax_class.__name__))
    ))
    return outf_lines # displayDetails()


class DisplayMatchingRule(DisplaySchemaElement):
  type_desc = 'Matching Rule'
  detail_attrs = (
    ('Description','desc',None),
    ('LDAP syntax','syntax',LDAPSyntax),
  )

  def displayDetails(self,sid,outf,form,dn):
    outf_lines = DisplaySchemaElement.displayDetails(self,sid,outf,form,dn)
    mr_use_se = self.s.get_obj(MatchingRuleUse,self.se.oid)
    if mr_use_se:
      applies_dict = {}
      for a in mr_use_se.applies:
        applies_dict[self.s.getoid(AttributeType,a)] = None
      # Display list of attribute types for which this matching rule is applicable
      mr_applicable_for = [
        at_oid
        for at_oid in self.s.sed[AttributeType].keys()
        if applies_dict.has_key(at_oid)
      ]
      if mr_applicable_for:
        outf_lines.append('<dt>Applicable for attribute types per matching rule use:</dt>\n<dd>\n%s\n</dd>\n' % (
          ', '.join(displayNameOrOIDList(sid,form,dn,self.s,mr_applicable_for,AttributeType))
        ))
    mr_used_by = []
    for at_oid in self.s.sed[AttributeType].keys():
      try:
        at_se = self.s.get_inheritedobj(AttributeType,at_oid,['equality','substr','ordering'])
      except KeyError:
        pass
      else:
        if at_se and ( \
           (at_se.equality in self.se.names or at_se.substr in self.se.names or at_se.ordering in self.se.names) or \
           (at_se.equality==self.se.oid or at_se.substr==self.se.oid or at_se.ordering==self.se.oid) \
        ):
          mr_used_by.append(at_se.oid)
    if mr_used_by:
      outf_lines.append('<dt>Referencing attribute types:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,mr_used_by,AttributeType))
      ))
    return outf_lines # displayDetails()


class DisplayMatchingRuleUse(DisplaySchemaElement):
  type_desc = 'Matching Rule Use'
  detail_attrs = (
    ('Names','names',None),
    ('Matching Rule','oid',MatchingRule),
    ('Applies to','applies',AttributeType),
  )


class DisplayDITContentRule(DisplaySchemaElement):
  type_desc = 'DIT content rule'
  detail_attrs = (
    ('Names','names',None),
    ('Governs structural object class','oid',ObjectClass),
    ('Auxiliary classes','aux',ObjectClass),
    ('Must have','must',AttributeType),
    ('May have','may',AttributeType),
    ('Must not have','nots',AttributeType),
  )


class DisplayDITStructureRule(DisplaySchemaElement):
  type_desc = 'DIT structure rule'
  detail_attrs = (
    ('Description','desc',None),
    ('Associated name form','form',NameForm),
    ('Superior structure rules','sup',DITStructureRule),
  )

  def display(self,sid,outf,form,ls,dn):
    web2ldap.app.gui.TopSection(
      sid,outf,'oid',form,ls,dn,
      '%s %s (%s)' % (
        self.type_desc,
        ', '.join(
          self.se.__dict__.get('names',(()))
        ),
        self.se.ruleid
      ),
      web2ldap.app.gui.MainMenu(sid,form,ls,dn),
      context_menu_list=SchemaContextMenu(sid,form,ls,dn)
    )
    outf.write("""
%s
<h1>%s <em>%s</em> (%s)</h1>
<dl>
<dt>Schema element string:</dt>
<dd><code>%s</code></dd>
%s
</dl>
    """ % (
      OIDInputForm(form,sid,dn,''),
      self.type_desc,
      ", ".join(
        self.se.__dict__.get('names',(()))
      ),
      self.se.ruleid,
      form.utf2display(unicode(str(self.se),ls.charset)),
      ''.join(self.displayDetails(sid,outf,form,dn)),
    ))
    web2ldap.app.gui.Footer(outf,form)

  def displayDetails(self,sid,outf,form,dn):
    outf_lines = DisplaySchemaElement.displayDetails(self,sid,outf,form,dn)
    ########################################################################
    # Display subordinate DIT structure rule(s)
    ########################################################################
    ditsr_rules_ref_list = []
    for ditsr_id,ditsr_se in self.s.sed[DITStructureRule].items():
      if self.sei.ruleid in ditsr_se.sup:
        ditsr_rules_ref_list.append(ditsr_id)
    if ditsr_rules_ref_list:
      outf_lines.append('<dt>Subordinate DIT structure rules:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,ditsr_rules_ref_list,DITStructureRule))
      ))
    return outf_lines # displayDetails()


class DisplayNameForm(DisplaySchemaElement):
  type_desc = 'Name form'
  detail_attrs = (
    ('Description','desc',None),
    ('Structural object class this rule applies to','oc',ObjectClass),
    ('Mandantory naming attributes','must',AttributeType),
    ('Allowed naming attributes','may',AttributeType),
  )

  def displayDetails(self,sid,outf,form,dn):
    outf_lines = DisplaySchemaElement.displayDetails(self,sid,outf,form,dn)
    ########################################################################
    # Display referencing DIT structure rule(s)
    ########################################################################
    ditsr_rules_ref_list = []
    for ditsr_id,ditsr_se in self.s.sed[DITStructureRule].items():
      if ditsr_se.form==self.sei.oid or ditsr_se.form in self.sei.names:
        ditsr_rules_ref_list.append(ditsr_id)
    if ditsr_rules_ref_list:
      outf_lines.append('<dt>Referencing DIT structure rule:</dt>\n<dd>\n%s\n</dd>\n' % (
        ', '.join(displayNameOrOIDList(sid,form,dn,self.s,ditsr_rules_ref_list,DITStructureRule))
      ))
    return outf_lines # displayDetails()


SCHEMA_VIEWER_CLASS = {
  ObjectClass:DisplayObjectClass,
  AttributeType:DisplayAttributeType,
  LDAPSyntax:DisplayLDAPSyntax,
  MatchingRule:DisplayMatchingRule,
  MatchingRuleUse:DisplayMatchingRuleUse,
  DITContentRule:DisplayDITContentRule,
  DITStructureRule:DisplayDITStructureRule,
  NameForm:DisplayNameForm,
}


def OIDInputForm(form,sid,dn,oid=None):
  oid_input_field_html = web2ldap.app.form.OIDInput(
    'oid',
    u'OID or descriptive name of schema element',
    default=oid
  ).inputHTML(oid)
  oid_class_select_html = form.field['oid_class'].inputHTML('')
  return form.formHTML(
    'oid','Search',sid,'GET',
    [('dn',dn)],
    extrastr='\n'.join((oid_input_field_html,oid_class_select_html)),
  )


def DisplayAllSchemaelements(sid,outf,form,ls,dn,schema,se_classes,se_list):
  se_list = se_list or []
  se_classes = filter(None,se_classes or []) or SCHEMA_CLASS_MAPPING.values()

  web2ldap.app.gui.TopSection(
    sid,outf,'oid',form,ls,dn,'Schema elements',
    web2ldap.app.gui.MainMenu(sid,form,ls,dn),
    context_menu_list=SchemaContextMenu(sid,form,ls,dn)
  )

  if schema is None:
    raise web2ldap.app.core.ErrorExit(u'No sub schema available!')

  oid_dict = {}
  if se_list:
    for schema_class in se_classes:
      oid_dict[schema_class] = []
    for se in se_list:
      try:
        se_id = se.oid
      except AttributeError:
        se_id = se.ruleid
      try:
        oid_dict[se.__class__].append(se_id)
      except KeyError:
        oid_dict[se.__class__] = [ se_id ]
  else:
    for schema_class in se_classes:
      oid_dict[schema_class] = schema.sed[schema_class].keys()
  outf.write(OIDInputForm(form,sid,dn,''))

  if oid_dict:
    for schema_class in oid_dict.keys():
      schema_elements = oid_dict[schema_class]
      if not schema_elements:
        continue
      outf.write('<h2>%s</h2>\n<p>found %d</p>\n%s\n' % (
        SCHEMA_VIEWER_CLASS[schema_class].type_desc,
        len(schema_elements),
        ',\n '.join(displayNameOrOIDList(sid,form,dn,schema,schema_elements,schema_class)),
      ))
  else:
    outf.write("""<p>Hints:</p>
    <ul>
      <li>You can search for schema elements by OID or name.</li>
      <li>Wildcard search with * is supported.</li>
      <li>For browsing choose from context menu on the right</li>
    </ul>
    """)
  web2ldap.app.gui.Footer(outf,form)


def w2l_DisplaySchemaElement(sid,outf,command,form,ls,dn):

  def contains_oid(x,oid):
    return x.__contains__(oid)

  def startswith_oid(x,oid):
    return x.startswith(oid)

  def endswith_oid(x,oid):
    return x.endswith(oid)

  sub_schema = ls.retrieveSubSchema(
    dn,
    web2ldap.app.cnf.GetParam(ls,'_schema',None),
    web2ldap.app.cnf.GetParam(ls,'supplement_schema',None),
    web2ldap.app.cnf.GetParam(ls,'schema_strictcheck',True),
  )

  # Get input parameter from form input
  oid = form.getInputValue('oid',[None])[0]
  se_classes = [
    SCHEMA_CLASS_MAPPING[se_name.strip()]
    for se_name in form.getInputValue('oid_class',[])
    if se_name
  ]

  if not oid or oid=='*':
    # Display entry page of schema browser
    DisplayAllSchemaelements(sid,outf,form,ls,dn,sub_schema,se_classes,None)
    return

  else:

    # Sanitize oid
    oid = oid.strip()
    if oid.lower().endswith(';binary'):
      oid=oid[:-7]

    # Determine the matching method, e.g. for wildcard search
    if oid.startswith('*') and oid.endswith('*'):
      oid_mv = oid[1:-1].lower()
      cmp_method = contains_oid
    elif oid.startswith('*'):
      oid_mv = oid[1:].lower()
      cmp_method = endswith_oid
    elif oid.endswith('*'):
      oid_mv = oid[:-1].lower()
      cmp_method = startswith_oid
    else:
      cmp_method = None

    if len(se_classes)==1 and cmp_method is None:
      # Display a single schema element referenced by OID and class
      se_list = [sub_schema.get_obj(se_classes[0],oid,None)]
    else:
      # Search schema element by OID
      se_list = []
      if cmp_method is None:
        # No wildcard search => just try to look up directly via name or OID
        for schema_element_type in se_classes or SCHEMA_VIEWER_CLASS.keys():
          se = sub_schema.get_obj(schema_element_type,oid,None)
          if not se is None:
            se_list.append(se)
      else:
        # Do a wildcard search
        for schema_element_type in se_classes or SCHEMA_VIEWER_CLASS.keys():
          for se in sub_schema.sed[schema_element_type].values():
            try:
              se_id = se.oid
            except AttributeError:
              se_id = se.ruleid
            if cmp_method(se_id.lower(),oid_mv):
              # OID matched
              se_list.append(se)
            else:
              # Look whether a value of NAMEs match
              try:
                se_names = se.names
              except AttributeError:
                continue
              for se_name in se_names or []:
                if cmp_method(se_name.lower(),oid_mv):
                  se_list.append(se)
                  break


    if not se_list:
      web2ldap.app.gui.SimpleMessage(
        sid,outf,command,form,ls,dn,
        title=u'',
        message='<h1>Schema elements</h1><p class="ErrorMessage">Name or OID not found in schema!</p><p>%s</p>' % (
          OIDInputForm(form,sid,dn,oid)
        ),
        main_div_id='Message',
        main_menu_list=web2ldap.app.gui.MainMenu(sid,form,ls,dn),
        context_menu_list=SchemaContextMenu(sid,form,ls,dn)
      )
      return
    elif len(se_list)>1:
      # Display a list of schema elements to choose from
      DisplayAllSchemaelements(sid,outf,form,ls,dn,sub_schema,None,se_list)
      return
    else:
      # Directly display a single schema element
      se_obj = se_list[0]
      if not SCHEMA_VIEWER_CLASS.has_key(se_obj.__class__):
        raise web2ldap.app.core.ErrorExit(u'No viewer for this type of schema element!')
      schema_viewer = SCHEMA_VIEWER_CLASS[se_obj.__class__](sub_schema,se_obj)
      schema_viewer.display(sid,outf,form,ls,dn)
