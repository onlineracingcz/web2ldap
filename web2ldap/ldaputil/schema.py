# -*- coding: utf-8 -*-
"""
ldaputil.schema: More functionality for ldap0.schema

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import collections
from itertools import combinations
from types import UnicodeType

import ldap0.schema
import ldap0.schema.subentry
from ldap0.schema.models import AttributeType


class SchemaElementOIDSet(collections.MutableSet):

  def __init__(self,schema,se_class,nameoroids):
    self._schema = schema
    self._se_class = se_class
    self._nameoroid_dict = {}
    self._nameoroid_list = []
    nameoroids = filter(
      None,
      [ nameoroid.strip() for nameoroid in nameoroids ]
    )
    for nameoroid in nameoroids:
      self.add(nameoroid)
  
  def __iter__(self):
    return self._nameoroid_list.__iter__()

  def __len__(self):
    return len(self._nameoroid_dict)

  def discard(self,nameoroid):
    oid = self._schema.getoid(self._se_class,nameoroid,raise_keyerror=0).lower()
    try:
      del self._nameoroid_dict[oid]
    except KeyError:
      pass
    else:
      self._nameoroid_list.remove(oid)

  def __contains__(self,nameoroid):
    oid = self._schema.getoid(self._se_class,nameoroid,raise_keyerror=0).lower()
    return oid in self._nameoroid_dict

  def intersection(self,s):
    return SchemaElementOIDSet(
      self._schema,
      self._se_class,
      [
        i
        for i in s
        if i in self
      ]
    )

  def add(self,se_name):
    se_name = se_name.strip()
    if se_name[0]=='@':
      assert self._se_class==AttributeType,ValueError('@-form only possible with AttributeType')
      must_attr,may_attr = self._schema.attribute_types(
        (se_name[1:],),
        attr_type_filter=None,
        raise_keyerror=0,
        ignore_dit_content_rule=1
      )
      at_list = [
        ( at_oid , (at_obj.names or [at_oid])[0] )
        for at_oid,at_obj in must_attr.items() + may_attr.items()
      ]
    else:
      at_list = [ (self._schema.getoid(self._se_class,se_name,raise_keyerror=0).lower(),se_name) ]
    for at_oid,at_name in at_list:
      if not at_oid in self._nameoroid_dict:
        self._nameoroid_dict[at_oid] = at_name
        self._nameoroid_list.append(at_oid)

  def update(self,l):
    for i in l:
      self.add(i)

  def names(self):
    return [
      self._nameoroid_dict[se_oid]
      for se_oid in self._nameoroid_list
    ]


class SubSchema(ldap0.schema.subentry.SubSchema):

  def __init__(self,sub_schema_sub_entry,subentry_dn=None,check_uniqueness=True):
    ldap0.schema.subentry.SubSchema.__init__(
      self,
      sub_schema_sub_entry,
      check_uniqueness=check_uniqueness,
    )
    self.subentry_dn = subentry_dn
    self.no_user_mod_attr_oids = self.determine_no_user_mod_attrs()

  def get_all_operational_attribute_names(self,only_user_editable=False):
    """
    Returns SchemaElementOIDSet with all operational attributes
    """
    r = []
    for at_obj in self.sed[AttributeType].values():
      if at_obj.usage!=0 and \
        (not only_user_editable or not (at_obj.no_user_mod or at_obj.collective)):
        r.append(at_obj.names[0])
    return r

  def determine_no_user_mod_attrs(self):
    result = {}.fromkeys([
      a.oid
      for a in self.sed[ldap0.schema.models.AttributeType].values()
      if a.no_user_mod
    ])
    return result # determine_no_user_mod_attrs()

  def get_associated_name_forms(self,structural_object_class_oid):
    """
    Returns a list of instances of ldap0.schema.models.NameForm
    representing all name forms associated with the current structural
    object class of this entry.

    The structural object class is determined by attribute
    'structuralObjectClass' if it exists or by calling
    method get_structural_oc() if not.
    """
    if structural_object_class_oid is None:
      return []
    structural_object_class_obj = self.get_obj(ldap0.schema.models.ObjectClass,structural_object_class_oid)
    if structural_object_class_obj:
      structural_object_class_names = [
        oc_name.lower()
        for oc_name in structural_object_class_obj.names or ()
      ]
    else:
      structural_object_class_names = ()
    result = []
    for name_form_oid,name_form_obj in self.sed[ldap0.schema.models.NameForm].items():
      if not name_form_obj.obsolete and (
           name_form_obj.oc==structural_object_class_oid or \
           name_form_obj.oc.lower() in structural_object_class_names
      ):
        result.append(name_form_obj)
    return result # get_associated_name_forms()

  def get_rdn_variants(self,structural_object_class_oid):
    rdn_variants = []
    for name_form_obj in self.get_associated_name_forms(structural_object_class_oid):
      rdn_variants.append((name_form_obj,name_form_obj.must))
      for l in range(1, len(name_form_obj.may)):
        for i in combinations(name_form_obj.may, l):
          rdn_variants.append((name_form_obj,name_form_obj.must+i))
    return rdn_variants # get_rdn_variants()

  def get_rdn_templates(self,structural_object_class_oid):
    """convert the tuple RDN combinations to RDN template strings"""
    rdn_attr_tuples = {}.fromkeys([
      rdn_attr_tuple
      for name_form_obj,rdn_attr_tuple in self.get_rdn_variants(structural_object_class_oid)
    ]).keys()
    return [
      '+'.join([
        '%s=' % (attr_type)
        for attr_type in attr_types
      ])
      for attr_types in rdn_attr_tuples
    ] # get_rdn_templates()

  def get_applicable_name_form_objs(self,dn,structural_object_class_oid):
    """
    Returns a list of instances of ldap0.schema.models.NameForm
    representing all name form associated with the current structural
    object class of this entry and matching the current RDN.
    """
    if dn:
      rdn_list=ldap0.dn.str2dn(dn)[0]
      current_rdn_attrs = [ attr_type.lower() for attr_type,attr_value,dummy in rdn_list ]
      current_rdn_attrs.sort()
    else:
      current_rdn_attrs = []
    result=[]
    for name_form_obj,rdn_attr_tuple in self.get_rdn_variants(structural_object_class_oid):
      name_form_rdn_attrs = [ attr_type.lower() for attr_type in rdn_attr_tuple ]
      name_form_rdn_attrs.sort()
      if current_rdn_attrs==name_form_rdn_attrs:
        result.append(name_form_obj)
    return result # get_applicable_name_form_objs()

  def get_possible_dit_structure_rules(self,dn,structural_object_class_oid):
    name_form_identifiers = ldap0.cidict.cidict({})
    for name_form_obj in self.get_applicable_name_form_objs(dn,structural_object_class_oid):
      name_form_identifiers[name_form_obj.oid] = None
    dit_struct_ruleids = {}
    for dit_struct_rule_obj in self.sed[ldap0.schema.models.DITStructureRule].values():
      name_form_obj = self.get_obj(ldap0.schema.models.NameForm,dit_struct_rule_obj.form)
      if name_form_obj!=None and (name_form_obj.oid in name_form_identifiers) and \
         (self.getoid(ldap0.schema.models.ObjectClass,name_form_obj.oc)==structural_object_class_oid):
        dit_struct_ruleids[dit_struct_rule_obj.ruleid]=dit_struct_rule_obj
    return dit_struct_ruleids.keys() # get_possible_dit_structure_rules()

  def get_subord_structural_oc_names(self,ruleid):
    subord_structural_oc_oids = {}
    subord_structural_ruleids = {}
    for dit_struct_rule_obj in self.sed[ldap0.schema.models.DITStructureRule].values():
      for sup in dit_struct_rule_obj.sup:
        if sup==ruleid:
          subord_structural_ruleids[dit_struct_rule_obj.ruleid]=None
          name_form_obj = self.get_obj(ldap0.schema.models.NameForm,dit_struct_rule_obj.form)
          if name_form_obj:
            subord_structural_oc_oids[self.getoid(ldap0.schema.models.ObjectClass,name_form_obj.oc)]=None
    result = []
    for oc_oid in subord_structural_oc_oids.keys():
      oc_obj = self.get_obj(ldap0.schema.models.ObjectClass,oc_oid)
      if oc_obj and oc_obj.names:
        result.append(oc_obj.names[0])
      else:
        result.append(oc_oid)
    return subord_structural_ruleids.keys(),result # get_subord_structural_oc_names()

  def get_superior_structural_oc_names(self,ruleid):
    try:
      dit_struct_rule_obj = self.sed[ldap0.schema.models.DITStructureRule][ruleid]
    except KeyError:
      return None
    else:
      result=[];sup_ruleids=[]
      for sup_ruleid in dit_struct_rule_obj.sup:
        try:
          sup_dit_struct_rule_obj = self.sed[ldap0.schema.models.DITStructureRule][sup_ruleid]
        except KeyError:
          pass
        else:
          if sup_dit_struct_rule_obj.form:
            sup_name_form_obj = self.get_obj(ldap0.schema.models.NameForm,sup_dit_struct_rule_obj.form)
            if sup_name_form_obj:
              sup_ruleids.append(sup_ruleid)
              result.append(sup_name_form_obj.oc)
    return sup_ruleids,result # get_superior_structural_oc_names()


class Entry(ldap0.schema.models.Entry):
  """
  Base class with some additional basic methods
  """

  def __getitem__(self,nameoroid):
    try:
      return ldap0.schema.models.Entry.__getitem__(self,nameoroid)
    except KeyError as e:
      if (self.dn!=None) and (nameoroid.lower()=='entrydn' or nameoroid.lower()=='1.3.6.1.1.20'):
        if type(self.dn)==UnicodeType:
          entry_dn = self.dn.encode('utf-8')
        else:
          entry_dn = self.dn
        return [entry_dn]
      else:
        raise e

  def object_class_oid_set(self):
    try:
      object_classes = ldap0.schema.models.Entry.__getitem__(self,'objectClass')
    except KeyError:
      object_classes = []
    return SchemaElementOIDSet(self._s,ldap0.schema.models.ObjectClass,object_classes)

  def get_structural_oc(self):
    try:
      structural_object_class_oid = self._s.getoid(
        ldap0.schema.models.ObjectClass,
        ldap0.schema.models.Entry.__getitem__(self,'structuralObjectClass')[-1]
      )
    except (KeyError,IndexError):
      try:
        structural_object_class_oid = self._s.get_structural_oc(
          ldap0.schema.models.Entry.__getitem__(self,'objectClass')
        )
      except KeyError:
        return None
    return structural_object_class_oid

  def get_possible_dit_structure_rules(self,dn):
    try:
      structural_oc = self.get_structural_oc()
    except KeyError:
      return None
    else:
      return self._s.get_possible_dit_structure_rules(dn,structural_oc)

  def get_rdn_templates(self):
    return self._s.get_rdn_templates(self.get_structural_oc())
