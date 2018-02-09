# -*- coding: utf-8 -*-
"""
w2lapp.schema: Module package for application-specific
               (pseudo-)schema handling

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import sys,ldap,ldap.schema,ldaputil.schema,msbase


NOT_HUMAN_READABLE_LDAP_SYNTAXES = set([
  '1.3.6.1.4.1.1466.115.121.1.4',  # Audio
  '1.3.6.1.4.1.1466.115.121.1.5',  # Binary
  '1.3.6.1.4.1.1466.115.121.1.8',  # Certificate
  '1.3.6.1.4.1.1466.115.121.1.9',  # Certificate List
  '1.3.6.1.4.1.1466.115.121.1.10', # Certificate Pair
  '1.3.6.1.4.1.1466.115.121.1.23', # G3 FAX
  '1.3.6.1.4.1.1466.115.121.1.28', # JPEG
  '1.3.6.1.4.1.1466.115.121.1.49', # Supported Algorithm
  # From draft-sermersheim-nds-ldap-schema
  '2.16.840.1.113719.1.1.5.1.12',
  '2.16.840.1.113719.1.1.5.1.13',
])


# OIDs of syntaxes and attribute types which need ;binary
NEEDS_BINARY_TAG = set((
  # attribute types
  '2.5.4.37', # caCertificate
  '2.5.4.36', # userCertificate
  '2.5.4.40', # crossCertificatePair
  '2.5.4.52', # supportedAlgorithms
  '2.5.4.38', # authorityRevocationList
  '2.5.4.39', # certificateRevocationList
  '2.5.4.53', # deltaRevocationList
  # LDAP syntaxes
  '1.3.6.1.4.1.1466.115.121.1.8', # Certificate
  '1.3.6.1.4.1.1466.115.121.1.9', # Certificate List
  '1.3.6.1.4.1.1466.115.121.1.10', # Certificate Pair
  '1.3.6.1.4.1.1466.115.121.1.49', # Supported Algorithm
))


USERAPP_ATTRS = set(map(str.lower,(
  'objectClass',
)))

NO_USERAPP_ATTRS = set(map(str.lower,(
  'entryCSN',
)))


def no_userapp_attr(schema,attr_type_name,relax_rules=False):
  """
  Returns True if the attribute type specified by the schema
  element instance attr_se is considered operational and therefore
  should not be modified by the user.

  If the attribute type is not found in the schema False is returned.
  """
  at_lower = attr_type_name.lower()
  if at_lower in USERAPP_ATTRS:
    return False
  if at_lower in NO_USERAPP_ATTRS and not relax_rules:
    return True
  attr_type_se = schema.get_obj(ldap.schema.AttributeType,attr_type_name)
  if attr_type_se is None:
    return False
#  return attr_type_se.usage!=0 or attr_type_se.no_user_mod or attr_type_se.collective
  return attr_type_se.no_user_mod or attr_type_se.collective


def no_humanreadable_attr(schema,attr_type):
  """
  Returns True if the attribute type specified by the server's schema
  element instance attr_se cannot be displayed human readable form.
  """
  attr_type_se = schema.get_obj(ldap.schema.AttributeType,attr_type)
  if attr_type_se is None:
    return False
  syntax_oid = attr_type_se.__dict__.get('syntax',None)
  if syntax_oid!=None:
    syntax_se = schema.get_obj(ldap.schema.LDAPSyntax,syntax_oid)
    if syntax_se!=None and syntax_se.not_human_readable:
      return True
  return \
    syntax_oid in ldap.schema.NOT_HUMAN_READABLE_LDAP_SYNTAXES or \
    attr_type.endswith(';binary')


def object_class_categories(sub_schema,object_classes):
  """
  Split a list of object class identifiers (name or OID)
  into three lists of categories of object classes.
  """
  ObjectClass = ldap.schema.ObjectClass
  if len(object_classes)==1:
    # Special work-around:
    # Consider a single object class without object class description in 
    # schema always to be STRUCTURAL
    oc_obj = sub_schema.get_obj(ObjectClass,object_classes[0])
    if oc_obj is None:
      oc_kind = 0
    else:
      oc_kind = oc_obj.kind
    kind = [[],[],[]]
    kind[oc_kind] = object_classes
  else:
    kind = [
      ldap.cidict.cidict(),
      ldap.cidict.cidict(),
      ldap.cidict.cidict()
    ]
    for nameoroid in object_classes:
      oc_obj = sub_schema.get_obj(ObjectClass,nameoroid)
      if oc_obj is None:
        continue
      kind[oc_obj.kind][nameoroid] = None
    for k in range(3):
      l = kind[k].keys()
      l.sort(key=str.lower)
      kind[k] = l
  return tuple(kind)


def parse_fake_schema(ldap_def):
  for k in ldap_def.keys():
    try:
      schema_uri = ldap_def[k].schema_uri
    except AttributeError:
      pass
    else:
      try:
        _,schema = ldap.schema.urlfetch(schema_uri)
      except (IOError,OSError,ldap.LDAPError) as e:
        # FIX ME!!! This does not work for running as FastCGI server
        sys.stderr.write('Error retrieving schema from %s: %s\n' % (schema_uri,str(e)))
      else:
        if schema!=None:
          # Here comes an ugly class changing hack!!!
          schema.__class__ = ldaputil.schema.SubSchema
          schema.no_user_mod_attr_oids = schema.determine_no_user_mod_attrs()
          # Store the pre-parsed schema in the configuration
          ldap_def[k]._schema = schema

