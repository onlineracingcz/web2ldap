# -*- coding: utf-8 -*-
"""
ldaputil.modlist2 - create modify modlist's with schema knowledge
(c) by Michael Stroeder <michael@stroeder.com>
"""

from __future__ import absolute_import

import ldap,ldaputil.schema

# This constant defines the maximum count of attribute values for
# which order is preserved when generating a diff
MODLIST_VALUE_ORDERING_MAXCOUNT = 3


def modifyModlist(
  sub_schema,
  old_entry,
  new_entry,
  ignore_attr_types=None,
  ignore_oldexistent=0
):
  """
  Build differential modify list for calling LDAPObject.modify()/modify_s()

  sub_schema
      Instance of ldaputil.schema.SubSchema
  old_entry
      Dictionary holding the old entry
  new_entry
      Dictionary holding what the new entry should be
  ignore_attr_types
      List of attribute type names to be ignored completely
  ignore_oldexistent
      If non-zero attribute type names which are in old_entry
      but are not found in new_entry at all are not deleted.
      This is handy for situations where your application
      sets attribute value to '' for deleting an attribute.
      In most cases leave zero.
  """
  # Type checking
  assert isinstance(sub_schema,ldaputil.schema.SubSchema)
  assert isinstance(old_entry,ldaputil.schema.Entry)
  assert isinstance(new_entry,ldaputil.schema.Entry)

  # Performance optimization
  AttributeType = ldap.schema.AttributeType
  MatchingRule = ldap.schema.MatchingRule

  # Start building the modlist result
  modlist = []

  # Sanitize new_entry
  for a in new_entry.keys():
    # Filter away list items which are empty strings or None
    new_entry[a] = filter(None,new_entry[a])
    # Check for attributes with empty value lists
    if not new_entry[a]:
      # Remove the empty attribute
      del new_entry[a]

  for attrtype in new_entry.keys():

    if sub_schema.getoid(AttributeType,attrtype) in ignore_attr_types:
      # This attribute type is ignored
      continue

    # Check whether there's an equality matching rule defined
    # for the attribute type and the matching rule is announced in subschema
    try:
      at_eq_mr = sub_schema.get_inheritedattr(AttributeType,attrtype,'equality')
    except KeyError:
      mr_obj =  None
    else:
      if at_eq_mr:
        mr_obj =  sub_schema.get_obj(MatchingRule,at_eq_mr)
      else:
        mr_obj =  None

    # Filter away list items which are empty strings or None
    new_value = new_entry[attrtype]
    old_value = filter(None,old_entry.get(attrtype,[]))

    # We have to check if attribute value lists differs
    old_value_dict={}.fromkeys(old_value)
    new_value_dict={}.fromkeys(new_value)

    if mr_obj:
      # for attributes with equality matching rule try to
      # generate a fine-grained diff
      if len(old_value)>MODLIST_VALUE_ORDERING_MAXCOUNT or len(new_value)>MODLIST_VALUE_ORDERING_MAXCOUNT:
        # for "many" values be less invasive but not order-preserving
        del_values = [ v for v in old_value if not v in new_value_dict ]
        add_values = [ v for v in new_value if not v in old_value_dict ]
        if old_value and del_values:
          modlist.append((ldap.MOD_DELETE,attrtype,del_values))
        if new_value and add_values:
          modlist.append((ldap.MOD_ADD,attrtype,add_values))
      else:
        # for few values be order-preserving
        if new_value and old_value!=new_value:
          if old_value:
            modlist.append((ldap.MOD_DELETE,attrtype,old_value))
          modlist.append((ldap.MOD_ADD,attrtype,new_value))
    elif new_value and old_value!=new_value:
      if old_value:
        modlist.append((ldap.MOD_DELETE,attrtype,None))
      modlist.append((ldap.MOD_ADD,attrtype,new_value))

  # Remove all attributes of old_entry which are not present
  # in new_entry at all
  if not ignore_oldexistent:
    for attrtype,old_values in old_entry.items():
      if old_values and \
         old_values!=[''] and \
         not attrtype in new_entry and \
         not sub_schema.getoid(AttributeType,attrtype) in ignore_attr_types:
        try:
          at_eq_mr =  sub_schema.get_inheritedattr(AttributeType,attrtype,'equality')
        except KeyError:
          at_eq_mr = None
        if at_eq_mr:
          mr_obj =  sub_schema.get_obj(MatchingRule,at_eq_mr)
          if mr_obj:
            modlist.append((ldap.MOD_DELETE,attrtype,old_values))
          else:
            modlist.append((ldap.MOD_DELETE,attrtype,None))
        else:
          modlist.append((ldap.MOD_DELETE,attrtype,None))

  return modlist # modifyModlist()
