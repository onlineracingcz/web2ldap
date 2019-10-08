# -*- coding: utf-8 -*-
"""
web2ldap.app.schema.viewer -  Display LDAPv3 schema

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0

from ldap0.schema.subentry import SCHEMA_ATTRS, SCHEMA_CLASS_MAPPING, SCHEMA_ATTR_MAPPING
from ldap0.schema.models import \
    LDAPSyntax, \
    AttributeType, \
    ObjectClass, \
    MatchingRule, \
    MatchingRuleUse, \
    DITContentRule, \
    DITStructureRule, \
    NameForm, \
    OBJECTCLASS_KIND_STR

from web2ldap.web import escape_html
import web2ldap.app.gui
import web2ldap.app.schema.syntaxes


OBSOLETE_TEMPL = {
    False: '%s',
    True: '<s>%s</s>',
}

SCHEMA_VIEWER_USAGE = """
<p>Hints:</p>
<ul>
  <li>You can search for schema elements by OID or name.</li>
  <li>Wildcard search with * is supported.</li>
  <li>For browsing choose from context menu on the right</li>
</ul>
"""


def schema_link_text(se, charset):
    names = [
        escape_html(name)
        for name in se.__dict__.get('names', (()))
    ]
    obsolete = se.__dict__.get('obsolete', False)
    if len(names) == 1:
        res = names[0]
    elif len(names) > 1:
        res = '%s (alias %s)' % (names[0], ', '.join(names[1:]))
    elif isinstance(se, LDAPSyntax) and se.desc is not None:
        res = escape_html(se.desc)
    else:
        res = escape_html(se.oid)
    return OBSOLETE_TEMPL[obsolete] % res


def schema_anchor(
        app,
        se_nameoroid,
        se_class,
        name_template=r'%s',
        link_text=None,
    ):
    """
    Return a pretty HTML-formatted string describing a schema element
    referenced by name or OID
    """
    se = app.schema.get_obj(se_class, se_nameoroid, None)
    if se is None:
        return name_template % (app.form.utf2display(se_nameoroid))
    anchor = app.anchor(
        'oid', link_text or schema_link_text(se, app.form.accept_charset),
        [
            ('dn', app.dn),
            ('oid', se.oid),
            ('oid_class', ldap0.schema.SCHEMA_ATTR_MAPPING[se_class]),
        ]
    )
    if link_text is None:
        return name_template % (anchor)
    return '%s\n%s' % (
        name_template % (app.form.utf2display(se_nameoroid)),
        anchor,
    )
    # end of schema_anchor()


def schema_anchors(app, se_names, se_class):
    link_texts = []
    for se_nameoroid in se_names:
        se = app.schema.get_obj(se_class, se_nameoroid, default=None)
        if se:
            ltxt = schema_link_text(se, app.form.accept_charset)
            try:
                schema_id = se.oid
            except AttributeError:
                schema_id = se.ruleid
            anchor = app.anchor(
                'oid', ltxt,
                [
                    ('dn', app.dn),
                    ('oid', schema_id),
                    ('oid_class', SCHEMA_ATTR_MAPPING[se_class]),
                ],
            )
            link_texts.append((ltxt, anchor))
        else:
            link_texts.append((se_nameoroid, se_nameoroid))
    link_texts.sort(key=lambda x: x[0].lower())
    return [i[1] for i in link_texts]


def schema_tree_html(app, schema, se_class, se_tree, se_oid, level):
    """HTML output for browser"""
    app.outf.write('<dl>')
    se_obj = schema.get_obj(se_class, se_oid)
    if se_obj is not None:
        display_id = (se_obj.names or (se_oid,))[0]
        app.outf.write(
            '<dt>%s</dt>' % (
                schema_anchor(app, display_id, se_class),
            )
        )
    if se_tree[se_oid]:
        app.outf.write('<dd>')
        for sub_se_oid in se_tree[se_oid]:
            schema_tree_html(app, schema, se_class, se_tree, sub_se_oid, level+1)
        app.outf.write('</dd>')
    else:
        app.outf.write('<dd></dd>')
    app.outf.write('</dl>')
    # end of schema_tree_html()


def schema_context_menu(app):
    """Build context menu with schema-related items"""
    context_menu_list = []
    sub_schema_dn = None
    try:
        sub_schema_dn = app.ls.l.search_subschemasubentry_s(app.dn)
    except ldap0.LDAPError:
        pass
    else:
        if sub_schema_dn is not None:
            form_param_list = [
                ('dn', sub_schema_dn),
                ('filterstr', u'(objectClass=subschema)'),
            ]
            for schema_attr in SCHEMA_ATTRS+['objectClass', 'cn']:
                form_param_list.append(('read_attr', schema_attr))
            context_menu_list.append(
                app.anchor(
                    'read', 'Subschema Subentry',
                    form_param_list,
                    title=u'Directly read the subschema subentry'),
                )
        if app.schema:
            se_class_attrs = [
                SCHEMA_ATTR_MAPPING[se_class]
                for se_class in app.schema.sed.keys()
                if app.schema.sed[se_class]
            ]
            se_class_attrs.sort(key=str.lower)
            for se_class_attr in se_class_attrs:
                context_menu_list.append(
                    app.anchor(
                        'oid', se_class_attr,
                        [('dn', app.dn), ('oid_class', se_class_attr)],
                        title=u'Browse all %s' % (se_class_attr),
                    )
                )
    return context_menu_list


class DisplaySchemaElement:
    type_desc = 'Abstract Schema Element'
    detail_attrs = ()

    def __init__(self, app, se):
        self._app = app
        self.s = app.schema
        self.se = se
        try:
            schema_id = self.se.oid
        except AttributeError:
            schema_id = self.se.ruleid
        self.sei = app.schema.get_inheritedobj(self.se.__class__, schema_id, [])

    def disp_details(self):
        for text, class_attr, se_class in self.detail_attrs:
            class_attr_value = self.sei.__dict__.get(class_attr, None)
            if class_attr_value is None:
                continue
            if isinstance(class_attr_value, (tuple, list)):
                class_attr_value_list = list(class_attr_value)
                class_attr_value_list.sort(key=str.lower)
            else:
                class_attr_value_list = [class_attr_value]
            if se_class is None:
                value_output = ', '.join([
                    self._app.form.utf2display(v, sp_entity=' ', lf_entity='<br>')
                    for v in class_attr_value_list
                ])
            else:
                value_output = ', '.join(
                    schema_anchors(self._app, class_attr_value_list, se_class)
                )
            self._app.outf.write('<dt>%s</dt>\n<dd>\n%s\n</dd>\n' % (text, value_output))
        # end of disp_details()

    def display(self):
        ms_ad_schema_link = ''
        if 'schemaNamingContext' in self._app.ls.rootDSE:
            try:
                result = self._app.ls.l.search_s(
                    self._app.ls.rootDSE['schemaNamingContext'][0].decode(self._app.ls.charset),
                    ldap0.SCOPE_SUBTREE,
                    (
                        '(|'
                        '(&(objectClass=attributeSchema)(attributeID=%s))'
                        '(&(objectClass=classSchema)(governsID=%s))'
                        ')'
                    ) % (
                        self.se.oid,
                        self.se.oid,
                    ),
                    attrlist=['cn']
                )
            except ldap0.LDAPError:
                pass
            else:
                if result:
                    ad_schema_dn, ad_schema_entry = result[0].dn_s, result[0].entry_s
                    ms_ad_schema_link = '<dt>Schema Definition Entry (MS AD)</dt>\n<dd>\n%s\n</dd>\n' % (
                        self._app.anchor(
                            'read', ad_schema_entry['cn'][0],
                            [('dn', ad_schema_dn)],
                        )
                    )
        obsolete = self.se.__dict__.get('obsolete', 0)
        web2ldap.app.gui.top_section(
            self._app,
            '%s %s (%s)' % (
                self.type_desc,
                ', '.join(
                    self.se.__dict__.get('names', (()))
                ),
                self.se.oid
            ),
            web2ldap.app.gui.main_menu(self._app),
            context_menu_list=schema_context_menu(self._app)
        )
        self._app.outf.write(
            """
            %s
            <h1>%s <em>%s</em> (%s)</h1>
            Try to look it up:
            <a id="alvestrand_oid" href="%s/urlredirect/%s?http://www.alvestrand.no/objectid/%s.html">[Alvestrand]</a>
            <a id="oid-info_oid" href="%s/urlredirect/%s?http://www.oid-info.com/get/%s">[oid-info.com]</a>
            <dl>
            <dt>Schema element string:</dt>
            <dd><code>%s</code></dd>
            %s
            </dl>
            """ % (
                oid_input_form(self._app, ''),
                self.type_desc,
                OBSOLETE_TEMPL[obsolete] % (
                    ', '.join(self.se.__dict__.get('names', (()))),
                ),
                self.se.oid,
                self._app.form.script_name, self._app.sid, self.se.oid,
                self._app.form.script_name, self._app.sid, self.se.oid,
                self._app.form.utf2display(str(self.se)),
                ms_ad_schema_link,
            )
        )
        self.disp_details()
        web2ldap.app.gui.footer(self._app)


class DisplayObjectClass(DisplaySchemaElement):
    type_desc = 'Object class'
    detail_attrs = (
        ('Description', 'desc', None),
        ('Derived from', 'sup', ObjectClass),
    )

    def __init__(self, app, se):
        DisplaySchemaElement.__init__(self, app, se)
        self.sei = app.schema.get_inheritedobj(self.se.__class__, self.se.oid, ['kind'])

    def disp_details(self):
        DisplaySchemaElement.disp_details(self)
        must, may = self.s.attribute_types([self.se.oid], raise_keyerror=False)
        # Display all required and allowed attributes
        self._app.outf.write('<dt>Kind of object class:</dt><dd>\n%s&nbsp;</dd>\n' % (
            OBJECTCLASS_KIND_STR[self.sei.kind]
        ))
        # Display all required and allowed attributes
        self._app.outf.write('<dt>All required attributes:</dt><dd>\n%s&nbsp;</dd>\n' % (
            ', '.join(schema_anchors(self._app, must.keys(), AttributeType))
        ))
        self._app.outf.write('<dt>All allowed attributes:</dt><dd>\n%s&nbsp;</dd>\n' % (
            ', '.join(schema_anchors(self._app, may.keys(), AttributeType))
        ))
        # Display relationship to DIT content rule(s)
        # normally only in case of a STRUCTURAL object class)
        content_rule = self.s.get_obj(DITContentRule, self.se.oid)
        if content_rule:
            self._app.outf.write('<dt>Governed by DIT content rule:</dt><dd>\n%s&nbsp;</dd>\n' % (
                schema_anchor(self._app, content_rule.oid, DITContentRule)
            ))
            self._app.outf.write('<dt>Applicable auxiliary object classes:</dt><dd>\n%s&nbsp;</dd>\n' % (
                ', '.join(schema_anchors(self._app, content_rule.aux, ObjectClass))
            ))
        # normally only in case of a AUXILIARY object class
        dcr_list = []
        structural_oc_list = []
        for _, content_rule in self.s.sed[DITContentRule].items():
            for aux_class_name in content_rule.aux:
                aux_class_oid = self.s.get_oid(ObjectClass, aux_class_name)
                if aux_class_oid == self.se.oid:
                    dcr_list.append(content_rule.oid)
                    structural_oc_list.append(content_rule.oid)
        if dcr_list:
            self._app.outf.write('<dt>Referring DIT content rules:</dt><dd>\n%s&nbsp;</dd>\n' % (
                ', '.join(schema_anchors(self._app, dcr_list, DITContentRule))
            ))
        if structural_oc_list:
            self._app.outf.write('<dt>Allowed with structural object classes:</dt><dd>\n%s&nbsp;</dd>\n' % (
                ', '.join(schema_anchors(self._app, structural_oc_list, ObjectClass))
            ))
        # Display name forms which regulates naming for this object class
        oc_ref_list = []
        for nf_oid, name_form_se in self.s.sed[NameForm].items():
            name_form_oc = name_form_se.oc.lower()
            se_names = set([o.lower() for o in self.sei.names])
            if name_form_se.oc == self.sei.oid or name_form_oc in se_names:
                oc_ref_list.append(nf_oid)
        if oc_ref_list:
            self._app.outf.write('<dt>Applicable name forms:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, oc_ref_list, NameForm))
            ))
        # Display tree of derived object classes
        self._app.outf.write('<dt>Object class tree:</dt>\n')
        self._app.outf.write('<dd>\n')
        try:
            oc_tree = self.s.tree(ObjectClass)
        except KeyError as e:
            self._app.outf.write('<strong>Missing schema elements referenced:<pre>%s</pre></strong>\n' % self._app.form.utf2display(str(e)))
        else:
            if self.se.oid in oc_tree and oc_tree[self.se.oid]:
                schema_tree_html(self._app, self.s, ObjectClass, oc_tree, self.se.oid, 0)
        self._app.outf.write('&nbsp;</dd>\n')
        # Display a link for searching entries by object class
        self._app.outf.write(
            '<dt>Search entries</dt>\n<dd>\n%s\n</dd>\n' % (
                self._app.anchor(
                    'searchform',
                    '(objectClass=%s)' % self._app.form.utf2display(str((self.se.names or [self.se.oid])[0])),
                    [
                        ('dn', self._app.dn),
                        ('searchform_mode', u'adv'),
                        ('search_attr', u'objectClass'),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_IS_EQUAL),
                        ('search_string', str((self.se.names or [self.se.oid])[0])),
                    ],
                    title=u'Search entries by object class',
                )
            )
        )
        # end of disp_details()


class DisplayAttributeType(DisplaySchemaElement):
    type_desc = 'Attribute type'
    detail_attrs = (
        ('Description', 'desc', None),
        ('Syntax', 'syntax', LDAPSyntax),
        ('Derived from', 'sup', AttributeType),
        ('Equality matching rule', 'equality', MatchingRule),
        ('Sub-string matching rule', 'substr', MatchingRule),
        ('Ordering matching rule', 'ordering', MatchingRule),
    )

    def __init__(self, app, se):
        DisplaySchemaElement.__init__(self, app, se)
        try:
            self.sei = app.schema.get_inheritedobj(
                self.se.__class__, self.se.oid,
                ('syntax', 'equality', 'substr', 'ordering'),
            )
        except KeyError:
            # If the schema element referenced by SUP is not present
            self.sei = app.schema.get_obj(self.se.__class__, self.se.oid)

    def disp_details(self):

        DisplaySchemaElement.disp_details(self)

        at_oid = self.se.oid
        syntax_oid = self.sei.syntax

        self._app.outf.write('<dt>Usage:</dt>\n<dd>\n%s\n</dd>\n' % (
            {
                0: 'userApplications',
                1: 'directoryOperation',
                2: 'distributedOperation',
                3: 'dSAOperation',
            }[self.se.usage]
        ))

        if syntax_oid is not None:

            # Display applicable matching rules
            #---------------------------------------------------------------
            mr_use_se = self.s.get_obj(MatchingRuleUse, syntax_oid)
            applies_dict = {}
            for mr_oid, mr_use_se in self.s.sed[MatchingRuleUse].items():
                applies_dict[mr_oid] = {}
                mr_use_se = self.s.get_obj(MatchingRuleUse, mr_oid)
                for a in mr_use_se.applies:
                    applies_dict[mr_oid][self.s.get_oid(AttributeType, a)] = None
            # Display list of attribute types for which this matching rule is applicable
            mr_applicable_for = [
                mr_oid
                for mr_oid in self.s.sed[MatchingRule].keys()
                if mr_oid in applies_dict and at_oid in applies_dict[mr_oid]
            ]
            if mr_applicable_for:
                self._app.outf.write('<dt>Applicable matching rules:</dt>\n<dd>\n%s\n</dd>\n' % (
                    ', '.join(
                        schema_anchors(self._app, mr_applicable_for, MatchingRule)
                    )
                ))

        # Display DIT content rules which reference attributes of this type
        #-------------------------------------------------------------------
        attr_type_ref_list = []
        for oc_oid, object_class_se in self.s.sed[ObjectClass].items():
            object_class_se = self.s.get_obj(ObjectClass, oc_oid)
            for dcr_at in object_class_se.must+object_class_se.may:
                if dcr_at == at_oid or dcr_at in self.sei.names:
                    attr_type_ref_list.append(oc_oid)
        if attr_type_ref_list:
            self._app.outf.write('<dt>Directly referencing object classes:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, attr_type_ref_list, ObjectClass))
            ))

        # Display object classes which may contain attributes of this type
        #-------------------------------------------------------------------
        all_object_classes = self.s.sed[ObjectClass].keys()
        attr_type_ref_list = []
        for oc_oid in all_object_classes:
            must, may = self.s.attribute_types([oc_oid], raise_keyerror=False)
            if at_oid in must or at_oid in may:
                attr_type_ref_list.append(oc_oid)
        if attr_type_ref_list:
            self._app.outf.write('<dt>Usable in these object classes:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, attr_type_ref_list, ObjectClass))
            ))

        # Display DIT content rules which reference attributes of this type
        #-------------------------------------------------------------------
        attr_type_ref_list = []
        for dcr_oid, dit_content_rule_se in self.s.sed[DITContentRule].items():
            dit_content_rule_se = self.s.get_obj(DITContentRule, dcr_oid)
            for dcr_at in dit_content_rule_se.must+dit_content_rule_se.may+dit_content_rule_se.nots:
                if dcr_at == at_oid or dcr_at in self.sei.names:
                    attr_type_ref_list.append(dcr_oid)
        if attr_type_ref_list:
            self._app.outf.write('<dt>Referencing DIT content rules:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, attr_type_ref_list, DITContentRule))
            ))

        # Display name forms which uses this attribute type for naming an entry
        #-----------------------------------------------------------------------
        attr_type_ref_list = []
        for nf_oid, name_form_se in self.s.sed[NameForm].items():
            name_form_se = self.s.get_obj(NameForm, nf_oid)
            for nf_at in name_form_se.must+name_form_se.may:
                if nf_at == at_oid or nf_at in self.sei.names:
                    attr_type_ref_list.append(nf_oid)
        if attr_type_ref_list:
            self._app.outf.write('<dt>Referencing name forms:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, attr_type_ref_list, NameForm))
            ))

        #########################################
        # Output attribute type inheritance tree
        #########################################
        self._app.outf.write('<dt>Attribute type tree:</dt>\n<dd>\n')
        # Display tree of derived attribute types
        try:
            at_tree = self.s.tree(AttributeType)
        except KeyError as e:
            self._app.outf.write('<strong>Missing schema elements referenced:<pre>%s</pre></strong>\n' % self._app.form.utf2display(str(e)))
        else:
            if at_oid in at_tree and at_tree[at_oid]:
                schema_tree_html(self._app, self.s, AttributeType, at_tree, at_oid, 0)
        # Display a link for searching entries by attribute presence
        self._app.outf.write(
            '</dd>\n<dt>Search entries</dt>\n<dd>\n%s\n</dd>\n' % (
                self._app.anchor(
                    'searchform',
                    '(%s=*)' % self._app.form.utf2display(str((self.se.names or [self.se.oid])[0])),
                    [
                        ('dn', self._app.dn),
                        ('searchform_mode', u'adv'),
                        ('search_attr', str((self.se.names or [self.se.oid])[0])),
                        ('search_option', web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS),
                        ('search_string', ''),
                    ],
                    title=u'Search entries by attribute presence',
                )
            )
        )

        #########################################
        # Output registered plugin class name
        #########################################
        self._app.outf.write("""
          <dt>Associated plugin class(es):</dt>
          <dd>
            <table>
              <tr><th>Structural<br>object class</th><th>Plugin class</th>""")
        for structural_oc in web2ldap.app.schema.syntaxes.syntax_registry.at2syntax[at_oid].keys() or [None]:
            syntax_class = web2ldap.app.schema.syntaxes.syntax_registry.get_syntax(self.s, at_oid, structural_oc)
            if structural_oc:
                oc_text = schema_anchor(self._app, structural_oc, ObjectClass)
            else:
                oc_text = '-any-'
            self._app.outf.write('<tr><td>%s</td><td>%s.%s</td></th>\n' % (
                oc_text,
                self._app.form.utf2display(str(syntax_class.__module__)),
                self._app.form.utf2display(str(syntax_class.__name__)),
            ))
        self._app.outf.write('</table>\n</dd>\n')
        # end of disp_details()


class DisplayLDAPSyntax(DisplaySchemaElement):
    type_desc = 'LDAP Syntax'
    detail_attrs = (
        ('Description', 'desc', None),
    )

    def disp_details(self):
        DisplaySchemaElement.disp_details(self)
        # Display list of attribute types which directly reference this syntax
        syntax_using_at_list = [
            at_oid
            for at_oid in self.s.sed[AttributeType].keys()
            if self.s.get_syntax(at_oid) == self.se.oid
        ]
        if syntax_using_at_list:
            self._app.outf.write('<dt>Referencing attribute types:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, syntax_using_at_list, AttributeType))
            ))
        syntax_ref_mr_list = [
            mr_oid
            for mr_oid in self.s.listall(MatchingRule, [('syntax', self.se.oid)])
        ]
        if syntax_ref_mr_list:
            self._app.outf.write('<dt>Referencing matching rules:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, syntax_ref_mr_list, MatchingRule))
            ))
        try:
            x_subst = self.se.x_subst
        except AttributeError:
            pass
        else:
            if x_subst:
                self._app.outf.write('<dt>Substituted by:</dt>\n<dd>\n%s\n</dd>\n' % (
                    schema_anchor(self._app, x_subst, LDAPSyntax)
                ))
        #########################################
        # Output registered plugin class name
        #########################################
        syntax_class = web2ldap.app.schema.syntaxes.syntax_registry.oid2syntax.get(
            self.se.oid,
            web2ldap.app.schema.syntaxes.LDAPSyntax,
        )
        self._app.outf.write('<dt>Associated syntax class</dt>\n<dd>\n%s\n</dd>\n' % (
            '.'.join((syntax_class.__module__, syntax_class.__name__))
        ))
        # end of disp_details()


class DisplayMatchingRule(DisplaySchemaElement):
    type_desc = 'Matching Rule'
    detail_attrs = (
        ('Description', 'desc', None),
        ('LDAP syntax', 'syntax', LDAPSyntax),
    )

    def disp_details(self):
        DisplaySchemaElement.disp_details(self)
        mr_use_se = self.s.get_obj(MatchingRuleUse, self.se.oid)
        if mr_use_se:
            applies_dict = {}
            for a in mr_use_se.applies:
                applies_dict[self.s.get_oid(AttributeType, a)] = None
            # Display list of attribute types for which this matching rule is applicable
            mr_applicable_for = [
                at_oid
                for at_oid in self.s.sed[AttributeType].keys()
                if at_oid in applies_dict
            ]
            if mr_applicable_for:
                self._app.outf.write('<dt>Applicable for attribute types per matching rule use:</dt>\n<dd>\n%s\n</dd>\n' % (
                    ', '.join(schema_anchors(self._app, mr_applicable_for, AttributeType))
                ))
        mr_used_by = []
        for at_oid in self.s.sed[AttributeType].keys():
            try:
                at_se = self.s.get_inheritedobj(AttributeType, at_oid, ('equality', 'substr', 'ordering'))
            except KeyError:
                pass
            else:
                if at_se and ( \
                   (at_se.equality in self.se.names or at_se.substr in self.se.names or at_se.ordering in self.se.names) or \
                   (at_se.equality == self.se.oid or at_se.substr == self.se.oid or at_se.ordering == self.se.oid) \
                ):
                    mr_used_by.append(at_se.oid)
        if mr_used_by:
            self._app.outf.write('<dt>Referencing attribute types:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, mr_used_by, AttributeType))
            ))
        # end of disp_details()


class DisplayMatchingRuleUse(DisplaySchemaElement):
    type_desc = 'Matching Rule Use'
    detail_attrs = (
        ('Names', 'names', None),
        ('Matching Rule', 'oid', MatchingRule),
        ('Applies to', 'applies', AttributeType),
    )


class DisplayDITContentRule(DisplaySchemaElement):
    type_desc = 'DIT content rule'
    detail_attrs = (
        ('Names', 'names', None),
        ('Governs structural object class', 'oid', ObjectClass),
        ('Auxiliary classes', 'aux', ObjectClass),
        ('Must have', 'must', AttributeType),
        ('May have', 'may', AttributeType),
        ('Must not have', 'nots', AttributeType),
    )


class DisplayDITStructureRule(DisplaySchemaElement):
    type_desc = 'DIT structure rule'
    detail_attrs = (
        ('Description', 'desc', None),
        ('Associated name form', 'form', NameForm),
        ('Superior structure rules', 'sup', DITStructureRule),
    )

    def display(self):
        web2ldap.app.gui.top_section(
            self._app,
            '%s %s (%s)' % (
                self.type_desc,
                ', '.join(
                    self.se.__dict__.get('names', (()))
                ),
                self.se.ruleid
            ),
            web2ldap.app.gui.main_menu(self._app),
            context_menu_list=schema_context_menu(self._app)
        )
        self._app.outf.write(
            """
            %s
            <h1>%s <em>%s</em> (%s)</h1>
            <dl>
            <dt>Schema element string:</dt>
            <dd><code>%s</code></dd>
            </dl>
            """ % (
                oid_input_form(self._app, ''),
                self.type_desc,
                ", ".join(
                    self.se.__dict__.get('names', (()))
                ),
                self.se.ruleid,
                self._app.form.utf2display(str(self.se).decode(self._app.ls.charset)),
            )
        )
        self.disp_details()
        web2ldap.app.gui.footer(self._app)

    def disp_details(self):
        """
        Display subordinate DIT structure rule(s)
        """
        DisplaySchemaElement.disp_details(self)
        ditsr_rules_ref_list = []
        for ditsr_id, ditsr_se in self.s.sed[DITStructureRule].items():
            if self.sei.ruleid in ditsr_se.sup:
                ditsr_rules_ref_list.append(ditsr_id)
        if ditsr_rules_ref_list:
            self._app.outf.write('<dt>Subordinate DIT structure rules:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, ditsr_rules_ref_list, DITStructureRule))
            ))
        # end of disp_details()


class DisplayNameForm(DisplaySchemaElement):
    type_desc = 'Name form'
    detail_attrs = (
        ('Description', 'desc', None),
        ('Structural object class this rule applies to', 'oc', ObjectClass),
        ('Mandantory naming attributes', 'must', AttributeType),
        ('Allowed naming attributes', 'may', AttributeType),
    )

    def disp_details(self):
        """
        Display referencing DIT structure rule(s)
        """
        DisplaySchemaElement.disp_details(self)
        ditsr_rules_ref_list = []
        for ditsr_id, ditsr_se in self.s.sed[DITStructureRule].items():
            if ditsr_se.form == self.sei.oid or ditsr_se.form in self.sei.names:
                ditsr_rules_ref_list.append(ditsr_id)
        if ditsr_rules_ref_list:
            self._app.outf.write('<dt>Referencing DIT structure rule:</dt>\n<dd>\n%s\n</dd>\n' % (
                ', '.join(schema_anchors(self._app, ditsr_rules_ref_list, DITStructureRule))
            ))
        # end of disp_details()


SCHEMA_VIEWER_CLASS = {
    ObjectClass: DisplayObjectClass,
    AttributeType: DisplayAttributeType,
    LDAPSyntax: DisplayLDAPSyntax,
    MatchingRule: DisplayMatchingRule,
    MatchingRuleUse: DisplayMatchingRuleUse,
    DITContentRule: DisplayDITContentRule,
    DITStructureRule: DisplayDITStructureRule,
    NameForm: DisplayNameForm,
}


def oid_input_form(app, oid=None):
    oid_input_field_html = web2ldap.app.form.OIDInput(
        'oid',
        u'OID or descriptive name of schema element',
        default=oid
    ).inputHTML(oid)
    oid_class_select_html = app.form.field['oid_class'].inputHTML('')
    return app.form_html(
        'oid', 'Search', 'GET',
        [('dn', app.dn)],
        extrastr='\n'.join((oid_input_field_html, oid_class_select_html)),
    )


def display_schema_elements(app, se_classes, se_list):
    se_list = se_list or []
    se_classes = tuple(filter(None, se_classes or []) or SCHEMA_CLASS_MAPPING.values())

    web2ldap.app.gui.top_section(
        app,
        'Schema elements',
        web2ldap.app.gui.main_menu(app),
        context_menu_list=schema_context_menu(app)
    )

    if app.schema is None:
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
                oid_dict[se.__class__] = [se_id]
    else:
        for schema_class in se_classes:
            oid_dict[schema_class] = app.schema.sed[schema_class].keys()
    app.outf.write(oid_input_form(app, ''))

    if oid_dict:
        for schema_class in oid_dict.keys():
            schema_elements = oid_dict[schema_class]
            if not schema_elements:
                continue
            app.outf.write('<h2>%s</h2>\n<p>found %d</p>\n%s\n' % (
                SCHEMA_VIEWER_CLASS[schema_class].type_desc,
                len(schema_elements),
                ',\n '.join(schema_anchors(app, schema_elements, schema_class)),
            ))
    else:
        app.outf.write(SCHEMA_VIEWER_USAGE)
    web2ldap.app.gui.footer(app)
    # end of display_schema_elements()


def w2l_schema_viewer(app):

    def contains_oid(x, oid):
        return x.__contains__(oid)

    def startswith_oid(x, oid):
        return x.startswith(oid)

    def endswith_oid(x, oid):
        return x.endswith(oid)

    # Get input parameter from form input
    oid = app.form.getInputValue('oid', [None])[0]
    se_classes = [
        SCHEMA_CLASS_MAPPING[se_name]
        for se_name in app.form.getInputValue('oid_class', [])
        if se_name
    ]

    if not oid:
        # Display entry page of schema browser
        display_schema_elements(app, se_classes, None)
        return

    # Sanitize oid
    oid = oid.strip()
    if oid.lower().endswith(';binary'):
        oid = oid[:-7]

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

    if len(se_classes) == 1 and cmp_method is None:
        # Display a single schema element referenced by OID and class
        se_list = []
        se_obj = app.schema.get_obj(se_classes[0], oid, None)
        if se_obj is not None:
            se_list.append(se_obj)
    else:
        # Search schema element by OID
        se_list = []
        if cmp_method is None:
            # No wildcard search => just try to look up directly via name or OID
            for schema_element_type in se_classes or SCHEMA_VIEWER_CLASS.keys():
                se = app.schema.get_obj(schema_element_type, oid, None)
                if not se is None:
                    se_list.append(se)
        else:
            # Do a wildcard search
            for schema_element_type in se_classes or SCHEMA_VIEWER_CLASS.keys():
                for se in app.schema.sed[schema_element_type].values():
                    try:
                        se_id = se.oid
                    except AttributeError:
                        se_id = se.ruleid
                    if cmp_method(se_id.lower(), oid_mv):
                        # OID matched
                        se_list.append(se)
                    else:
                        # Look whether a value of NAMEs match
                        try:
                            se_names = se.names
                        except AttributeError:
                            continue
                        for se_name in se_names or []:
                            if cmp_method(se_name.lower(), oid_mv):
                                se_list.append(se)
                                break

    if not se_list:
        # Display error message with input form
        app.simple_message(
            title=u'',
            message='<h1>Schema elements</h1><p class="ErrorMessage">Name or OID not found in schema!</p><p>%s</p>' % (
                oid_input_form(app, oid)
            ),
            main_div_id='Message',
            main_menu_list=web2ldap.app.gui.main_menu(app),
            context_menu_list=schema_context_menu(app)
        )
        return
    if len(se_list) > 1:
        # Display a list of schema elements to choose from
        display_schema_elements(app, None, se_list)
        return

    # Directly display a single schema element
    se_obj = se_list[0]
    if se_obj.__class__ not in SCHEMA_VIEWER_CLASS:
        raise web2ldap.app.core.ErrorExit(u'No viewer for this type of schema element!')
    schema_viewer = SCHEMA_VIEWER_CLASS[se_obj.__class__](app, se_obj)
    schema_viewer.display()
