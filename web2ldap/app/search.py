# -*- coding: utf-8 -*-
"""
web2ldap.app.search: do a search and return results in several formats

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import time
import csv
import urllib.parse
import binascii

import xlwt

import ldap0
import ldap0.cidict
import ldap0.filter
import ldap0.schema.models
from ldap0.controls.openldap import SearchNoOpControl
from ldap0.schema.models import AttributeType
from ldap0.base import decode_list
from ldap0.res import SearchReference, SearchResultEntry

from ..__about__ import __version__
from ..web import escape_html
from ..ldaputil import asynch
from ..ldaputil.extldapurl import ExtendedLDAPUrl
from ..ldapsession import LDAPLimitErrors
from ..msbase import GrabKeys, CaseinsensitiveStringKeyDict
from ..web.wsgi import WSGIBytesWrapper
from . import ErrorExit

from .form import ExportFormatSelect, InclOpAttrsCheckbox
from .entry import DisplayEntry
from .schema.syntaxes import syntax_registry
from .searchform import (
    w2l_searchform,
    SEARCH_OPT_ATTR_EXISTS,
    SEARCH_OPT_ATTR_NOT_EXISTS,
    SEARCH_SCOPE_STR_ONELEVEL,
)
from .gui import (
    footer,
    gen_headers,
    main_menu,
    top_section,
)

SEARCH_NOOP_TIMEOUT = 5.0

SEARCH_BOOKMARK_TMPL = """
<a
  href="{baseUrl}?{ldapUrl}"
  target="_blank"
  rel="bookmark"
  title="Bookmark for these search results"
>
  Bookmark
</a>
"""

PAGE_COMMAND_TMPL = """
<nav><table>
  <tr>
    <td width="20%">{0}</td>
    <td width="20%">{1}</td>
    <td width="20%">{2}</td>
    <td width="20%">{3}</td>
    <td width="20%">{4}</td>
  </tr>
</table></nav>
"""

LDAPERROR_SIZELIMIT_MSG = """
<p class="ErrorMessage">
  <strong>
    Only partial results received. Try to refine search.
  </strong><br>
  {error_msg}
</p>
"""

LDIF1_HEADER = r"""########################################################################
# LDIF export by web2ldap %s, see https://www.web2ldap.de
# Date and time: %s
# Bind-DN: %s
# LDAP-URL of search:
# %s
########################################################################
version: 1

"""

is_search_result = {
    ldap0.RES_SEARCH_ENTRY,
    ldap0.RES_SEARCH_RESULT,
}

is_search_reference = {
    ldap0.RES_SEARCH_REFERENCE,
}


class excel_semicolon(csv.excel):
    """Describe the usual properties of Excel-generated TAB-delimited files."""
    delimiter = ';'

csv.register_dialect('excel-semicolon', excel_semicolon)


class LDIFWriter(asynch.LDIFWriter):

    def pre_processing(self):
        return

    def after_first(self):
        self._ldif_writer._output_file.set_headers(
            gen_headers(
                content_type='text/plain',
                charset='utf-8',
                more_headers=[
                    ('Content-Disposition', 'inline; filename=web2ldap-export.ldif'),
                ]
            )
        )
        asynch.LDIFWriter.pre_processing(self)


class PrintableHTMLWriter(asynch.List):
    """
    Class for writing a stream LDAP search results to a printable file
    """
    _entryResultTypes = is_search_result

    def __init__(self, app, dn, sub_schema, print_template_str_dict):
        asynch.List.__init__(self, app.ls.l)
        self._app = app
        self._dn = dn
        self._s = sub_schema
        self._p = print_template_str_dict

    def process_results(self, ignoreResultsNumber=0, processResultsCount=0):
        asynch.List.process_results(self)
        #self.allResults.sort()
        # This should speed up things
        s2d = self._app.form.s2d
        print_cols = self._app.cfg_param('print_cols', '4')
        table = []
        for r in self.allResults:
            if not isinstance(r, SearchResultEntry):
                continue
            objectclasses = r.entry_s.get('objectclass', r.entry_s.get('objectClass', []))
            template_oc = list(
                {o.lower() for o in objectclasses} & {s.lower() for s in self._p.keys()}
            )
            if template_oc:
                tableentry = CaseinsensitiveStringKeyDict(default='')
                attr_list = r.entry_s.keys()
                for attr in attr_list:
                    tableentry[attr] = ', '.join([
                        s2d(attr_value)
                        for attr_value in r.entry_s[attr]
                    ])
                table.append(self._p[template_oc[0]] % (tableentry))
        # Output search results as pretty-printable table without buttons
        top_section(self._app, 'Printable Search Results', [])
        self._app.outf.write(
            """
            <table
              class="PrintSearchResults"
              rules="rows"
              id="PrintTable"
              summary="Table with search results formatted for printing">
            """
        )
        for i in range(0, len(table), print_cols):
            td_list = [
                '<td>%s</td>' % (tc)
                for tc in table[i:i+print_cols]
            ]
            self._app.outf.write('<tr>\n%s</tr>\n' % ('\n'.join(td_list)))
        self._app.outf.write('</table>\n')
        footer(self._app)
        # end of process_results()


class CSVWriter(asynch.AsyncSearchHandler):
    """
    Class for writing a stream LDAP search results to a CSV file
    """
    _entryResultTypes = is_search_result
    _formular_prefixes = frozenset('@+-=|%')

    def __init__(self, l, f, sub_schema, attr_types, ldap_charset='utf-8'):
        asynch.AsyncSearchHandler.__init__(self, l)
        self._output_file = f
        self._csv_writer = csv.writer(f, dialect='excel-semicolon')
        self._s = sub_schema
        self._attr_types = attr_types
        self._ldap_charset = ldap_charset

    def after_first(self):
        self._output_file.set_headers(
            gen_headers(
                content_type='text/csv',
                charset='utf-8',
                more_headers=[
                    ('Content-Disposition', 'inline; filename=web2ldap-export.csv'),
                ]
            )
        )
        self._csv_writer.writerow(self._attr_types)

    def _process_result(self, resultItem):
        if not isinstance(resultItem, SearchResultEntry):
            return
        entry = ldap0.schema.models.Entry(self._s, resultItem.dn_s, resultItem.entry_as)
        csv_row_list = []
        for attr_type in self._attr_types:
            csv_col_value_list = []
            for attr_value in entry.get(attr_type, [b'']):
                try:
                    csv_col_value = attr_value.decode(self._ldap_charset)
                except UnicodeError:
                    csv_col_value = binascii.b2a_base64(attr_value).decode('ascii').replace('\r', '').replace('\n', '')
                if csv_col_value and csv_col_value[0] in self._formular_prefixes:
                    csv_col_value_list.append("'"+csv_col_value)
                else:
                    csv_col_value_list.append(csv_col_value)
            csv_row_list.append('|'.join(csv_col_value_list))
        self._csv_writer.writerow(csv_row_list)


class ExcelWriter(asynch.AsyncSearchHandler):
    """
    Class for writing a stream LDAP search results to a Excel file
    """
    _entryResultTypes = is_search_result

    def __init__(self, l, f, sub_schema, attr_types, ldap_charset='utf-8'):
        asynch.AsyncSearchHandler.__init__(self, l)
        self._f = f
        self._s = sub_schema
        self._attr_types = attr_types
        self._ldap_charset = ldap_charset
        self._workbook = xlwt.Workbook(encoding='cp1251')
        self._worksheet = self._workbook.add_sheet('web2ldap_export')
        self._row_counter = 0

    def after_first(self):
        self._f.set_headers(
            gen_headers(
                content_type='application/vnd.ms-excel',
                charset='utf-8',
                more_headers=[
                    ('Content-Disposition', 'inline; filename=web2ldap-export.xls'),
                ]
            )
        )
        for col in range(len(self._attr_types)):
            self._worksheet.write(0, col, self._attr_types[col])
        self._row_counter += 1

    def post_processing(self):
        self._workbook.save(self._f)

    def _process_result(self, resultItem):
        if not isinstance(resultItem, SearchResultEntry):
            return
        entry = ldap0.schema.models.Entry(self._s, resultItem.dn_s, resultItem.entry_as)
        csv_row_list = []
        for attr_type in self._attr_types:
            csv_col_value_list = []
            for attr_value in entry.get(attr_type, [b'']):
                try:
                    csv_col_value = attr_value.decode(self._ldap_charset)
                except UnicodeError:
                    csv_col_value = binascii.b2a_base64(attr_value).decode('ascii').replace('\r', '').replace('\n', '')
                csv_col_value_list.append(csv_col_value)
            csv_row_list.append('\r\n'.join(csv_col_value_list))
        for col, val in enumerate(csv_row_list):
            self._worksheet.write(self._row_counter, col, val)
        self._row_counter += 1


def w2l_search(app):
    """
    Search for entries and output results as table, pretty-printable output
    or LDIF formatted
    """

    def page_appl_anchor(
            app,
            link_text,
            search_root, filterstr, search_output,
            search_resminindex, search_resnumber,
            search_lastmod,
            num_result_all,
        ):
        display_start_num = search_resminindex+1
        display_end_num = search_resminindex + search_resnumber
        if num_result_all is not None:
            display_end_num = min(display_end_num, num_result_all)
        if not search_resnumber:
            link_title = u'Display all search results'
        else:
            link_title = u'Display search results %d to %d' % (display_start_num, display_end_num)
        return app.anchor(
            'search',
            link_text.format(display_start_num, display_end_num),
            [
                ('dn', app.dn),
                ('search_root', search_root),
                ('filterstr', filterstr),
                ('search_output', search_output),
                ('search_resminindex', str(search_resminindex)),
                ('search_resnumber', str(search_resnumber)),
                ('search_lastmod', str(search_lastmod)),
                ('scope', str(scope)),
                ('search_attrs', u','.join(search_attrs)),
            ],
            title=link_title,
        )
        # end of page_appl_anchor()

    scope = app.ldap_url.scope
    filterstr = app.ldap_url.filterstr

    search_submit = app.form.getInputValue('search_submit', [u'Search'])[0]
    searchform_mode = app.form.getInputValue('searchform_mode', [u'exp'])[0]

    if search_submit != u'Search' and searchform_mode == 'adv':
        w2l_searchform(
            app,
            Msg='',
            filterstr=u'',
            scope=scope
        )
        return

    # This should speed up things
    s2d = app.form.s2d

    search_output = app.form.getInputValue('search_output', ['table'])[0]
    search_opattrs = app.form.getInputValue('search_opattrs', ['no'])[0] == 'yes'
    search_root = app.form.getInputValue('search_root', [app.dn])[0]

    if scope is None:
        scope = ldap0.SCOPE_SUBTREE

    search_filter = app.form.getInputValue('filterstr', [filterstr])

    search_mode = app.form.getInputValue('search_mode', [u'(&%s)'])[0]
    search_option = app.form.getInputValue('search_option', [])
    search_attr = app.form.getInputValue('search_attr', [])
    search_mr = app.form.getInputValue('search_mr', [None]*len(search_attr))
    search_string = app.form.getInputValue('search_string', [])

    if not len(search_option) == len(search_attr) == len(search_mr) == len(search_string):
        raise ErrorExit(u'Invalid search form data.')

    # Build LDAP search filter from input data of advanced search form
    for i in range(len(search_attr)):
        if not search_attr[i]:
            # Ignore null-string attribute types
            continue
        search_av_string = search_string[i]
        if not '*' in search_option[i]:
            # If an exact assertion value is needed we can normalize via plugin class
            attr_instance = syntax_registry.get_at(
                app, app.dn, app.schema, search_attr[i], None, entry=None
            )
            search_av_string = attr_instance.sanitize(search_av_string.encode(app.ls.charset)).decode(app.ls.charset)
        if search_mr[i]:
            search_mr_string = ':%s:' % (search_mr[i])
        else:
            search_mr_string = ''
        if search_av_string or \
           search_option[i] in {SEARCH_OPT_ATTR_EXISTS, SEARCH_OPT_ATTR_NOT_EXISTS}:
            search_filter.append(search_option[i].format(
                at=''.join((search_attr[i], search_mr_string)),
                av=ldap0.filter.escape_str(search_av_string)
            ))

    # Wipe out all nullable search_filter list items
    search_filter = list(filter(None, search_filter))

    if not search_filter:
        w2l_searchform(
            app,
            Msg='Empty search values.',
            filterstr=u'',
            scope=scope
        )
        return
    if len(search_filter) == 1:
        filterstr = search_filter[0]
    elif len(search_filter) > 1:
        filterstr = search_mode % (u''.join(search_filter))

    search_resminindex = int(app.form.getInputValue('search_resminindex', ['0'])[0])
    search_resnumber = int(
        app.form.getInputValue(
            'search_resnumber',
            [str(app.cfg_param('search_resultsperpage', 10))]
        )[0]
    )

    search_lastmod = int(app.form.getInputValue('search_lastmod', [-1])[0])
    if search_lastmod > 0:
        timestamp_str = time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()-search_lastmod))
        if '1.2.840.113556.1.2.2' in app.schema.sed[AttributeType] and \
           '1.2.840.113556.1.2.3' in app.schema.sed[AttributeType]:
            # Assume we're searching MS Active Directory
            filterstr2 = u'(&(|(whenCreated>=%s.0Z)(whenChanged>=%s.0Z))%s)' % (
                timestamp_str, timestamp_str, filterstr,
            )
        else:
            # Assume standard LDAPv3 attributes
            filterstr2 = u'(&(|(createTimestamp>=%sZ)(modifyTimestamp>=%sZ))%s)' % (
                timestamp_str, timestamp_str, filterstr,
            )
    else:
        filterstr2 = filterstr

    requested_attrs = app.cfg_param('requested_attrs', [])

    search_attrs = [
        a.strip()
        for a in app.form.getInputValue(
            'search_attrs',
            [u','.join(app.ldap_url.attrs or [])]
        )[0].split(u',')
        if a.strip()
    ]

    search_attr_set = ldap0.schema.models.SchemaElementOIDSet(app.schema, AttributeType, search_attrs)
    search_attrs = search_attr_set.names

    search_ldap_url = app.ls.ldap_url(dn=search_root or str(app.naming_context))
    search_ldap_url.filterstr = filterstr2
    search_ldap_url.scope = scope
    search_ldap_url.attrs = search_attrs

    ldap_search_command = search_ldap_url.ldapsearch_cmd()

    read_attr_set = ldap0.schema.models.SchemaElementOIDSet(app.schema, AttributeType, search_attrs)
    if search_output in {'table', 'print'}:
        read_attr_set.add('objectClass')

    if search_output == 'print':
        print_template_filenames_dict = app.cfg_param('print_template', None)
        if print_template_filenames_dict is None:
            raise ErrorExit(u'No templates for printing defined.')
        print_template_str_dict = CaseinsensitiveStringKeyDict()
        for oc in print_template_filenames_dict.keys():
            try:
                with open(print_template_filenames_dict[oc], 'r') as template_file:
                    print_template_str_dict[oc] = template_file.read()
            except IOError:
                pass
            else:
                read_attr_set.update(GrabKeys(print_template_str_dict[oc]).keys)
        read_attrs = read_attr_set.names
        result_handler = PrintableHTMLWriter(app, search_root, app.schema, print_template_str_dict)

    elif search_output in {'table', 'raw'}:

        search_tdtemplate = ldap0.cidict.CIDict(app.cfg_param('search_tdtemplate', {}))
        search_tdtemplate_keys = search_tdtemplate.keys()
        search_tdtemplate_attrs_lower = ldap0.cidict.CIDict()
        for oc in search_tdtemplate_keys:
            search_tdtemplate_attrs_lower[oc] = GrabKeys(search_tdtemplate[oc]).keys

        # Start with operational attributes used to determine subordinate
        # entries existence/count
        read_attr_set.update([
            'subschemaSubentry', 'displayName', 'description', 'structuralObjectClass',
            'hasSubordinates', 'subordinateCount',
            'numSubordinates',
            'numAllSubordinates', #  Siemens DirX
            'countImmSubordinates', 'countTotSubordinates', # Critical Path Directory Server
            'msDS-Approx-Immed-Subordinates' # MS Active Directory
        ])

        # Extend with list of attributes to read for displaying results with templates
        if search_output == 'table':
            for oc in search_tdtemplate_keys:
                read_attr_set.update(GrabKeys(search_tdtemplate[oc]).keys)
        read_attr_set.discard('entryDN')
        read_attrs = read_attr_set.names

        # Create async search handler instance
        result_handler = asynch.List(app.ls.l)

    elif search_output in {'ldif', 'ldif1'}:
        # read all attributes
        read_attrs = (
            search_attrs
            or {False:('*',), True:('*', '+')}[app.ls.supportsAllOpAttr and search_opattrs]+requested_attrs
            or None
        )
        result_handler = LDIFWriter(app.ls.l, WSGIBytesWrapper(app.outf))
        if search_output == 'ldif1':
            result_handler.header = LDIF1_HEADER % (
                __version__,
                time.strftime(
                    '%A, %Y-%m-%d %H:%M:%S GMT',
                    time.gmtime(time.time())
                ),
                repr(app.ls.who),
                str(search_ldap_url),
            )

    elif search_output in {'csv', 'excel'}:

        read_attrs = [a for a in search_attrs if not a in {'*', '+'}]
        if not read_attrs:
            if searchform_mode == u'base':
                searchform_mode = u'adv'
            w2l_searchform(
                app,
                Msg='For table-structured export you have to define the attributes to be read!',
                filterstr=filterstr,
                scope=scope,
                search_root=search_root,
                searchform_mode=searchform_mode,
            )
            return
        if search_output == 'csv':
            result_handler = CSVWriter(app.ls.l, app.outf, app.schema, read_attrs, ldap_charset=app.ls.charset)
        elif search_output == 'excel':
            result_handler = ExcelWriter(app.ls.l, WSGIBytesWrapper(app.outf), app.schema, read_attrs, ldap_charset=app.ls.charset)

    if search_resnumber:
        search_size_limit = search_resminindex+search_resnumber
    else:
        search_size_limit = -1

    try:
        # Start the search
        result_handler.start_search(
            search_root,
            scope,
            filterstr2,
            attrList=read_attrs or None,
            sizelimit=search_size_limit
        )
    except (
            ldap0.FILTER_ERROR,
            ldap0.INAPPROPRIATE_MATCHING,
        ) as e:
        # Give the user a chance to edit his bad search filter
        w2l_searchform(
            app,
            Msg=' '.join((
                app.ldap_error_msg(e),
                s2d(filterstr2),
            )),
            filterstr=filterstr,
            scope=scope
        )
        return
    except ldap0.NO_SUCH_OBJECT as e:
        if app.dn:
            raise e

    if search_output in {'table', 'raw'}:

        SearchWarningMsg = ''
        max_result_msg = ''
        num_all_search_results, num_all_search_continuations = None, None
        num_result_all = None
        partial_results = 0

        try:
            result_handler.process_results(
                search_resminindex, search_resnumber+int(search_resnumber > 0)
            )
        except (ldap0.SIZELIMIT_EXCEEDED, ldap0.ADMINLIMIT_EXCEEDED) as e:
            if search_size_limit < 0 or result_handler.endResultBreak < search_size_limit:
                SearchWarningMsg = app.ldap_error_msg(e, template=LDAPERROR_SIZELIMIT_MSG)
            partial_results = 1
            resind = result_handler.endResultBreak
            # Retrieve the overall number of search results by resending the
            # search request without size limit but with the SearchNoOpControl attached
            if SearchNoOpControl.controlType in app.ls.supportedControl:
                try:
                    num_all_search_results, num_all_search_continuations = app.ls.l.noop_search(
                        search_root,
                        scope,
                        filterstr=filterstr2,
                        timeout=SEARCH_NOOP_TIMEOUT,
                    )
                    if num_all_search_results is not None and num_all_search_continuations is not None:
                        num_result_all = num_all_search_results + num_all_search_continuations
                        max_result_msg = '(of %d / %d) ' % (num_all_search_results, num_all_search_continuations)
                except LDAPLimitErrors:
                    pass
        except (ldap0.FILTER_ERROR, ldap0.INAPPROPRIATE_MATCHING) as e:
            # Give the user a chance to edit his bad search filter
            w2l_searchform(
                app,
                Msg=app.ldap_error_msg(e),
                filterstr=filterstr,
                scope=scope
            )
            return
        except (ldap0.NO_SUCH_OBJECT, ldap0.UNWILLING_TO_PERFORM) as e:
            resind = result_handler.endResultBreak
            if search_root or scope != ldap0.SCOPE_ONELEVEL:
                # Give the user a chance to edit his bad search filter
                w2l_searchform(
                    app,
                    Msg=app.ldap_error_msg(e),
                    filterstr=filterstr,
                    scope=scope
                )
                return
        else:
            partial_results = search_size_limit >= 0 and result_handler.endResultBreak > search_size_limit
            resind = result_handler.endResultBreak

        search_resminindex = result_handler.beginResultsDropped
        result_dnlist = result_handler.allResults

        # HACK! Searching the root level the namingContexts is
        # appended if not already received in search result
        if not search_root and not result_dnlist and scope == ldap0.SCOPE_ONELEVEL:
            result_dnlist.extend([
                SearchResultEntry(result_dn.encode(app.ls.charset), {})
                for result_dn in app.ls.namingContexts
            ])
            resind = len(result_dnlist)

#        result_dnlist.sort(key=lambda x: x.dn_s)

        ContextMenuList = [
            app.anchor(
                'searchform', 'Edit Filter',
                [
                    ('dn', app.dn),
                    ('searchform_mode', 'exp'),
                    ('search_root', search_root),
                    ('filterstr', filterstr),
                    ('search_lastmod', str(search_lastmod)),
                    ('search_attrs', ','.join(search_attrs)),
                    ('scope', str(scope)),
                ],
            ),
            app.anchor(
                'search', 'Negate search',
                [
                    ('dn', app.dn),
                    ('search_root', search_root),
                    ('search_output', {False:'raw', True:'table'}[search_output == 'table']),
                    ('scope', str(scope)),
                    ('filterstr', ldap0.filter.negate_filter(filterstr)),
                    ('search_resminindex', str(search_resminindex)),
                    ('search_resnumber', str(search_resnumber)),
                    ('search_lastmod', str(search_lastmod)),
                    ('search_attrs', u','.join(search_attrs)),
                ],
                title=u'Search with negated search filter',
            ),
        ]

        if searchform_mode in {'base', 'adv'}:
            ContextMenuList.append(
                app.anchor(
                    'searchform', 'Modify Search',
                    app.form.allInputFields(
                        fields=[
                            ('dn', app.dn),
                            ('searchform_mode', 'adv')
                        ],
                        ignore_fields=('dn', 'searchform_mode'),
                    ),
                    title=u'Modify search parameters',
                )
            )

        search_param_html = """
            <table>
              <tr>
                <td>Scope:</td>
                <td>%s</td>
              </tr>
              <tr>
                <td>Base DN:</td>
                <td>%s</td>
              </tr>
              <tr>
                <td>Filter string:</td>
                <td>%s</td>
              </tr>
            </table>
            """ % (
                ldap0.ldapurl.SEARCH_SCOPE_STR[scope],
                s2d(search_root),
                s2d(filterstr2),
            )

        if not result_dnlist:

            # Empty search results
            #--------------------------------------------------
            app.simple_message(
                'No Search Results',
                '<p class="WarningMessage">No entries found.</p>%s' % (search_param_html),
                main_menu_list=main_menu(app),
                context_menu_list=ContextMenuList
            )

        else:

            # There are search results to be displayed
            #--------------------------------------------------

            page_command_list = None

            ContextMenuList.extend([
                app.anchor(
                    'search',
                    {False:'Raw', True:'Table'}[search_output == 'raw'],
                    [
                        ('dn', app.dn),
                        ('search_root', search_root),
                        ('search_output', {False:'raw', True:'table'}[search_output == 'raw']),
                        ('scope', str(scope)),
                        ('filterstr', filterstr),
                        ('search_resminindex', str(search_resminindex)),
                        ('search_resnumber', str(search_resnumber)),
                        ('search_lastmod', str(search_lastmod)),
                        ('search_attrs', u','.join(search_attrs)),
                    ],
                    title=u'Display %s of search results' % (
                        {False:u'distinguished names', True:u'attributes'}[search_output == 'raw']
                    ),
                ),
                app.anchor(
                    'delete', 'Delete',
                    [
                        ('dn', search_root),
                        ('filterstr', filterstr2),
                        ('scope', str(scope)),
                    ],
                ),
                app.anchor(
                    'bulkmod', 'Bulk modify',
                    [
                        ('dn', search_root),
                        ('filterstr', filterstr2),
                        ('scope', str(scope)),
                    ],
                ),
            ])

            if (partial_results and search_size_limit > 0) or search_resminindex:

                page_command_list = 5 * ['&nbsp;']
                prev_resminindex = max(0, search_resminindex-search_resnumber)

                if search_resminindex > search_resnumber:
                    page_command_list[0] = page_appl_anchor(
                        app,
                        '|&larr;{0}…{1}',
                        search_root, filterstr, search_output,
                        0, search_resnumber,
                        search_lastmod, num_result_all,
                    )

                if search_resminindex > 0:
                    page_command_list[1] = page_appl_anchor(
                        app,
                        '&larr;{0}…{1}',
                        search_root, filterstr, search_output,
                        max(0, prev_resminindex), search_resnumber,
                        search_lastmod, num_result_all,
                    )

                page_command_list[2] = page_appl_anchor(
                    app,
                    'all',
                    search_root, filterstr, search_output,
                    0, 0,
                    search_lastmod, num_result_all,
                )

                if partial_results:

                    page_next_link = page_appl_anchor(
                        app,
                        '{0}…{1}&rarr;',
                        search_root, filterstr, search_output,
                        search_resminindex+search_resnumber, search_resnumber,
                        search_lastmod, num_result_all,
                    )

                    if num_result_all is not None and resind < num_result_all:
                        page_command_list[3] = page_next_link
                        page_command_list[4] = page_appl_anchor(
                            app,
                            '{0}…{1}&rarr;|',
                            search_root, filterstr, search_output,
                            num_result_all-search_resnumber, search_resnumber,
                            search_lastmod, num_result_all,
                        )
                    elif search_resminindex+search_resnumber <= resind:
                        page_command_list[3] = page_next_link

            search_bookmark = SEARCH_BOOKMARK_TMPL.format(
                baseUrl=escape_html(app.form.script_name),
                ldapUrl=str(search_ldap_url),
            )
            result_message = '\n<p>Search results %d - %d %s / <a href="#params" title="See search parameters and export options">Params</a> / %s</p>\n' % (
                search_resminindex+1,
                resind,
                max_result_msg,
                search_bookmark,
            )

            top_section(app, 'Search Results', main_menu(app), context_menu_list=ContextMenuList)

            export_field = ExportFormatSelect()
            export_field.charset = app.form.accept_charset

            app.outf.write('\n'.join((SearchWarningMsg, result_message)))

            if search_resminindex == 0 and not partial_results:
                mailtolist = set()
                for r in result_dnlist:
                    if isinstance(r, SearchResultEntry):
                        mailtolist.update(r.entry_s.get('mail', r.entry_s.get('rfc822Mailbox', [])))
                if mailtolist:
                    mailtolist = [urllib.parse.quote(m) for m in mailtolist]
                    app.outf.write('Mail to all <a href="mailto:%s?cc=%s">Cc:-ed</a> - <a href="mailto:?bcc=%s">Bcc:-ed</a>' % (
                        mailtolist[0],
                        ','.join(mailtolist[1:]),
                        ','.join(mailtolist)
                    ))

            if page_command_list:
                # output the paging links
                app.outf.write(PAGE_COMMAND_TMPL.format(*page_command_list))

            app.outf.write('<table id="SrchResList">\n')

            for r in result_dnlist[0:resind]:

                if isinstance(r, SearchReference):

                    # Display a search continuation (search reference)
                    entry = ldap0.cidict.CIDict({})
                    try:
                        refUrl = ExtendedLDAPUrl(r.ref_url_strings[0])
                    except ValueError:
                        command_table = []
                        result_dd_str = 'Search reference (NON-LDAP-URI) =&gt; %s' % (s2d(str(r[1][1][0])))
                    else:
                        result_dd_str = 'Search reference =&gt; %s' % (refUrl.htmlHREF(hrefTarget=None))
                        if scope == ldap0.SCOPE_SUBTREE:
                            refUrl.scope = refUrl.scope or scope
                            refUrl.filterstr = ((refUrl.filterstr or '') or filterstr)
                            command_table = [
                                app.anchor(
                                    'search', 'Continue search',
                                    [('ldapurl', refUrl.unparse())],
                                    title=u'Follow this search continuation',
                                )
                            ]
                        else:
                            command_table = []
                            refUrl.filterstr = filterstr
                            refUrl.scope = ldap0.SCOPE_BASE
                            command_table.append(app.anchor(
                                'read', 'Read',
                                [('ldapurl', refUrl.unparse())],
                                title=u'Display single entry following search continuation',
                            ))
                            refUrl.scope = ldap0.SCOPE_ONELEVEL
                            command_table.append(app.anchor(
                                'search', 'Down',
                                [('ldapurl', refUrl.unparse())],
                                title=u'Descend into tree following search continuation',
                            ))

                elif isinstance(r, SearchResultEntry):

                    # Display a search result with entry's data
                    entry = ldap0.schema.models.Entry(app.schema, r.dn_s, r.entry_as)

                    if search_output == 'raw':

                        # Output DN
                        result_dd_str = s2d(r.dn_s)

                    else:

                        oc_set = ldap0.schema.models.SchemaElementOIDSet(
                            app.schema,
                            ldap0.schema.models.ObjectClass,
                            decode_list(entry.get('objectClass', []), encoding='ascii'),
                        )
                        tdtemplate_oc = oc_set.intersection(search_tdtemplate_keys).names
                        tableentry_attrs = None

                        if tdtemplate_oc:
                            template_attrs = ldap0.schema.models.SchemaElementOIDSet(
                                app.schema,
                                AttributeType,
                                [],
                            )
                            for oc in tdtemplate_oc:
                                template_attrs.update(search_tdtemplate_attrs_lower[oc])
                            tableentry_attrs = template_attrs.intersection(entry.keys())

                        if tableentry_attrs:
                            # Output entry with the help of pre-defined templates
                            tableentry = DisplayEntry(
                                app, r.dn_s, app.schema, entry, 'search_sep', False
                            )
                            tdlist = []
                            for oc in tdtemplate_oc:
                                tdlist.append(search_tdtemplate[oc] % tableentry)
                            result_dd_str = '<br>\n'.join(tdlist)

                        elif 'displayName' in entry:
                            result_dd_str = s2d(app.ls.uc_decode(entry['displayName'][0])[0])

                        else:
                            # Output DN
                            result_dd_str = s2d(r.dn_s)

                    # Build the list for link table
                    command_table = []

                    # A [Read] link is added in any case
                    command_table.append(
                        app.anchor(
                            'read', 'Read',
                            [('dn', r.dn_s)],
                        )
                    )

                    # Try to determine from entry's attributes if there are subordinates
                    hasSubordinates = entry.get('hasSubordinates', [b'TRUE'])[0].upper() == b'TRUE'
                    try:
                        subordinateCountFlag = int(
                            entry.get(
                                'subordinateCount',
                                entry.get(
                                    'numAllSubordinates',
                                    entry.get('msDS-Approx-Immed-Subordinates', [b'1'])))[0]
                        )
                    except ValueError:
                        subordinateCountFlag = 1

                    # If subordinates or unsure a [Down] link is added
                    if hasSubordinates and subordinateCountFlag > 0:

                        down_title_list = [u'List direct subordinates of %s' % (r.dn_s)]

                        # Determine number of direct subordinates
                        numSubOrdinates = entry.get(
                            'numSubOrdinates',
                            entry.get(
                                'subordinateCount',
                                entry.get(
                                    'countImmSubordinates',
                                    entry.get(
                                        'msDS-Approx-Immed-Subordinates',
                                        [None]))))[0]
                        if numSubOrdinates is not None:
                            numSubOrdinates = int(numSubOrdinates)
                            down_title_list.append('direct: %d' % (numSubOrdinates))
                        # Determine total number of subordinates
                        numAllSubOrdinates = entry.get(
                            'numAllSubOrdinates',
                            entry.get('countTotSubordinates', [None])
                        )[0]
                        if numAllSubOrdinates is not None:
                            numAllSubOrdinates = int(numAllSubOrdinates)
                            down_title_list.append(u'total: %d' % (numAllSubOrdinates))

                        command_table.append(app.anchor(
                            'search', 'Down',
                            (
                                ('dn', r.dn_s),
                                ('scope', SEARCH_SCOPE_STR_ONELEVEL),
                                ('searchform_mode', u'adv'),
                                ('search_attr', u'objectClass'),
                                ('search_option', SEARCH_OPT_ATTR_EXISTS),
                                ('search_string', ''),
                            ),
                            title=u'\r\n'.join(down_title_list),
                        ))

                else:
                    raise ValueError('LDAP result of invalid type: %r' % (r,))

                # write the search result table row
                app.outf.write(
                    '<tr><td class="CT">{0}</td><td>{1}</td></tr>\n'.format(
                        ''.join(command_table),
                        result_dd_str
                    )
                )

            app.outf.write(
                """
                </table>
                <a id="params"></a>
                %s
                  <h3>Export to other formats</h3>
                  <p>%s &nbsp; Include operational attributes %s</p>
                  <p><input type="submit" value="Export"></p>
                </form>
                """ % (
                    '\n'.join((
                        app.begin_form('search', 'GET', target='web2ldapexport'),
                        app.form.hiddenFieldHTML('dn', app.dn, u''),
                        app.form.hiddenFieldHTML('search_root', search_root, u''),
                        app.form.hiddenFieldHTML('scope', str(scope), u''),
                        app.form.hiddenFieldHTML('filterstr', filterstr, u''),
                        app.form.hiddenFieldHTML('search_lastmod', str(search_lastmod), u''),
                        app.form.hiddenFieldHTML('search_resnumber', u'0', u''),
                        app.form.hiddenFieldHTML('search_attrs', u','.join(search_attrs), u''),
                    )),
                    export_field.input_html(),
                    InclOpAttrsCheckbox().input_html(),
                )
            )

            app.outf.write(
                """
                <h3>Search parameters used</h3>
                %s
                <p>
                  Equivalent OpenLDAP command:<br>
                  <input value="%s" size="60" readonly>
                </p>
                """ % (
                    search_param_html,
                    s2d(ldap_search_command),
                )
            )

            footer(app)


    else:

        try:
            result_handler.process_results()
        except (
                ldap0.SIZELIMIT_EXCEEDED,
                ldap0.ADMINLIMIT_EXCEEDED,
            ):
            result_handler.post_processing()
