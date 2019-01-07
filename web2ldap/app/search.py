# -*- coding: utf-8 -*-
"""
web2ldap.app.search: do a search and return results in several formats

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time
import csv
import urllib

import xlwt

import ldap0
import ldap0.schema.models
from ldap0.controls.openldap import SearchNoOpControl

import web2ldap.web.forms
from web2ldap.web.forms import escapeHTML

import web2ldap.ldaputil.async
import web2ldap.msbase
import web2ldap.ldaputil.base
import web2ldap.app.core
import web2ldap.app.cnf
import web2ldap.app.gui
import web2ldap.app.read
import web2ldap.app.searchform
from web2ldap.ldaputil.extldapurl import ExtendedLDAPUrl
from web2ldap.ldaputil.base import escape_ldap_filter_chars
from web2ldap.msbase import GrabKeys
from web2ldap.app.schema.syntaxes import syntax_registry
from web2ldap.app.searchform import SEARCH_OPT_ATTR_EXISTS, SEARCH_OPT_ATTR_NOT_EXISTS
from web2ldap.ldapsession import LDAPLimitErrors
from web2ldap.msbase import CaseinsensitiveStringKeyDict

import web2ldap.__about__

SEARCH_NOOP_TIMEOUT = 5.0

SizeLimitMsg = """
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


class LDIFWriter(web2ldap.ldaputil.async.LDIFWriter):

    def preProcessing(self):
        return

    def afterFirstResult(self):
        self._ldif_writer._output_file.set_headers(
            web2ldap.app.gui.gen_headers(
                content_type='text/plain',
                charset='utf-8',
                more_headers=[
                    ('Content-Disposition', 'inline; filename=web2ldap-export.ldif'),
                ]
            )
        )
        web2ldap.ldaputil.async.LDIFWriter.preProcessing(self)


class PrintableHTMLWriter(web2ldap.ldaputil.async.List):
    """
    Class for writing a stream LDAP search results to a printable file
    """
    _entryResultTypes = is_search_result

    def __init__(self, sid, outf, form, ls, dn, sub_schema, print_template_str_dict):
        web2ldap.ldaputil.async.List.__init__(self, ls.l)
        self._sid = sid
        self._outf = outf
        self._form = form
        self._ls = ls
        self._dn = dn
        self._s = sub_schema
        self._p = print_template_str_dict
        return # __init__()

    def processResults(self, ignoreResultsNumber=0, processResultsCount=0, timeout=-1):
        web2ldap.ldaputil.async.List.processResults(self, timeout=timeout)
        self.allResults.sort()
        # This should speed up things
        utf2display = self._form.utf2display
        print_cols = web2ldap.app.cnf.GetParam(self._ls, 'print_cols', '4')
        table = []
        for r in self.allResults:
            if r[0] in is_search_result:
                entry = r[1][1]
                objectclasses = entry.get('objectclass', entry.get('objectClass', []))
                template_oc = list(set([o.lower() for o in objectclasses]).intersection(
                    [s.lower() for s in self._p.keys()]
                ))
                if template_oc:
                    tableentry = CaseinsensitiveStringKeyDict(default='')
                    attr_list = entry.keys()
                    for attr in attr_list:
                        tableentry[attr] = ', '.join([
                            utf2display(attr_value.decode(self._ls.charset))
                            for attr_value in entry[attr]
                        ])
                    table.append(self._p[template_oc[0]] % (tableentry))
        # Output search results as pretty-printable table without buttons
        web2ldap.app.gui.TopSection(
            self._sid, self._outf, 'search', self._form, self._ls, self._dn,
            'Printable Search Results', [],
        )
        self._outf.write(
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
            self._outf.write('<tr>\n%s</tr>\n' % ('\n'.join(td_list)))
        self._outf.write('</table>\n')
        web2ldap.app.gui.Footer(self._outf, self._form)
        return # processResults()


class CSVWriter(web2ldap.ldaputil.async.AsyncSearchHandler):
    """
    Class for writing a stream LDAP search results to a CSV file
    """
    _entryResultTypes = is_search_result

    def __init__(self, l, f, sub_schema, attr_types, ldap_charset='utf-8', csv_charset='utf-8'):
        web2ldap.ldaputil.async.AsyncSearchHandler.__init__(self, l)
        self._output_file = f
        self._csv_writer = csv.writer(f, dialect='excel-semicolon')
        self._s = sub_schema
        self._attr_types = attr_types
        self._ldap_charset = ldap_charset
        self._csv_charset = csv_charset

    def afterFirstResult(self):
        self._output_file.set_headers(
            web2ldap.app.gui.gen_headers(
                content_type='text/csv',
                charset='utf-8',
                more_headers=[
                    ('Content-Disposition', 'inline; filename=web2ldap-export.csv'),
                ]
            )
        )
        self._csv_writer.writerow(self._attr_types)

    def _processSingleResult(self, resultType, resultItem):
        if resultType in self._entryResultTypes:
            entry = ldap0.schema.models.Entry(self._s, resultItem[0], resultItem[1])
            csv_row_list = []
            for attr_type in self._attr_types:
                csv_col_value_list = []
                for attr_value in entry.get(attr_type, ['']):
                    try:
                        csv_col_value = attr_value.decode(self._ldap_charset).encode(self._csv_charset)
                    except UnicodeError:
                        csv_col_value = attr_value.encode('base64').replace('\r', '').replace('\n', '')
                    csv_col_value_list.append(csv_col_value)
                csv_row_list.append('|'.join(csv_col_value_list))
            self._csv_writer.writerow(csv_row_list)


class ExcelWriter(web2ldap.ldaputil.async.AsyncSearchHandler):
    """
    Class for writing a stream LDAP search results to a Excel file
    """
    _entryResultTypes = is_search_result

    def __init__(self, l, f, sub_schema, attr_types, ldap_charset='utf-8'):
        web2ldap.ldaputil.async.AsyncSearchHandler.__init__(self, l)
        self._f = f
        self._s = sub_schema
        self._attr_types = attr_types
        self._ldap_charset = ldap_charset
        self._workbook = xlwt.Workbook(encoding='cp1251')
        self._worksheet = self._workbook.add_sheet('web2ldap_export')
        self._row_counter = 0

    def afterFirstResult(self):
        self._f.set_headers(
            web2ldap.app.gui.gen_headers(
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

    def postProcessing(self):
        self._workbook.save(self._f)

    def _processSingleResult(self, resultType, resultItem):
        if resultType in self._entryResultTypes:
            entry = ldap0.schema.models.Entry(self._s, resultItem[0], resultItem[1])
            csv_row_list = []
            for attr_type in self._attr_types:
                csv_col_value_list = []
                for attr_value in entry.get(attr_type, ['']):
                    try:
                        csv_col_value = attr_value.decode(self._ldap_charset)
                    except UnicodeError:
                        csv_col_value = attr_value.encode('base64').replace('\r', '').replace('\n', '').decode('ascii')
                    csv_col_value_list.append(csv_col_value)
                csv_row_list.append('\r\n'.join(csv_col_value_list))
            for col in range(len(csv_row_list)):
                self._worksheet.write(self._row_counter, col, csv_row_list[col])
            self._row_counter += 1


def w2l_Search(sid, outf, command, form, ls, dn, connLDAPUrl):
    """
    Search for entries and output results as table, pretty-printable output
    or LDIF formatted
    """

    def page_appl_anchor(
            sid, form, dn, link_text,
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
        return form.applAnchor(
            'search',
            link_text.format(display_start_num, display_end_num),
            sid,
            [
                ('dn', dn),
                ('search_root', search_root),
                ('filterstr', filterstr),
                ('search_output', search_output),
                ('search_resminindex', unicode(search_resminindex)),
                ('search_resnumber', unicode(search_resnumber)),
                ('search_lastmod', unicode(search_lastmod)),
                ('scope', str(scope)),
                ('search_attrs', u','.join(search_attrs)),
            ],
            title=link_title,
        )
        # end of page_appl_anchor()

    scope = connLDAPUrl.scope
    filterstr = web2ldap.app.core.str2unicode(connLDAPUrl.filterstr, form.accept_charset)

    search_submit = form.getInputValue('search_submit', [u'Search'])[0]
    searchform_mode = form.getInputValue('searchform_mode', [u'exp'])[0]

    if search_submit != u'Search' and searchform_mode == 'adv':
        web2ldap.app.searchform.w2l_SearchForm(
            sid, outf, command, form, ls, dn,
            Msg='',
            filterstr=u'',
            scope=scope
        )
        return

    # This should speed up things
    utf2display = form.utf2display

    search_output = form.getInputValue('search_output', ['table'])[0]
    search_opattrs = form.getInputValue('search_opattrs', ['no'])[0] == 'yes'
    search_root = form.getInputValue('search_root', [dn])[0]

    # Hmm, this retrieves sub schema sub entry for the search root.
    # Theoretically it could be different for all search results.
    # But what the hey...
    sub_schema = ls.retrieveSubSchema(
        dn,
        web2ldap.app.cnf.GetParam(ls, '_schema', None),
        web2ldap.app.cnf.GetParam(ls, 'supplement_schema', None),
        web2ldap.app.cnf.GetParam(ls, 'schema_strictcheck', True),
    )

    if scope is None:
        scope = ldap0.SCOPE_SUBTREE

    search_filter = form.getInputValue('filterstr', [filterstr])

    search_mode = form.getInputValue('search_mode', [ur'(&%s)'])[0]
    search_option = form.getInputValue('search_option', [])
    search_attr = form.getInputValue('search_attr', [])
    search_mr = form.getInputValue('search_mr', [None]*len(search_attr))
    search_string = form.getInputValue('search_string', [])

    if not len(search_option) == len(search_attr) == len(search_mr) == len(search_string):
        raise web2ldap.app.core.ErrorExit(u'Invalid search form data.')

    # Build LDAP search filter from input data of advanced search form
    for i in range(len(search_attr)):
        if not search_attr[i]:
            # Ignore null-string attribute types
            continue
        search_av_string = search_string[i]
        if not '*' in search_option[i]:
            # If an exact assertion value is needed we can normalize via plugin class
            attr_instance = syntax_registry.attrInstance(
                None, form, ls, dn, sub_schema, search_attr[i], None, entry=None
            )
            search_av_string = attr_instance.sanitizeInput(search_av_string.encode(form.accept_charset))
        if search_mr[i]:
            search_mr_string = ':%s:' % (search_mr[i])
        else:
            search_mr_string = ''
        if search_av_string or \
           search_option[i] in {SEARCH_OPT_ATTR_EXISTS, SEARCH_OPT_ATTR_NOT_EXISTS}:
            search_filter.append(search_option[i].format(
                at=''.join((search_attr[i], search_mr_string)),
                av=escape_ldap_filter_chars(search_av_string, ls.charset)
            ))

    # Wipe out all nullable search_filter list items
    search_filter = filter(None, search_filter)

    if not search_filter:
        web2ldap.app.searchform.w2l_SearchForm(
            sid, outf, command, form, ls, dn,
            Msg='Empty search values.',
            filterstr=u'',
            scope=scope
        )
        return
    elif len(search_filter) == 1:
        filterstr = search_filter[0]
    elif len(search_filter) > 1:
        filterstr = search_mode % (u''.join(search_filter))

    search_resminindex = int(form.getInputValue('search_resminindex', ['0'])[0])
    search_resnumber = int(
        form.getInputValue(
            'search_resnumber',
            [unicode(web2ldap.app.cnf.GetParam(ls, 'search_resultsperpage', 10))]
        )[0]
    )

    search_lastmod = int(form.getInputValue('search_lastmod', [-1])[0])
    if search_lastmod > 0:
        timestamp_str = unicode(time.strftime('%Y%m%d%H%M%S', time.gmtime(time.time()-search_lastmod)), 'ascii')
        if sub_schema.sed[ldap0.schema.models.AttributeType].has_key('1.2.840.113556.1.2.2') and \
           sub_schema.sed[ldap0.schema.models.AttributeType].has_key('1.2.840.113556.1.2.3'):
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

    requested_attrs = web2ldap.app.cnf.GetParam(ls, 'requested_attrs', [])

    search_attrs = [
        a.strip().encode('ascii')
        for a in form.getInputValue(
            'search_attrs',
            [u','.join(connLDAPUrl.attrs or [])]
        )[0].split(u',')
        if a.strip()
    ]

    search_attr_set = ldap0.schema.models.SchemaElementOIDSet(sub_schema, ldap0.schema.models.AttributeType, search_attrs)
    search_attrs = search_attr_set.names()

    search_ldap_url = ls.ldapUrl(dn=search_root)
    search_ldap_url.filterstr = filterstr2.encode(ls.charset)
    search_ldap_url.scope = scope
    search_ldap_url.attrs = search_attrs

    ldap_search_command = search_ldap_url.ldapsearch_cmd().decode(ls.charset)

    read_attr_set = ldap0.schema.models.SchemaElementOIDSet(sub_schema, ldap0.schema.models.AttributeType, search_attrs)
    if search_output in {'table', 'print'}:
        read_attr_set.add('objectClass')

    if search_output == 'print':
        print_template_filenames_dict = web2ldap.app.cnf.GetParam(ls, 'print_template', None)
        if print_template_filenames_dict is None:
            raise web2ldap.app.core.ErrorExit(u'No templates for printing defined.')
        print_template_str_dict = CaseinsensitiveStringKeyDict()
        for oc in print_template_filenames_dict.keys():
            try:
                print_template_str_dict[oc] = open(print_template_filenames_dict[oc], 'r').read()
            except IOError:
                pass
            else:
                read_attr_set.update(GrabKeys(print_template_str_dict[oc]).keys)
        read_attrs = read_attr_set.names()
        result_handler = PrintableHTMLWriter(sid, outf, form, ls, dn, sub_schema, print_template_str_dict)

    elif search_output in {'table', 'raw'}:

        search_tdtemplate = ldap0.cidict.cidict(web2ldap.app.cnf.GetParam(ls, 'search_tdtemplate', {}))
        search_tdtemplate_keys = search_tdtemplate.keys()
        search_tdtemplate_keys_lower = search_tdtemplate.data.keys()
        search_tablistattrs = web2ldap.app.cnf.GetParam(ls, 'search_tablistattrs', [])

        search_tdtemplate_attrs_lower = {}
        for oc in search_tdtemplate_keys_lower:
            search_tdtemplate_attrs_lower[oc] = [
                k.lower()
                for k in GrabKeys(search_tdtemplate[oc]).keys
            ]

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
            read_attr_set.update(search_tablistattrs)
            for oc in search_tdtemplate_keys:
                read_attr_set.update(GrabKeys(search_tdtemplate[oc]).keys)
        read_attr_set.discard('entryDN')
        read_attrs = read_attr_set.names()

        # Create async search handler instance
        result_handler = web2ldap.ldaputil.async.List(ls.l)

    elif search_output in {'ldif', 'ldif1'}:
        # read all attributes
        read_attrs = search_attrs or ({False:['*'], True:['*', '+']}[ls.supportsAllOpAttr and search_opattrs]+requested_attrs) or None
        result_handler = LDIFWriter(ls.l, outf)
        if search_output == 'ldif1':
            result_handler.headerStr = LDIF1_HEADER % (
                web2ldap.__about__.__version__,
                time.strftime(
                    '%A, %Y-%m-%d %H:%M:%S GMT',
                    time.gmtime(time.time())
                ),
                repr(ls.who),
                str(search_ldap_url),
            )

    elif search_output in {'csv', 'excel'}:

        read_attrs = [a for a in search_attrs if not a in {'*', '+'}]
        if not read_attrs:
            if searchform_mode == u'base':
                searchform_mode = u'adv'
            web2ldap.app.searchform.w2l_SearchForm(
                sid, outf, command, form, ls, dn,
                Msg='Attributes to be read have to be explicitly defined for table-structured data export!',
                filterstr=filterstr,
                scope=scope,
                search_root=search_root,
                searchform_mode=searchform_mode,
            )
            return
        result_handler = {
            'csv':CSVWriter,
            'excel':ExcelWriter
        }[search_output](ls.l, outf, sub_schema, read_attrs)

    if search_resnumber:
        search_size_limit = search_resminindex+search_resnumber
    else:
        search_size_limit = -1

    try:
        # Start the search
        result_handler.startSearch(
            search_root.encode(ls.charset),
            scope,
            filterstr2.encode(ls.charset),
            attrList=[a.encode(ls.charset) for a in read_attrs or []] or None,
            attrsOnly=0,
            sizelimit=search_size_limit
        )
    except (
            ldap0.FILTER_ERROR,
            ldap0.INAPPROPRIATE_MATCHING,
        ) as e:
        # Give the user a chance to edit his bad search filter
        web2ldap.app.searchform.w2l_SearchForm(
            sid, outf, command, form, ls, dn,
            Msg=' '.join((
                web2ldap.app.gui.LDAPError2ErrMsg(e, form, charset=ls.charset),
                form.utf2display(filterstr2),
            )),
            filterstr=filterstr,
            scope=scope
        )
        return
    except ldap0.NO_SUCH_OBJECT as e:
        if dn:
            raise e

    if search_output in {'table', 'raw'}:

        SearchWarningMsg = ''
        max_result_msg = ''
        num_all_search_results, num_all_search_continuations = None, None
        num_result_all = None
        partial_results = 0

        try:
            result_handler.processResults(
                search_resminindex, search_resnumber+int(search_resnumber > 0), timeout=ls.timeout
            )
        except (ldap0.SIZELIMIT_EXCEEDED, ldap0.ADMINLIMIT_EXCEEDED) as e:
            if search_size_limit < 0 or result_handler.endResultBreak < search_size_limit:
                SearchWarningMsg = web2ldap.app.gui.LDAPError2ErrMsg(e, form, ls.charset, template=SizeLimitMsg)
            partial_results = 1
            resind = result_handler.endResultBreak
            # Retrieve the overall number of search results by resending the
            # search request without size limit but with the SearchNoOpControl attached
            if SearchNoOpControl.controlType in ls.supportedControl:
                try:
                    num_all_search_results, num_all_search_continuations = ls.l.noop_search(
                        search_root.encode(ls.charset),
                        scope,
                        filterstr=filterstr2.encode(ls.charset),
                        timeout=SEARCH_NOOP_TIMEOUT,
                    )
                    if num_all_search_results is not None and num_all_search_continuations is not None:
                        num_result_all = num_all_search_results + num_all_search_continuations
                        max_result_msg = '(of %d / %d) ' % (num_all_search_results, num_all_search_continuations)
                except LDAPLimitErrors:
                    pass
        except (ldap0.FILTER_ERROR, ldap0.INAPPROPRIATE_MATCHING) as e:
            # Give the user a chance to edit his bad search filter
            web2ldap.app.searchform.w2l_SearchForm(
                sid, outf, command, form, ls, dn,
                Msg=web2ldap.app.gui.LDAPError2ErrMsg(e, form, charset=ls.charset),
                filterstr=filterstr,
                scope=scope
            )
            return
        except (ldap0.NO_SUCH_OBJECT, ldap0.UNWILLING_TO_PERFORM) as e:
            resind = result_handler.endResultBreak
            if dn or scope != ldap0.SCOPE_ONELEVEL:
                # Give the user a chance to edit his bad search filter
                web2ldap.app.searchform.w2l_SearchForm(
                    sid, outf, command, form, ls, dn,
                    Msg=web2ldap.app.gui.LDAPError2ErrMsg(e, form, charset=ls.charset),
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
        if not dn and scope == ldap0.SCOPE_ONELEVEL:
            d = ldap0.cidict.cidict()
            for result_dn in ls.namingContexts:
                if result_dn:
                    d[result_dn] = result_dn
            for r in result_dnlist:
                result_dn = r[1][0]
                if result_dn is not None and d.has_key(result_dn):
                    del d[result_dn]
            result_dnlist.extend([
                (ldap0.RES_SEARCH_ENTRY, (result_dn.encode(ls.charset), {}))
                for result_dn in d.values()
            ])
            resind = len(result_dnlist)

        result_dnlist.sort()

        ContextMenuList = [
            form.applAnchor(
                'searchform', 'Edit Filter', sid,
                [
                    ('dn', dn),
                    ('searchform_mode', 'exp'),
                    ('search_root', search_root),
                    ('filterstr', filterstr),
                    ('search_lastmod', unicode(search_lastmod)),
                    ('search_attrs', ','.join(search_attrs)),
                    ('scope', str(scope)),
                ],
            ),
            form.applAnchor(
                'search', 'Negate search', sid,
                [
                    ('dn', dn),
                    ('search_root', search_root),
                    ('search_output', {False:'raw', True:'table'}[search_output == 'table']),
                    ('scope', str(scope)),
                    ('filterstr', web2ldap.ldaputil.base.negate_filter(filterstr)),
                    ('search_resminindex', str(search_resminindex)),
                    ('search_resnumber', str(search_resnumber)),
                    ('search_lastmod', unicode(search_lastmod)),
                    ('search_attrs', u','.join(search_attrs)),
                ],
                title=u'Search with negated search filter',
            ),
        ]

        if searchform_mode in {'base', 'adv'}:
            ContextMenuList.append(
                form.applAnchor(
                    'searchform', 'Modify Search', sid,
                    form.allInputFields(
                        fields=[
                            ('dn', dn),
                            ('searchform_mode', 'adv')
                        ],
                        ignoreFieldNames=('dn', 'searchform_mode'),
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
                web2ldap.ldaputil.base.SEARCH_SCOPE_STR[scope],
                utf2display(search_root),
                utf2display(filterstr2),
            )

        if not result_dnlist:

            # Empty search results
            #--------------------------------------------------
            web2ldap.app.gui.SimpleMessage(
                sid, outf, command, form, ls, dn,
                'No Search Results',
                '<p class="WarningMessage">No entries found.</p>%s' % (search_param_html),
                main_menu_list=web2ldap.app.gui.MainMenu(sid, form, ls, dn),
                context_menu_list=ContextMenuList
            )

        else:

            # There are search results to be displayed
            #--------------------------------------------------

            page_command_list = None

            ContextMenuList.extend([
                form.applAnchor(
                    'search',
                    {False:'Raw', True:'Table'}[search_output == 'raw'],
                    sid,
                    [
                        ('dn', dn),
                        ('search_root', search_root),
                        ('search_output', {False:'raw', True:'table'}[search_output == 'raw']),
                        ('scope', str(scope)),
                        ('filterstr', filterstr),
                        ('search_resminindex', str(search_resminindex)),
                        ('search_resnumber', str(search_resnumber)),
                        ('search_lastmod', unicode(search_lastmod)),
                        ('search_attrs', u','.join(search_attrs)),
                    ],
                    title=u'Display %s of search results' % (
                        {False:u'distinguished names', True:u'attributes'}[search_output == 'raw']
                    ),
                ),
                form.applAnchor(
                    'delete', 'Delete', sid,
                    [
                        ('dn', search_root),
                        ('filterstr', filterstr2),
                        ('scope', str(scope)),
                    ],
                ),
                form.applAnchor(
                    'bulkmod', 'Bulk modify', sid,
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
                        sid, form, dn, '|&larr;{0}…{1}',
                        search_root, filterstr, search_output,
                        0, search_resnumber,
                        search_lastmod, num_result_all,
                    )

                if search_resminindex > 0:
                    page_command_list[1] = page_appl_anchor(
                        sid, form, dn, '&larr;{0}…{1}',
                        search_root, filterstr, search_output,
                        max(0, prev_resminindex), search_resnumber,
                        search_lastmod, num_result_all,
                    )

                page_command_list[2] = page_appl_anchor(
                    sid, form, dn, 'all',
                    search_root, filterstr, search_output,
                    0, 0,
                    search_lastmod, num_result_all,
                )

                if partial_results:

                    page_next_link = page_appl_anchor(
                        sid, form, dn, '{0}…{1}&rarr;',
                        search_root, filterstr, search_output,
                        search_resminindex+search_resnumber, search_resnumber,
                        search_lastmod, num_result_all,
                    )

                    if num_result_all is not None and resind < num_result_all:
                        page_command_list[3] = page_next_link
                        page_command_list[4] = page_appl_anchor(
                            sid, form, dn, '{0}…{1}&rarr;|',
                            search_root, filterstr, search_output,
                            num_result_all-search_resnumber, search_resnumber,
                            search_lastmod, num_result_all,
                        )
                    elif search_resminindex+search_resnumber <= resind:
                        page_command_list[3] = page_next_link

            search_bookmark = """
                <a
                  href="{baseUrl}?{ldapUrl}"
                  target="_blank"
                  rel="bookmark"
                  title="Bookmark for these search results"
                >
                  Bookmark
                </a>
                """.format(
                    baseUrl=escapeHTML(form.script_name),
                    ldapUrl=str(search_ldap_url),
                )
            result_message = '\n<p>Search results %d - %d %s / <a href="#params" title="See search parameters and export options">Params</a> / %s</p>\n' % (
                search_resminindex+1,
                resind,
                max_result_msg,
                search_bookmark,
            )

            web2ldap.app.gui.TopSection(
                sid, outf, command, form, ls, dn,
                'Search Results',
                web2ldap.app.gui.MainMenu(sid, form, ls, dn),
                context_menu_list=ContextMenuList
            )

            export_field = web2ldap.app.form.ExportFormatSelect('search_output')
            export_field.charset = form.accept_charset

            outf.write('\n'.join((SearchWarningMsg, result_message)))

            if search_resminindex == 0 and not partial_results:
                mailtolist = set()
                for r in result_dnlist:
                    if r[0] in is_search_result:
                        mailtolist.update(r[1][1].get('mail', r[1][1].get('rfc822Mailbox', [])))
                if mailtolist:
                    mailtolist = [urllib.quote(m) for m in mailtolist]
                    outf.write('Mail to all <a href="mailto:%s?cc=%s">Cc:-ed</a> - <a href="mailto:?bcc=%s">Bcc:-ed</a>' % (
                        mailtolist[0],
                        ','.join(mailtolist[1:]),
                        ','.join(mailtolist)
                    ))

            if page_command_list:
               outf.write("""
                  <nav><table>
                    <tr>
                      <td width="20%">{0}</td>
                      <td width="20%">{1}</td>
                      <td width="20%">{2}</td>
                      <td width="20%">{3}</td>
                      <td width="20%">{4}</td>
                    </tr>
                  </table></nav>
               """.format(*page_command_list))

            outf.write('<table id="SrchResList">\n')

            for r in result_dnlist[0:resind]:

              if r[0] in is_search_reference:

                # Display a search continuation (search reference)
                entry = ldap0.cidict.cidict({})
                try:
                  refUrl = ExtendedLDAPUrl(r[1][1][0])
                except ValueError:
                  command_table = []
                  result_dd_str='Search reference (NON-LDAP-URI) =&gt; %s' % (form.utf2display(unicode(r[1][1][0])))
                else:
                  result_dd_str='Search reference =&gt; %s' % (refUrl.htmlHREF(hrefTarget=None))
                  if scope==ldap0.SCOPE_SUBTREE:
                    refUrl.scope = refUrl.scope or scope
                    refUrl.filterstr = (unicode(refUrl.filterstr or '',ls.charset) or filterstr).encode(form.accept_charset)
                    command_table = [
                      form.applAnchor(
                        'search','Continue search',
                        {0:sid,1:None}[refUrl.initializeUrl()!=ls.uri],
                        [('ldapurl',refUrl.unparse())],
                        title=u'Follow this search continuation',
                      )
                    ]
                  else:
                    command_table = []
                    refUrl.filterstr = filterstr
                    refUrl.scope=ldap0.SCOPE_BASE
                    command_table.append(form.applAnchor(
                      'read','Read',
                      {0:sid,1:None}[refUrl.initializeUrl()!=ls.uri],
                      [('ldapurl',refUrl.unparse())],
                      title=u'Display single entry following search continuation',
                    ))
                    refUrl.scope=ldap0.SCOPE_ONELEVEL
                    command_table.append(form.applAnchor(
                      'search','Down',
                      {0:sid,1:None}[refUrl.initializeUrl()!=ls.uri],
                      [('ldapurl',refUrl.unparse())],
                      title=u'Descend into tree following search continuation',
                    ))

              elif r[0] in is_search_result:

                # Display a search result with entry's data
                dn,entry = unicode(r[1][0],ls.charset),ldap0.cidict.cidict(r[1][1])

                if search_output == 'raw':

                  # Output DN
                  result_dd_str=utf2display(dn)

                else:

                  objectclasses_lower_set = set([o.lower() for o in entry.get('objectClass',[])])
                  tdtemplate_oc = objectclasses_lower_set.intersection(search_tdtemplate_keys_lower)

                  if tdtemplate_oc:

                    template_attrs = set([])
                    for oc in tdtemplate_oc:
                      template_attrs.update(search_tdtemplate_attrs_lower[oc])
                    tableentry_attrs = template_attrs.intersection(entry.data.keys())
                    if tableentry_attrs:
                      # Output entry with the help of pre-defined templates
                      tableentry = web2ldap.app.read.DisplayEntry(sid, form, ls, dn,sub_schema,entry,'searchSep',0)
                      tdlist = []
                      for oc in tdtemplate_oc:
                        tdlist.append(search_tdtemplate[oc] % tableentry)
                      result_dd_str='<br>\n'.join(tdlist)
                    else:
                      # Output DN
                      result_dd_str=utf2display(dn)

                  elif entry.has_key('displayName'):
                    result_dd_str = utf2display(ls.uc_decode(entry['displayName'][0])[0])

                  elif search_tablistattrs and entry.has_key(search_tablistattrs[0]):
                    tdlist = []
                    for attr_type in search_tablistattrs:
                      if entry.has_key(attr_type):
                        tdlist.append(', '.join([
                          web2ldap.app.gui.DataStr(
                            sid, form, ls, dn,sub_schema,attr_type,value,commandbutton=0
                          )
                          for value in entry[attr_type]
                        ]))
                    result_dd_str='<br>\n'.join(filter(None,tdlist))

                  else:
                    # Output DN
                    result_dd_str=utf2display(dn)

                # Build the list for link table
                command_table = []

                # A [Read] link is added in any case
                read_title_list = [ dn ]
                for attr_type in (u'description',u'structuralObjectClass'):
                  try:
                    first_attr_value = unicode(entry[attr_type][0],ls.charset)
                  except KeyError:
                    pass
                  else:
                    read_title_list.append(u'%s: %s' % (attr_type,first_attr_value))
                command_table.append(
                  form.applAnchor(
                    'read','Read', sid,
                    [('dn', dn)],
                    title=u'\n'.join(read_title_list)
                  )
                )

                # Try to determine from entry's attributes if there are subordinates
                hasSubordinates = entry.get('hasSubordinates',['TRUE'])[0].upper()=='TRUE'
                try:
                  subordinateCountFlag = int(entry.get('subordinateCount',entry.get('numAllSubordinates',entry.get('msDS-Approx-Immed-Subordinates',['1'])))[0])
                except ValueError:
                  subordinateCountFlag = 1

                # If subordinates or unsure a [Down] link is added
                if hasSubordinates and subordinateCountFlag>0:

                  down_title_list = [u'List direct subordinates of %s' % (dn)]

                  # Determine number of direct subordinates
                  numSubOrdinates = entry.get('numSubOrdinates',entry.get('subordinateCount',entry.get('countImmSubordinates',entry.get('msDS-Approx-Immed-Subordinates',[None]))))[0]
                  if numSubOrdinates is not None:
                    numSubOrdinates = int(numSubOrdinates)
                    down_title_list.append('direct: %d' % (numSubOrdinates))
                  # Determine total number of subordinates
                  numAllSubOrdinates = entry.get('numAllSubOrdinates',entry.get('countTotSubordinates',[None]))[0]
                  if numAllSubOrdinates is not None:
                    numAllSubOrdinates = int(numAllSubOrdinates)
                    down_title_list.append(u'total: %d' % (numAllSubOrdinates))

                  command_table.append(form.applAnchor(
                      'search','Down', sid,
                      (
                        ('dn', dn),
                        ('scope', web2ldap.app.searchform.SEARCH_SCOPE_STR_ONELEVEL),
                        ('searchform_mode',u'adv'),
                        ('search_attr',u'objectClass'),
                        ('search_option',web2ldap.app.searchform.SEARCH_OPT_ATTR_EXISTS),
                        ('search_string',''),
                      ),
                      title=u'\r\n'.join(down_title_list),
                  ))

              else:
                raise ValueError,"LDAP result of invalid type %s." % (repr(r[0]))

              outf.write("""
              <tr>
                <td class="CommandTable">\n%s\n</td>
                <td class="SrchRes">\n%s\n</td>
              </tr>
              """ % (
                  '\n'.join(command_table),
                  result_dd_str
                )
              )

            outf.write("""
              </table>
              <a id="params"></a>
              %s
                <h4>Export to other formats</h4>
                <p>%s &nbsp; Include operational attributes %s</p>
                <p><input type="submit" value="Export"></p>
              </form>
            """ % (
              '\n'.join((
                form.beginFormHTML('search', sid,'GET',target='web2ldapexport'),
                form.hiddenFieldHTML('dn',dn,u''),
                form.hiddenFieldHTML('search_root', search_root,u''),
                form.hiddenFieldHTML('scope', unicode(scope),u''),
                form.hiddenFieldHTML('filterstr', filterstr,u''),
                form.hiddenFieldHTML('search_lastmod', unicode(search_lastmod),u''),
                form.hiddenFieldHTML('search_resnumber',u'0',u''),
                form.hiddenFieldHTML('search_attrs', u','.join(search_attrs),u''),
              )),
                export_field.inputHTML(),
                web2ldap.app.form.InclOpAttrsCheckbox(
                  'search_opattrs',
                  u'Request operational attributes',
                  default="yes",checked=0
                ).inputHTML(),
            ))

            outf.write("""
            <h4>Search parameters used</h4>
            %s
            <p>
              Equivalent OpenLDAP command:<br>
              <input value="%s" size="60" readonly>
            </p>
            """ % (
              search_param_html,
              utf2display(ldap_search_command),
            ))

            web2ldap.app.gui.Footer(outf, form)


    else:

        try:
          result_handler.processResults(timeout=ls.timeout)
        except (ldap0.SIZELIMIT_EXCEEDED,ldap0.ADMINLIMIT_EXCEEDED):
          result_handler.postProcessing()
