"""
web2ldap.ldaputil.asynch - handle async LDAP operations

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0
import ldap0.ldif
from ldap0.res import SearchResultEntry


class AsyncSearchHandler:
    """
    Class for stream-processing LDAP search results

    Arguments:

    l
      LDAPObject instance
    """

    def __init__(self, l):
        self._l = l
        self._msg_id = None
        self._after_first = True

    def start_search(
            self,
            searchRoot,
            searchScope,
            filterStr,
            attrList=None,
            sizelimit=0,
            req_ctrls=None,
        ):
        """
        searchRoot
            See parameter base of method LDAPObject.search()
        searchScope
            See parameter scope of method LDAPObject.search()
        filterStr
            See parameter filter of method LDAPObject.search()
        attrList=None
            See parameter attrlist of method LDAPObject.search()
        sizelimit
            Maximum number of entries a server should return
            (request client-side limit)
        req_ctrls
            list of server-side LDAP controls
        """
        self._msg_id = self._l.search(
            searchRoot,
            scope=searchScope,
            filterstr=filterStr,
            attrlist=attrList,
            req_ctrls=req_ctrls,
            sizelimit=sizelimit,
        )
        self._after_first = True
        # end of start_search()

    def pre_processing(self):
        """
        Do anything you want after starting search but
        before receiving and processing results
        """

    def after_first(self):
        """
        Do anything you want right after successfully receiving but before
        processing first result
        """

    def post_processing(self):
        """
        Do anything you want after receiving and processing all results
        """

    def process_results(
            self,
            ignoreResultsNumber=0,
            processResultsCount=0,
        ):
        """
        ignoreResultsNumber
            Don't process the first ignoreResultsNumber results.
        processResultsCount
            If non-zero this parameters indicates the number of results
            processed is limited to processResultsCount.
        """
        self.pre_processing()
        result_counter = 0
        end_result_counter = ignoreResultsNumber + processResultsCount
        go_ahead = True
        partial = False
        self.beginResultsDropped = 0
        self.endResultBreak = result_counter
        try:
            for result in self._l.results(self._msg_id):
                if self._after_first:
                    self.after_first()
                    self._after_first = False
                # Loop over list of search results
                for result_item in result.rdata:
                    if result_counter < ignoreResultsNumber:
                        self.beginResultsDropped += 1
                    elif processResultsCount == 0 or result_counter < end_result_counter:
                        self._process_result(result_item)
                    else:
                        go_ahead = False # break-out from while go_ahead
                        partial = True
                        break # break-out from this for-loop
                    result_counter = result_counter+1
                self.endResultBreak = result_counter
        finally:
            if partial and self._msg_id is not None:
                self._l.abandon(self._msg_id)
        self.post_processing()
        return partial # process_results()

    def _process_result(self, resultItem):
        """
        Process single entry

        resultItem
            Single item of a result list
        """
        pass


class List(AsyncSearchHandler):
    """
    Class for collecting all search results.

    This does not seem to make sense in the first place but think
    of retrieving exactly a certain portion of the available search
    results.
    """

    def __init__(self, l):
        AsyncSearchHandler.__init__(self, l)
        self.allResults = []

    def _process_result(self, resultItem):
        self.allResults.append(resultItem)


class FileWriter(AsyncSearchHandler):
    """
    Class for writing a stream of LDAP search results to a file object

    Arguments:
    l
      LDAPObject instance
    f
      File object instance where the LDIF data is written to
    """
    encoding = 'utf-8'

    def __init__(self, l, f, header='', footer=''):
        AsyncSearchHandler.__init__(self, l)
        self._f = f
        self.header = header
        self.footer = footer

    def pre_processing(self):
        """
        The header is written to output after starting search but
        before receiving and processing results.
        """
        self._f.write(self.header.encode(self.encoding))

    def post_processing(self):
        """
        The footer is written to output after receiving and
        processing results.
        """
        self._f.write(self.footer.encode(self.encoding))


class LDIFWriter(FileWriter):
    """
    Class for writing a stream LDAP search results to a LDIF file

    Arguments:

    l
      LDAPObject instance
    writer_obj
      Either a file-like object or a ldif.LDIFWriter instance used for output
    """

    def __init__(self, l, writer_obj, header='', footer=''):
        if isinstance(writer_obj, ldap0.ldif.LDIFWriter):
            self._ldif_writer = writer_obj
        else:
            self._ldif_writer = ldap0.ldif.LDIFWriter(writer_obj)
        FileWriter.__init__(
            self,
            l,
            self._ldif_writer._output_file,
            header,
            footer,
        )

    def _process_result(self, resultItem):
        if isinstance(resultItem, SearchResultEntry):
            self._ldif_writer.unparse(resultItem.dn_b, resultItem.entry_b)
