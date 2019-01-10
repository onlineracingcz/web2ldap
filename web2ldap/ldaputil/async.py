"""
web2ldap.ldaputil.async - handle async LDAP operations

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0
from ldap0.base import LDAPResult
import ldap0.ldif


SEARCH_RESULT_TYPES = {
    ldap0.RES_SEARCH_ENTRY,
    ldap0.RES_SEARCH_RESULT,
    ldap0.RES_SEARCH_REFERENCE,
}

ENTRY_RESULT_TYPES = {
    ldap0.RES_SEARCH_ENTRY,
    ldap0.RES_SEARCH_RESULT,
}


class WrongResultType(TypeError):

    def __init__(self, received, expected):
        self.received = received
        self.expected = expected
        TypeError.__init__(self)

    def __str__(self):
        return 'Received wrong result type %r (expected one of %r).' % (
            self.received,
            ', '.join(self.expected),
        )


class AsyncSearchHandler:
    """
    Class for stream-processsing LDAP search results

    Arguments:

    l
      LDAPObject instance
    """

    def __init__(self, l):
        self._l = l
        self._msg_id = None
        self._afterFirstResult = 1

    def startSearch(
            self,
            searchRoot,
            searchScope,
            filterStr,
            attrList=None,
            attrsOnly=0,
            timeout=-1,
            sizelimit=0,
            serverctrls=None,
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
        attrsOnly
            See parameter attrsonly of method LDAPObject.search()
        timeout
            Maximum time the server shall use for search operation
        sizelimit
            Maximum number of entries a server should return
            (request client-side limit)
        serverctrls
            list of server-side LDAP controls
        """
        self._msg_id = self._l.search(
            searchRoot, searchScope, filterStr,
            attrList, attrsOnly, serverctrls, timeout, sizelimit
        )
        self._afterFirstResult = 1
        return # startSearch()

    def preProcessing(self):
        """
        Do anything you want after starting search but
        before receiving and processing results
        """

    def afterFirstResult(self):
        """
        Do anything you want right after successfully receiving but before
        processing first result
        """

    def postProcessing(self):
        """
        Do anything you want after receiving and processing all results
        """

    def processResults(
            self,
            ignoreResultsNumber=0,
            processResultsCount=0,
            timeout=-1,
        ):
        """
        ignoreResultsNumber
            Don't process the first ignoreResultsNumber results.
        processResultsCount
            If non-zero this parameters indicates the number of results
            processed is limited to processResultsCount.
        timeout
            See parameter timeout of ldap0.LDAPObject.result()
        """
        self.preProcessing()
        result_counter = 0
        end_result_counter = ignoreResultsNumber+processResultsCount
        go_ahead = 1
        partial = 0
        self.beginResultsDropped = 0
        self.endResultBreak = result_counter
        try:
            result = LDAPResult(None, None, None, None)
            while go_ahead:
                while result.rtype is None and not result.data:
                    result = self._l.result(
                        self._msg_id,
                        0,
                        timeout
                    )
                    if self._afterFirstResult:
                        self.afterFirstResult()
                        self._afterFirstResult = 0
                if not result.data:
                    break
                if result.rtype not in SEARCH_RESULT_TYPES:
                    raise WrongResultType(result.rtype, SEARCH_RESULT_TYPES)
                # Loop over list of search results
                for result_item in result.data:
                    if result_counter < ignoreResultsNumber:
                        self.beginResultsDropped += 1
                    elif processResultsCount == 0 or result_counter < end_result_counter:
                        self._processSingleResult(result.rtype, result_item)
                    else:
                        go_ahead = 0 # break-out from while go_ahead
                        partial = 1
                        break # break-out from this for-loop
                    result_counter = result_counter+1
                result = LDAPResult(None, None, None, None)
                self.endResultBreak = result_counter
        finally:
            if partial and self._msg_id is not None:
                self._l.abandon(self._msg_id)
        self.postProcessing()
        return partial # processResults()

    def _processSingleResult(self, resultType, resultItem):
        """
        Process single entry

        resultType
            result type
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

    def _processSingleResult(self, resultType, resultItem):
        self.allResults.append((resultType, resultItem))


class FileWriter(AsyncSearchHandler):
    """
    Class for writing a stream of LDAP search results to a file object

    Arguments:
    l
      LDAPObject instance
    f
      File object instance where the LDIF data is written to
    """

    def __init__(self, l, f, header='', footer=''):
        AsyncSearchHandler.__init__(self, l)
        self._f = f
        self.header = header
        self.footer = footer

    def preProcessing(self):
        """
        The header is written to output after starting search but
        before receiving and processing results.
        """
        self._f.write(self.header)

    def postProcessing(self):
        """
        The footer is written to output after receiving and
        processing results.
        """
        self._f.write(self.footer)


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

    def _processSingleResult(self, resultType, resultItem):
        if resultType in ENTRY_RESULT_TYPES:
            # Search continuations are ignored
            dn, entry = resultItem
            self._ldif_writer.unparse(dn, entry)
