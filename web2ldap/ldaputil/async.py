"""
web2ldap.ldaputil.async - handle async LDAP operations

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0

SEARCH_RESULT_TYPES = set([
  ldap0.RES_SEARCH_ENTRY,
  ldap0.RES_SEARCH_RESULT,
  ldap0.RES_SEARCH_REFERENCE,
])

ENTRY_RESULT_TYPES = set([
  ldap0.RES_SEARCH_ENTRY,
  ldap0.RES_SEARCH_RESULT,
])


class WrongResultType(Exception):

  def __init__(self,receivedResultType,expectedResultTypes):
    self.receivedResultType = receivedResultType
    self.expectedResultTypes = expectedResultTypes
    Exception.__init__(self)

  def __str__(self):
    return 'Received wrong result type %s (expected one of %s).' % (
      self.receivedResultType,
      ', '.join(self.expectedResultTypes),
    )


class AsyncSearchHandler:
  """
  Class for stream-processsing LDAP search results

  Arguments:

  l
    LDAPObject instance
  """

  def __init__(self,l):
    self._l = l
    self._msgId = None
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
    self._msgId = self._l.search(
      searchRoot,searchScope,filterStr,
      attrList,attrsOnly,serverctrls,timeout,sizelimit
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

  def processResults(self,ignoreResultsNumber=0,processResultsCount=0,timeout=-1):
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
      result_type,result_list = None,None
      while go_ahead:
        while result_type is None and not result_list:
          result_type,result_list,result_msgid,result_serverctrls,_,_ = self._l.result(self._msgId,0,timeout)
          if self._afterFirstResult:
            self.afterFirstResult()
            self._afterFirstResult = 0
        if not result_list:
          break
        if result_type not in SEARCH_RESULT_TYPES:
          raise WrongResultType(result_type,SEARCH_RESULT_TYPES)
        # Loop over list of search results
        for result_item in result_list:
          if result_counter<ignoreResultsNumber:
            self.beginResultsDropped = self.beginResultsDropped+1
          elif processResultsCount==0 or result_counter<end_result_counter:
            self._processSingleResult(result_type,result_item)
          else:
            go_ahead = 0 # break-out from while go_ahead
            partial = 1
            break # break-out from this for-loop
          result_counter = result_counter+1
        result_type,result_list = None,None
        self.endResultBreak = result_counter
    finally:
      if partial and self._msgId!=None:
        self._l.abandon(self._msgId)
    self.postProcessing()
    return partial # processResults()

  def _processSingleResult(self,resultType,resultItem):
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

  def __init__(self,l):
    AsyncSearchHandler.__init__(self,l)
    self.allResults = []

  def _processSingleResult(self,resultType,resultItem):
    self.allResults.append((resultType,resultItem))


class FileWriter(AsyncSearchHandler):
  """
  Class for writing a stream of LDAP search results to a file object

  Arguments:
  l
    LDAPObject instance
  f
    File object instance where the LDIF data is written to
  """

  def __init__(self,l,f,headerStr='',footerStr=''):
    AsyncSearchHandler.__init__(self,l)
    self._f = f
    self.headerStr = headerStr
    self.footerStr = footerStr

  def preProcessing(self):
    """
    The headerStr is written to output after starting search but
    before receiving and processing results.
    """
    self._f.write(self.headerStr)

  def postProcessing(self):
    """
    The footerStr is written to output after receiving and
    processing results.
    """
    self._f.write(self.footerStr)


class LDIFWriter(FileWriter):
  """
  Class for writing a stream LDAP search results to a LDIF file

  Arguments:

  l
    LDAPObject instance
  writer_obj
    Either a file-like object or a ldif.LDIFWriter instance used for output
  """

  def __init__(self,l,writer_obj,headerStr='',footerStr=''):
    import ldap0.ldif
    if isinstance(writer_obj,ldap0.ldif.LDIFWriter):
      self._ldif_writer = writer_obj
    else:
      self._ldif_writer = ldap0.ldif.LDIFWriter(writer_obj)
    FileWriter.__init__(self,l,self._ldif_writer._output_file,headerStr,footerStr)

  def _processSingleResult(self,resultType,resultItem):
    if resultType in ENTRY_RESULT_TYPES:
      # Search continuations are ignored
      dn,entry = resultItem
      self._ldif_writer.unparse(dn,entry)
