# -*- coding: utf-8 -*-
"""
msgzip.py
(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

try:

  import gzip

except ImportError:
  GzipFile=None

else:
  class GzipFile(gzip.GzipFile):
    """
    Stub class for gzip.GzipFile with delayed output of gzip-header
    """
    def __init__(self,filename=None,mode=None,compresslevel=9,fileobj=None):
      self._init_args = (filename,mode,compresslevel,fileobj)
      self._not_initialized = 1
      self.fileobj = fileobj
      self.compresslevel = compresslevel

    def write(self,data):
      if self._not_initialized:
        self._not_initialized = 0
        # Do a deferred __init__()
        gzip.GzipFile.__init__(self,*self._init_args)
      gzip.GzipFile.write(self,data)


class DebugFile:
  def __init__(self,f):
    self._f = f

  def write(self,data):
    import pprint
    pprint.pprint(repr(data))
    self._f.write(data)

  def flush(self):
    self._f.flush()
