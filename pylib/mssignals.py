# -*- coding: utf-8 -*-
"""
mssignals.py: handle signals

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

class SigPipeException(Exception):
  pass

def PIPESignalHandler(signum,frame):
  pass

def TERMSignalHandler(signum,frame):
  raise KeyboardInterrupt

def USR1SignalHandler(signum,frame):
  raise KeyboardInterrupt
