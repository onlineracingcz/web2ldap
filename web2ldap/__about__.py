# -*- coding: utf-8 -*-
"""
Meta information about module package ekca_client
"""

import collections

VersionInfo = collections.namedtuple('version_info', ('major', 'minor', 'micro'))
__version_info__ = VersionInfo(
    major=1,
    minor=3,
    micro=0,
)
__version__ = '.'.join(str(val) for val in __version_info__)
__author__ = u'Michael Stroeder'
__mail__ = u'michael@stroeder.com'
__license__ = 'GPL-2.0'

__all__ = [
    '__version_info__',
    '__version__',
    '__author__',
    '__license__',
]
