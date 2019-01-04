# -*- coding: utf-8 -*-
"""
web2ldap.log -- Logging
"""

from __future__ import absolute_import

import os
import logging

LOG_LEVEL = os.environ.get('LOG_LEVEL', logging.INFO)
LOG_FORMAT = '%(asctime)s %(levelname)s %(name)s: %(message)s'


class LogHelper:
  """
  mix-in class for logging with a class-specific log prefix
  """

  def _log_prefix(self):
      return '%s[%x] ' % (self.__class__.__name__, id(self))

  def log(self, level, msg, *args, **kwargs):
      logger.log(level, ' '.join((self._log_prefix(), msg)), *args, **kwargs)


def init_logger():
    """
    Create logger instance
    """
    logger = logging.getLogger('web2ldap')
    logger.setLevel(LOG_LEVEL)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(LOG_LEVEL)
    formatter = logging.Formatter(LOG_FORMAT)
    stream_handler.setFormatter(formatter)
#    logger.addHandler(stream_handler)
    return logger


global logger
logger = init_logger()
