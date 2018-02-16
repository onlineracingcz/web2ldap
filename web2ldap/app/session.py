# -*- coding: utf-8 -*-
"""
web2ldap.app.session: The session handling thingy

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2018 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import sys,time,traceback,collections

import pyweblib.session
       
from web2ldap.ldapsession import LDAPSession
import web2ldap.app.cnf


class InvalidSessionInstance(pyweblib.session.SessionException):
  pass


class WrongSessionCookie(pyweblib.session.SessionException):
  pass


class Session(pyweblib.session.WebSession):

  def __init__(
    self,
    dictobj=None,
    expireDeactivate=0,
    expireRemove=0,
    crossCheckVars=None,
    maxSessionCount=None,
    sessionIDLength=12,
    sessionIDChars=None,
    maxSessionCountPerIP=None,
  ):
    pyweblib.session.WebSession.__init__(
      self,
      dictobj,
      expireDeactivate,
      expireRemove,
      crossCheckVars,
      maxSessionCount,
      sessionIDLength,
      sessionIDChars,
    )
    self.max_concurrent_sessions = 0
    self.remote_ip_sessions = collections.defaultdict(set)
    self.session_ip_addr = {}
    self.maxSessionCountPerIP = maxSessionCountPerIP or self.maxSessionCount/4
    self.remote_ip_counter = collections.Counter()

  def _remote_ip(self,env):
    return env.get('FORWARDED_FOR',
           env.get('HTTP_X_FORWARDED_FOR',
           env.get('HTTP_X_REAL_IP',
           env.get('REMOTE_HOST',
           env.get('REMOTE_ADDR','__UNKNOWN__')))))

  def newSession(self,env=None):
    remote_ip = self._remote_ip(env)
    remote_ip_sessions = self.remote_ip_sessions.get(remote_ip,set())
    if len(remote_ip_sessions)>=self.maxSessionCountPerIP:
      raise pyweblib.session.MaxSessionCountExceeded(self.maxSessionCountPerIP)
    session_id = pyweblib.session.WebSession.newSession(self,env)
    current_concurrent_sessions = len(self.sessiondict)/2
    if current_concurrent_sessions>self.max_concurrent_sessions:
      self.max_concurrent_sessions = current_concurrent_sessions
    self.session_ip_addr[session_id] = remote_ip
    self.remote_ip_counter.update({remote_ip:1})
    self.remote_ip_sessions[remote_ip].add(session_id)
    return session_id

  def _remove_ip_assoc(self,sid,remote_ip):
    try:
      del self.session_ip_addr[sid]
    except KeyError:
      pass
    try:
      self.remote_ip_sessions[remote_ip].remove(sid)
    except KeyError:
      pass
    else:
      if not self.remote_ip_sessions[remote_ip]:
        del self.remote_ip_sessions[remote_ip]
    return # _remove_ip_assoc()

  def renameSession(self,old_sid,env):
    session_data = self.retrieveSession(old_sid,env)
    new_sid = self.newSession(env)
    self.storeSession(new_sid,session_data)
    pyweblib.session.WebSession.deleteSession(self,old_sid)
    # Set new remote IP associations
    remote_ip = self._remote_ip(env)
    self.session_ip_addr[new_sid] = remote_ip
    # Remove old remote IP associations
    self._remove_ip_assoc(old_sid,remote_ip)
    return new_sid

  def deleteSession(self,sid):
    try:
      ls_local = self.sessiondict[sid][1]
    except KeyError:
      pass
    else:
      if isinstance(ls_local,LDAPSession):
        ls_local.unbind()
    pyweblib.session.WebSession.deleteSession(self,sid)
    # Remove old remote IP associations
    try:
      remote_ip = self.session_ip_addr[sid]
    except KeyError:
      pass
    else:
      self._remove_ip_assoc(sid,remote_ip)
    return # deleteSession()


class CleanUpThread(pyweblib.session.CleanUpThread):
  """
  Thread class for clean-up thread

  Mainly it overrides pyweblib.session.CleanUpThread.run()
  to call ldapSession.unbind().
  """

  def __init__(self,*args,**kwargs):
    pyweblib.session.CleanUpThread.__init__(self,*args,**kwargs)
    self.removed_sessions = 0

  def run(self):
    """Thread function for cleaning up session database"""
    while not self._stop_event.isSet():
      try:
        current_time = time.time()
        sessiondict_keys = [
          sid
          for sid in self._sessionInstance.sessiondict.keys()
          if not sid.startswith('__')
        ]
        for session_id in sessiondict_keys:
          try:
            session_timestamp,_ = self._sessionInstance.sessiondict[session_id]
          except KeyError:
            # Avoid race condition. The session might have been
            # deleted in the meantime. But make sure everything is deleted.
            self._sessionInstance.deleteSession(session_id)
          else:
            # Check expiration time
            if session_timestamp+self._sessionInstance.expireRemove<current_time:
              # Remove expired session
              self._sessionInstance.deleteSession(session_id)
              self.removed_sessions+=1
      except:
        # Catch all exceptions to avoid thread being killed.
        if __debug__:
          traceback.print_exc()
        pass

      # Sleeping until next turn
      self._stop_event.wait(self._interval)

    return # CleanUpThread.run()


########################################################################
# Initialize web session object
########################################################################

global session
if not hasattr(__name__, 'session'):
    sys.stderr.write('Initialize web2ldap session store\n')
    session = Session(
      expireDeactivate=web2ldap.app.cnf.misc.session_remove,
      expireRemove=web2ldap.app.cnf.misc.session_remove,
      crossCheckVars = web2ldap.app.cnf.misc.session_checkvars,
      maxSessionCount = web2ldap.app.cnf.misc.session_limit,
      maxSessionCountPerIP = web2ldap.app.cnf.misc.session_per_ip_limit,
    )

global cleanUpThread
if not hasattr(__name__, 'cleanUpThread'):
    sys.stderr.write('Initialize web2ldap clean-up thread\n')
    cleanUpThread = CleanUpThread(session,interval=5)
