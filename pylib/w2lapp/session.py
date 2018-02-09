# -*- coding: utf-8 -*-
"""
w2lapp.session: The session handling thingy

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import time,traceback,collections, \
       pyweblib.session,ldapsession,w2lapp.cnf


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
      if isinstance(ls_local,ldapsession.LDAPSession):
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
session = Session(
  expireDeactivate=w2lapp.cnf.misc.session_remove,
  expireRemove=w2lapp.cnf.misc.session_remove,
  crossCheckVars = w2lapp.cnf.misc.session_checkvars,
  maxSessionCount = w2lapp.cnf.misc.session_limit,
  maxSessionCountPerIP = w2lapp.cnf.misc.session_per_ip_limit,
)

cleanUpThread = CleanUpThread(session,interval=5)
