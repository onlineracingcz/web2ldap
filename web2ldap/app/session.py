# -*- coding: utf-8 -*-
"""
web2ldap.app.session: The session handling thingy

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time
import collections
import logging

import web2ldap.web.session

from web2ldap.ldapsession import LDAPSession
from web2ldap.log import logger, LogHelper
import web2ldapcnf


class InvalidSessionInstance(web2ldap.web.session.SessionException):
    """
    Exception raised in case of invalid session
    """
    pass


class WrongSessionCookie(web2ldap.web.session.SessionException):
    """
    Exception raised in case of invalid cookie
    """
    pass


class Session(web2ldap.web.session.WebSession, LogHelper):
    """
    session store
    """

    def __init__(
            self,
            dictobj=None,
            session_ttl=0,
            crossCheckVars=None,
            maxSessionCount=None,
            sessionIDLength=12,
            sessionIDChars=None,
            max_session_count_per_ip=None,
        ):
        web2ldap.web.session.WebSession.__init__(
            self,
            dictobj,
            session_ttl,
            crossCheckVars,
            maxSessionCount,
            sessionIDLength,
            sessionIDChars,
        )
        self.max_concurrent_sessions = 0
        self.remote_ip_sessions = collections.defaultdict(set)
        self.session_ip_addr = {}
        self.max_session_count_per_ip = max_session_count_per_ip or self.maxSessionCount/4
        self.remote_ip_counter = collections.Counter()
        self.log(
            logging.DEBUG,
            'Initialized clean-up thread working on %s[%x]',
            self.__class__.__name__,
            id(self),
        )

    def new(self, env=None):
        self.log(logging.DEBUG, 'new(): creating a new session')
        remote_ip = self._remote_ip(env)
        self.log(logging.DEBUG, 'new(): remote_ip = %r', remote_ip)
        remote_ip_sessions = self.remote_ip_sessions.get(remote_ip, set())
        if len(remote_ip_sessions) >= self.max_session_count_per_ip:
            self.log(
                logging.WARN,
                '.new(): remote_ip = %r exceeded max. %d sessions',
                remote_ip,
                self.max_session_count_per_ip,
            )
            raise web2ldap.web.session.MaxSessionPerIPExceeded(remote_ip, self.max_session_count_per_ip)
        session_id = web2ldap.web.session.WebSession.new(self, env)
        current_concurrent_sessions = len(self.sessiondict) / 2
        if current_concurrent_sessions > self.max_concurrent_sessions:
            self.max_concurrent_sessions = current_concurrent_sessions
        self.session_ip_addr[session_id] = remote_ip
        self.remote_ip_counter.update({remote_ip:1})
        self.remote_ip_sessions[remote_ip].add(session_id)
        self.log(logging.INFO, 'new(): created new session for remote_ip = %r', remote_ip)
        return session_id

    def _remove_ip_assoc(self, sid, remote_ip):
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

    def rename(self, old_sid, env):
        session_data = self.retrieveSession(old_sid, env)
        new_sid = self.new(env)
        self.save(new_sid, session_data)
        web2ldap.web.session.WebSession.delete(self, old_sid)
        # Set new remote IP associations
        remote_ip = self._remote_ip(env)
        self.session_ip_addr[new_sid] = remote_ip
        # Remove old remote IP associations
        self._remove_ip_assoc(old_sid, remote_ip)
        return new_sid

    def delete(self, sid):
        assert isinstance(sid, bytes), TypeError('Expected sid to be bytes, got %r' % (sid))
        self.log(logging.DEBUG, 'delete(%r): remove session', sid)
        try:
            ls_local = self.sessiondict[sid][1]
        except KeyError:
            pass
        else:
            if isinstance(ls_local, LDAPSession):
                ls_local.unbind()
        web2ldap.web.session.WebSession.delete(self, sid)
        self.log(logging.INFO, 'delete(%r): removed session', sid)
        # Remove old remote IP associations
        try:
            remote_ip = self.session_ip_addr[sid]
        except KeyError:
            pass
        else:
            self._remove_ip_assoc(sid, remote_ip)
        return # delete()


class CleanUpThread(web2ldap.web.session.CleanUpThread, LogHelper):
    """
    Thread class for clean-up thread

    Mainly it overrides web2ldap.web.session.CleanUpThread.run()
    to call ldapSession.unbind().
    """


    def __init__(self, *args, **kwargs):
        web2ldap.web.session.CleanUpThread.__init__(self, *args, **kwargs)
        self.removed_sessions = 0
        self.run_counter = 0
        self.last_run_time = 0
        self.enabled = True

    def run(self):
        """Thread function for cleaning up session database"""
        self.log(logging.DEBUG, 'Entering .run()')
        while self.enabled and not self._stop_event.isSet():
            self.run_counter += 1
#            self.log(
#                logging.DEBUG,
#                'run() %d. expiry run on %s[%x]',
#                self.run_counter,
#                self._sessionInstance.__class__.__name__,
#                id(self._sessionInstance),
#            )
            current_time = time.time()
            try:
                sessiondict_keys = [
                    sid
                    for sid in globals()['session_store'].sessiondict.keys()
                    if not sid.startswith('__')
                ]
                for session_id in sessiondict_keys:
                    try:
                        session_timestamp, _ = self._sessionInstance.sessiondict[session_id]
                    except KeyError:
                        # Avoid race condition. The session might have been
                        # deleted in the meantime. But make sure everything is deleted.
                        self._sessionInstance.delete(session_id)
                    else:
                        # Check expiration time
                        if session_timestamp+self._sessionInstance.session_ttl < current_time:
                            # Remove expired session
                            self._sessionInstance.delete(session_id)
                            self.removed_sessions += 1
                self.last_run_time = current_time
            except (KeyboardInterrupt, SystemExit) as exit_exc:
                self.log(logging.DEBUG, 'Caught exit exception in run(): %s', exit_exc)
                self.enabled = False
            except Exception:
                # Catch all exceptions to avoid thread being killed.
                self.log(logging.ERROR, 'Unhandled exception in run()', exc_info=True)

            # Sleeping until next turn
            self._stop_event.wait(self._interval)

        self.log(logging.DEBUG, 'Exiting run()')
        return # CleanUpThread.run()


########################################################################
# Initialize web session object
########################################################################

global session_store
session_store = Session(
    session_ttl=web2ldapcnf.session_remove,
    crossCheckVars=web2ldapcnf.session_checkvars,
    maxSessionCount=web2ldapcnf.session_limit,
    max_session_count_per_ip=web2ldapcnf.session_per_ip_limit,
)
logger.debug('Initialized web2ldap session store %r', session_store)

global cleanUpThread
cleanUpThread = CleanUpThread(session_store, interval=5)
cleanUpThread.start()
logger.debug('Started clean-up thread %s[%x]', cleanUpThread.__class__.__name__, id(cleanUpThread))
