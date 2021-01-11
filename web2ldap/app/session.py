# -*- coding: utf-8 -*-
"""
web2ldap.app.session: The session handling thingy

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import time
import collections
import logging
import threading

import web2ldap.web.session
from web2ldap.web.helper import get_remote_ip

from web2ldap.ldapsession import LDAPSession
from web2ldap.log import logger, LogHelper
import web2ldapcnf


class InvalidSessionInstance(web2ldap.web.session.SessionException):
    """
    Exception raised in case of invalid session
    """


class WrongSessionCookie(web2ldap.web.session.SessionException):
    """
    Exception raised in case of invalid cookie
    """


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
            max_session_count_per_ip=None,
        ):
        web2ldap.web.session.WebSession.__init__(
            self,
            dictobj,
            session_ttl,
            crossCheckVars,
            maxSessionCount,
        )
        self.max_concurrent_sessions = 0
        self.remote_ip_sessions = collections.defaultdict(set)
        self.session_ip_addr = {}
        self.max_session_count_per_ip = max_session_count_per_ip or self.maxSessionCount/4
        self.remote_ip_counter = collections.Counter()
        self.expiry_thread = ExpiryThread(self, interval=5)
        self.expiry_thread.start()
        logger.debug(
            'Started clean-up thread %s[%x]',
            self.expiry_thread.__class__.__name__,
            id(self.expiry_thread),
        )

    def new(self, env=None):
        self.expire()
        self.log(logging.DEBUG, 'new(): creating a new session')
        remote_ip = get_remote_ip(env)
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
        current_concurrent_sessions = len(self.sessiondict) // 2
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
        # end of _remove_ip_assoc()

    def rename(self, old_sid, env):
        session_data = self.retrieveSession(old_sid, env)
        new_sid = self.new(env)
        self.save(new_sid, session_data)
        web2ldap.web.session.WebSession.delete(self, old_sid)
        # Set new remote IP associations
        remote_ip = get_remote_ip(env)
        self.session_ip_addr[new_sid] = remote_ip
        # Remove old remote IP associations
        self._remove_ip_assoc(old_sid, remote_ip)
        return new_sid

    def delete(self, sid):
        assert isinstance(sid, str), TypeError('Expected sid to be str, got %r' % (sid))
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
        # end of delete()

    def expire(self):
        expired = web2ldap.web.session.WebSession.expire(self)
        if expired:
            self.log(logging.INFO, 'expire() removed %d expired sessions', expired)
        return expired
        # end of expire()


class ExpiryThread(web2ldap.web.session.ExpiryThread, LogHelper):
    """
    Thread class for clean-up thread

    Mainly it overrides web2ldap.web.session.ExpiryThread.run()
    to call ldapSession.unbind().
    """


    def __init__(self, *args, **kwargs):
        web2ldap.web.session.ExpiryThread.__init__(self, *args, **kwargs)
        self.run_counter = 0
        self.enabled = True

    def run(self):
        """Thread function for cleaning up session database"""
        self.log(
            logging.DEBUG,
            'Entering .run() cleaning %s[%x]',
            self._sessionInstance.__class__.__name__,
            id(self._sessionInstance),
            )
        while self.enabled and not self._stop_event.isSet():
            self.run_counter += 1
            try:
                self._sessionInstance.expire()
            except (KeyboardInterrupt, SystemExit) as exit_exc:
                self.log(logging.DEBUG, 'Caught exit exception in run(): %s', exit_exc)
                self.enabled = False
            except Exception:
                # Catch all exceptions to avoid thread being killed.
                self.log(logging.ERROR, 'Unhandled exception in run()', exc_info=True)

            # Sleeping until next turn
            self._stop_event.wait(self._interval)

        self.log(logging.DEBUG, 'Exiting run()')
        # end of ExpiryThread.run()


########################################################################
# Initialize web session object
########################################################################

_SESSION_STORE_LOCK = threading.Lock()
_SESSION_STORE = None

def session_store():
    global _SESSION_STORE_LOCK
    global _SESSION_STORE
    with _SESSION_STORE_LOCK:
        if _SESSION_STORE is None:
            _SESSION_STORE = Session(
                session_ttl=web2ldapcnf.session_remove,
                crossCheckVars=web2ldapcnf.session_checkvars,
                maxSessionCount=web2ldapcnf.session_limit,
                max_session_count_per_ip=web2ldapcnf.session_per_ip_limit,
            )
            logger.debug(
                'Initialized web2ldap session store %s[%x]',
                _SESSION_STORE.__class__.__name__,
                id(_SESSION_STORE),
            )
    return _SESSION_STORE
