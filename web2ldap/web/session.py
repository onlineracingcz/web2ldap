# -*- coding: utf-8 -*-
"""
web2ldap.web.session - server-side web session handling

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import string
import re
import time
import threading

from ldap0.pw import random_string

# length of session ID
SESSION_ID_LENGTH = 12

# characters to be used when generating session IDs
SESSION_ID_CHARS = string.ascii_letters + string.digits + '-._'

# regex pattern for checking valid session IDs
SESSION_ID_REGEX = '^[%s]+$' % (re.escape(SESSION_ID_CHARS))


##############################################################################
# Exception classes
##############################################################################

class SessionException(Exception):
    """Base class for session errors"""

    def __init__(self, *args):
        self.args = args


class CorruptData(SessionException):
    """Raised if data was corrupt, e.g. UnpicklingError occurred"""

    def __str__(self):
        return "Error during retrieving corrupted session data. Session deleted."


class GenerateIDError(SessionException):
    """Raised if generation of unique session ID failed."""

    def __init__(self, maxtry):
        self.maxtry = maxtry

    def __str__(self):
        return "Could not create new session id. Tried %d times." % (self.maxtry)


class SessionHijacked(SessionException):
    """Raised if hijacking of session was detected."""

    def __init__(self, failed_vars):
        self.failed_vars = failed_vars

    def __str__(self):
        return "Crosschecking of the following env vars failed: %s." % (self.failed_vars)


class MaxSessionCountExceeded(SessionException):
    """Raised if maximum number of sessions is exceeded."""

    def __init__(self, max_session_count):
        self.max_session_count = max_session_count

    def __str__(self):
        return "Maximum number of sessions exceeded. Limit is %d." % (self.max_session_count)


class MaxSessionPerIPExceeded(SessionException):
    """Raised if maximum number of sessions is exceeded."""

    def __init__(self, remote_ip, max_session_count):
        self.remote_ip = remote_ip
        self.max_session_count = max_session_count

    def __str__(self):
        return "Maximum number of sessions exceeded for %r. Limit is %d." % (
            self.remote_ip,
            self.max_session_count,
        )


class BadSessionId(SessionException):
    """Raised if session ID not found in session dictionary."""

    def __init__(self, session_id):
        self.session_id = session_id

    def __str__(self):
        return "No session with key %s." % (self.session_id)


class InvalidSessionId(SessionException):
    """Raised if session ID not found in session dictionary."""

    def __init__(self, session_id):
        self.session_id = session_id

    def __str__(self):
        return "No session with key %s." % (self.session_id)


class WebSession:
    """
    The session class which handles storing and retrieving of session data
    in a dictionary-like sessiondict object.
    """
    dict_class = dict

    def __init__(
            self,
            session_ttl=0,
            session_check_vars=None,
            max_sessions=None,
        ):
        """
        dictobj
            has to be a instance of a dictionary-like object
            (e.g. derived from UserDict or shelve)
        session_ttl
            Amount of time (secs) after which a session
            expires and the session data is silently deleted.
            A InvalidSessionId exception is raised in this case if
            the application tries to access the session ID again.
        session_check_vars
            List of keys of variables cross-checked for each
            retrieval of session data in retrieve(). If None
            SESSION_CROSSCHECKVARS is used.
        max_sessions
            Maximum number of valid sessions. This affects
            behaviour of retrieve() which raises.
            None means unlimited number of sessions.
        """
        self.sessiondict = self.dict_class()
        self.session_ttl = session_ttl
        self._session_lock = threading.Lock()
        self.session_check_vars = session_check_vars
        self.max_sessions = max_sessions
        self.sessionCounter = 0
        self.expired_counter = 0
        self.session_id_len = SESSION_ID_LENGTH
        self.session_id_chars = SESSION_ID_CHARS
        self.session_id_re = re.compile(SESSION_ID_REGEX)
        # end of WebSession.__init__()

    def _validateSessionIdFormat(self, session_id):
        """
        Validate the format of session_id. Implementation
        has to match IDs produced in method _generateSessionID()
        """
        if (
                len(session_id) != self.session_id_len or
                self.session_id_re.match(session_id) is None
            ):
            raise BadSessionId(session_id)

    @staticmethod
    def _check_env(stored_env, env):
        """
        Returns a list of keys of items which differ in
        stored_env and env.
        """
        return [
            skey
            for skey, sval in stored_env.items()
            if skey not in env or sval != env[skey]
        ]

    def _generateCrosscheckEnv(self, env):
        """
        Generate a dictionary of env vars for session cross-checking
        """
        return {
            skey: env[skey]
            for skey in self.session_check_vars
            if skey in env
        }

    def _generateSessionID(self, maxtry=1):
        """
        Generate a new random and unique session id string
        """
        newid = random_string(alphabet=SESSION_ID_CHARS, length=self.session_id_len)
        tried = 0
        while newid in self.sessiondict:
            tried += 1
            if maxtry and tried >= maxtry:
                raise GenerateIDError(maxtry)
            newid = random_string(alphabet=SESSION_ID_CHARS, length=self.session_id_len)
        return newid

    def save(self, session_id, session_data):
        """
        Store session_data under session_id.
        """
        assert isinstance(session_id, str), TypeError('Expected session_id to be str, got %r' % (session_id))
        self._session_lock.acquire()
        try:
            # Store session data with timestamp
            self.sessiondict[session_id] = (time.time(), session_data)
        finally:
            self._session_lock.release()
        return session_id

    def delete(self, session_id):
        """
        Delete session_data referenced by session_id.
        """
        assert isinstance(session_id, str), TypeError('Expected session_id to be str, got %r' % (session_id))
        # Delete the session data
        self._session_lock.acquire()
        try:
            if session_id in self.sessiondict:
                del self.sessiondict[session_id]
            if '__session_checkvars__'+session_id in self.sessiondict:
                del self.sessiondict['__session_checkvars__'+session_id]
        finally:
            self._session_lock.release()
        return session_id

    def retrieve(self, session_id, env):
        """
        Retrieve session data
        """
        assert isinstance(session_id, str), TypeError('Expected session_id to be str, got %r' % (session_id))
        self._validateSessionIdFormat(session_id)
        session_vars_key = '__session_checkvars__'+session_id
        # Check if session id exists
        if  (
                session_id not in self.sessiondict or
                session_vars_key not in self.sessiondict
            ):
            raise InvalidSessionId(session_id)
        # Read the timestamped session data
        self._session_lock.acquire()
        try:
            session_checkvars = self.sessiondict[session_vars_key]
            timestamp, session_data = self.sessiondict[session_id]
        finally:
            self._session_lock.release()
        current_time = time.time()
        # Check if session is already expired
        if self.session_ttl and current_time > timestamp+self.session_ttl:
            # Remove expired session entry and raise exception
            # Check if application should be able to allow relogin
            self.delete(session_id)
            raise InvalidSessionId(session_id)
        failed_vars = self._check_env(session_checkvars, env)
        if failed_vars:
            # Remove session entry
            raise SessionHijacked(failed_vars)
        # Everything's ok => return the session data
        return session_data

    def new(self, env=None):
        """
        Store session data under session id
        """
        env = env or {}
        if self.max_sessions and len(self.sessiondict)/2+1 > self.max_sessions:
            raise MaxSessionCountExceeded(self.max_sessions)
        self._session_lock.acquire()
        try:
            # generate completely new session data entry
            session_id = self._generateSessionID(maxtry=3)
            # Store session data with timestamp if session ID
            # was created successfully
            self.sessiondict[session_id] = (time.time(), '_created_')
            self.sessiondict['__session_checkvars__'+session_id] = self._generateCrosscheckEnv(env)
            self.sessionCounter += 1
        finally:
            self._session_lock.release()
        return session_id

    def expire(self):
        """
        Search for expired session entries and delete them.

        Returns integer counter of deleted sessions as result.
        """
        current_time = time.time()
        expired = 0
        for session_id in list(self.sessiondict.keys()):
            if not session_id.startswith('__'):
                try:
                    session_timestamp = self.sessiondict[session_id][0]
                except InvalidSessionId:
                    # Avoid race condition. The session might have been
                    # deleted in the meantime. But make sure everything is deleted.
                    self.delete(session_id)
                else:
                    # Check expiration time
                    if session_timestamp+self.session_ttl < current_time:
                        self.delete(session_id)
                        expired += 1
        self.expired_counter += expired
        return expired
