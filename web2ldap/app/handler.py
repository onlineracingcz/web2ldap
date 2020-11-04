# -*- coding: utf-8 -*-
"""web2ldap.app.handler: base handler

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2020 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import sys
import inspect
import socket
import time
import urllib.parse
import logging
from collections import defaultdict

from ipaddress import ip_address, ip_network

import ldap0
from ldap0.ldapurl import is_ldapurl
from ldap0.dn import DNObj
from ldap0.err import PasswordPolicyException, PasswordPolicyExpirationWarning

import web2ldapcnf
import web2ldapcnf.hosts

COMMAND_COUNT = defaultdict(lambda: 0)

import web2ldap.web.forms
import web2ldap.web.helper
import web2ldap.web.session
from web2ldap.web.helper import get_remote_ip
import web2ldap.__about__
import web2ldap.ldaputil
import web2ldap.ldapsession
from web2ldap.ldaputil.extldapurl import ExtendedLDAPUrl
from web2ldap.ldapsession import LDAPSession
from web2ldap.log import LogHelper, logger, log_exception
# Import the application modules
import web2ldap.app.gui
import web2ldap.app.cnf
import web2ldap.app.passwd
import web2ldap.app.dit
import web2ldap.app.searchform
import web2ldap.app.locate
import web2ldap.app.search
import web2ldap.app.addmodifyform
import web2ldap.app.add
import web2ldap.app.modify
import web2ldap.app.dds
import web2ldap.app.delete
import web2ldap.app.params
import web2ldap.app.read
import web2ldap.app.conninfo
import web2ldap.app.login
import web2ldap.app.connect
import web2ldap.app.referral
import web2ldap.app.monitor
import web2ldap.app.groupadm
import web2ldap.app.rename
import web2ldap.app.urlredirect
import web2ldap.app.bulkmod
import web2ldap.app.srvrr
import web2ldap.app.schema.viewer
import web2ldap.app.metrics
from web2ldap.app.gui import exception_message, dns_available
from web2ldap.app.form import Web2LDAPForm
from web2ldap.app.session import session_store
from web2ldap.app.schema.syntaxes import syntax_registry
from web2ldap.ldaputil import AD_LDAP49_ERROR_CODES, AD_LDAP49_ERROR_PREFIX
from web2ldap.app.core import ErrorExit
if dns_available:
    from web2ldap.ldaputil.dns import dc_dn_lookup

SCOPE2COMMAND = {
    None:'search',
    ldap0.SCOPE_BASE:'read',
    ldap0.SCOPE_ONELEVEL:'search',
    ldap0.SCOPE_SUBTREE:'search',
    ldap0.SCOPE_SUBORDINATE:'search',
}

CONNTYPE2URLSCHEME = {
    0: 'ldap',
    1: 'ldap',
    2: 'ldaps',
    3: 'ldapi',
}

FORM_CLASS = {}
logger.debug('Registering Form classes')
for _, cls in inspect.getmembers(sys.modules['web2ldap.app.form'], inspect.isclass):
    if cls.__name__.startswith('Web2LDAPForm_') and cls.command is not None:
        logger.debug('Register class %s for command %r', cls.__name__, cls.command)
        FORM_CLASS[cls.command] = cls

SIMPLE_MSG_HTML = """
<html>
  <head>
    <title>Note</title>
  </head>
  <body>
    {message}
  </body>
</html>
"""

COMMAND_FUNCTION = {
    '': web2ldap.app.connect.w2l_connect,
    'disconnect': None,
    'locate': web2ldap.app.locate.w2l_locate,
    'monitor': web2ldap.app.monitor.w2l_monitor,
    'urlredirect': web2ldap.app.urlredirect.w2l_urlredirect,
    'searchform': web2ldap.app.searchform.w2l_searchform,
    'search': web2ldap.app.search.w2l_search,
    'add': web2ldap.app.add.w2l_add,
    'modify': web2ldap.app.modify.w2l_modify,
    'dds': web2ldap.app.dds.w2l_dds,
    'bulkmod': web2ldap.app.bulkmod.w2l_bulkmod,
    'delete': web2ldap.app.delete.w2l_delete,
    'dit': web2ldap.app.dit.w2l_dit,
    'rename': web2ldap.app.rename.w2l_rename,
    'passwd': web2ldap.app.passwd.w2l_passwd,
    'read': web2ldap.app.read.w2l_read,
    'conninfo': web2ldap.app.conninfo.w2l_conninfo,
    'params': web2ldap.app.params.w2l_params,
    'login': web2ldap.app.login.w2l_login,
    'groupadm': web2ldap.app.groupadm.w2l_groupadm,
    'oid': web2ldap.app.schema.viewer.w2l_schema_viewer,
}

if web2ldap.app.metrics.METRICS_AVAIL:
    COMMAND_FUNCTION['metrics'] = web2ldap.app.metrics.w2l_metrics


syntax_registry.check()


def check_access(env, command):
    """
    simple access control based on client IP address
    """
    remote_addr = ip_address(env[web2ldapcnf.httpenv_remote_addr.split(',')[-1].strip()])
    access_allowed = web2ldapcnf.access_allowed.get(
        command,
        web2ldapcnf.access_allowed['_']
    )
    for net in access_allowed:
        if remote_addr in ip_network(net, strict=False):
            return True
    return False


class AppHandler(LogHelper):
    """
    Class implements web application entry point
    and dispatches requests to use-case functions w2l_*()
    """

    def __init__(self, env, outf):
        self.current_access_time = time.time()
        self.inf = env['wsgi.input']
        self.outf = outf
        self.env = env
        self.env.update(web2ldapcnf.httpenv_override)
        self.script_name = self.env['SCRIPT_NAME']
        self.command, self.sid = self.path_info(env)
        self.form = None
        self.ls = None
        # class attributes later set by dn property method
        self.dn_obj = None
        self.query_string = env.get('QUERY_STRING', '')
        self.ldap_url = None
        self.schema = None
        self.cfg_key = None
        self._session_store = session_store()
        # initialize some more if query string is an LDAP URL
        if is_ldapurl(self.query_string):
            self.ldap_url = ExtendedLDAPUrl(self.query_string)
            if not self.command:
                self.command = SCOPE2COMMAND[self.ldap_url.scope]
        # end of __init__()

    @property
    def dn(self):
        """
        get current DN
        """
        return str(self.dn_obj)

    @dn.setter
    def dn(self, dn):
        """
        set current DN and related class attributes
        """
        assert ldap0.dn.is_dn(dn), ValueError(
            'Expected LDAP DN as dn, was %r' % (dn)
        )
        self.dn_obj = DNObj.from_str(dn)
        if self.ls and self.ls.uri:
            self.dn_obj.charset = self.ls.charset
            self.schema = self.ls.get_sub_schema(
                self.dn,
                self.cfg_param('_schema', None),
                self.cfg_param('supplement_schema', None),
                self.cfg_param('schema_strictcheck', True),
            )

    @property
    def naming_context(self):
        if self.ls and self.ls.uri:
            res = self.ls.get_search_root(self.dn)
        else:
            res = DNObj((()))
        return res

    @property
    def audit_context(self):
        if self.ls and self.ls.uri:
            res = self.ls.get_audit_context(self.naming_context)
        else:
            res = None
        return res

    @property
    def parent_dn(self):
        """
        get parent DN of current DN
        """
        return str(self.dn_obj.parent())

    @property
    def ldap_dn(self):
        """
        get LDAP encoding (UTF-8) of current DN
        """
        return bytes(self.dn_obj)

    def cfg_param(self, param_key, default):
        if self.ls and self.ls.uri:
            cfg_url = self.ls.uri
        else:
            cfg_url = 'ldap://'
        return web2ldap.app.cnf.LDAP_DEF.get_param(
            cfg_url,
            self.naming_context or u'',
            param_key,
            default,
        )

    @property
    def binddn_mapping(self):
        """
        get parameter 'binddn_mapping' from cascaded configuration
        """
        return self.cfg_param('binddn_mapping', u'ldap:///_??sub?(uid={user})')

    def anchor(
            self,
            command,
            anchor_text,
            form_parameters,
            target=None,
            title=None,
            anchor_id=None,
        ):
        """
        Build the HTML text of a anchor with form parameters
        """
        assert isinstance(command, str), \
            TypeError('command must be str, but was %r', command)
        assert isinstance(anchor_text, str), \
            TypeError('anchor_text must be str, but was %r', anchor_text)
        assert anchor_id is None or isinstance(anchor_id, str), \
            TypeError('anchor_id must be None or str, but was %r', anchor_id)
        assert target is None or isinstance(target, str), \
            TypeError('target must be None or str, but was %r', target)
        assert title is None or isinstance(title, str), \
            TypeError('title must be None or str, but was %r', title)
        target_attr = ''
        if target:
            target_attr = ' target="%s"' % (target)
        title_attr = ''
        if title:
            title_attr = ' title="%s"' % (self.form.utf2display(title).replace(' ', '&nbsp;'))
        if anchor_id:
            anchor_id = '#%s' % (self.form.utf2display(anchor_id))
        res = '<a class="CL"%s%s href="%s?%s%s">%s</a>' % (
            target_attr,
            title_attr,
            self.form.action_url(command, self.sid),
            '&amp;'.join([
                '%s=%s' % (param_name, urllib.parse.quote(param_value))
                for param_name, param_value in form_parameters
            ]),
            anchor_id or '',
            anchor_text,
        )
        assert isinstance(res, str), TypeError('res must be str, was %r', res)
        return res

    def begin_form(
            self,
            command,
            method,
            target=None,
            enctype='application/x-www-form-urlencoded',
        ):
        """
        convenience wrapper for Web2LDAPForm.begin_form()
        which sets non-zero sid
        """
        return self.form.begin_form(
            command,
            self.sid,
            method,
            target=target,
            enctype=enctype,
        )

    def form_html(
            self,
            command,
            submitstr,
            method,
            form_parameters,
            extrastr='',
            target=None
        ):
        """
        Build the HTML text of a submit form
        """
        form_str = [self.begin_form(command, method, target)]
        for param_name, param_value in form_parameters:
            form_str.append(self.form.hiddenFieldHTML(param_name, param_value, u''))
        form_str.append(
            '<p>\n<input type="submit" value="%s">\n%s\n</p>\n</form>' % (
                submitstr,
                extrastr,
            )
        )
        return '\n'.join(form_str)

    def dispatch(self):
        """
        Execute function for self.command
        """
        assert isinstance(self.dn, str), \
            TypeError(
                "Class attribute %s.dn must be str, was %r" % (
                    self.__class__.__name__,
                    self.dn,
                )
            )
        assert isinstance(self.ldap_url, ExtendedLDAPUrl), \
            TypeError(
                "Class attribute %s.ldap_url must be LDAPUrl instance, was %r" % (
                    self.__class__.__name__,
                    self.ldap_url,
                )
            )
        self.log(logging.DEBUG, '%s.ldap_url is %s', self.__class__.__name__, self.ldap_url)
        self.log(
            logging.DEBUG,
            'Dispatch command %r to function %s.%s()',
            self.command,
            COMMAND_FUNCTION[self.command].__module__,
            COMMAND_FUNCTION[self.command].__name__,
        )
        COMMAND_FUNCTION[self.command](self)
        # end of dispatch()

    def path_info(self, env):
        """
        Extract the command and sid from PATH_INFO env var
        """
        path_info = env.get('PATH_INFO', '/')[1:]
        self.log(logging.DEBUG, 'splitting path_info %r', path_info)
        if not path_info:
            cmd, sid = '', ''
        else:
            # Work around broken web servers which adds the script name
            # to path info as well
            script_name = env['SCRIPT_NAME']
            if path_info.startswith(script_name):
                path_info = path_info[len(script_name):]
            try:
                cmd, sid = path_info.split('/', 1)
            except ValueError:
                cmd, sid = path_info, ''
        self.log(logging.DEBUG, 'split path_info to (%r, %r)', cmd, sid)
        return cmd, sid # path_info()

    def display_dn(self, dn, commandbutton=False):
        """Display a DN as LDAP URL with or without button"""
        assert isinstance(dn, str), TypeError("Argument 'dn' must be str, was %r" % (dn,))
        dn_str = self.form.utf2display(dn or u'- World -')
        if commandbutton:
            command_buttons = [
                dn_str,
                self.anchor('read', 'Read', [('dn', dn)])
            ]
            return web2ldapcnf.command_link_separator.join(command_buttons)
        return dn_str

    def simple_message(
            self,
            title=u'',
            message=u'',
            main_div_id='Message',
            main_menu_list=None,
            context_menu_list=None,
        ):
        web2ldap.app.gui.top_section(
            self,
            title,
            main_menu_list,
            context_menu_list=context_menu_list,
            main_div_id=main_div_id,
        )
        self.outf.write(message)
        web2ldap.app.gui.footer(self)
        # end of simple_message()

    def simple_msg(self, msg):
        """
        Output HTML text.
        """
        web2ldap.app.gui.Header(self, 'text/html', self.form.accept_charset)
        self.outf.write(SIMPLE_MSG_HTML.format(message=msg))

    def url_redirect(
            self,
            redirect_msg,
            link_text='Continue&gt;&gt;',
            refresh_time=3,
            target_url=None,
        ):
        """
        Outputs HTML text with redirecting <head> section.
        """
        if self.form is None:
            self.form = Web2LDAPForm(None, self.env)
        target_url = target_url or self.script_name
        url_redirect_template_str = web2ldap.app.gui.read_template(
            self, None, u'redirect',
            tmpl_filename=web2ldapcnf.redirect_template,
        )
        if refresh_time:
            message_class = 'ErrorMessage'
        else:
            message_class = 'SuccessMessage'
        web2ldap.app.gui.Header(self, 'text/html', self.form.accept_charset)
        # Write out stub body with just a short redirect HTML snippet
        self.outf.write(
            url_redirect_template_str.format(
                refresh_time=refresh_time,
                target_url=target_url,
                message_class=message_class,
                redirect_msg=self.form.utf2display(redirect_msg),
                link_text=link_text,
            )
        )
        # end of url_redirect()

    def _new_session(self):
        """
        create new session
        """
        self.sid = self._session_store.new(self.env)
        self.ls = LDAPSession(
            get_remote_ip(self.env),
            web2ldapcnf.ldap_trace_level,
            web2ldapcnf.ldap_cache_ttl,
        )
        self.ls.cookie = self.form.set_cookie(str(id(self.ls)))
        self._session_store.save(self.sid, self.ls)
        # end of _get_session()

    def _get_session(self):
        """
        Restore old or initialize new web session object
        """
        if self.sid:
            # Session ID given => try to restore old session
            try:
                last_session_timestamp, _ = self._session_store.sessiondict[self.sid]
            except KeyError:
                pass
            self.ls = self._session_store.retrieveSession(self.sid, self.env)
            if not isinstance(self.ls, LDAPSession):
                raise web2ldap.app.session.InvalidSessionInstance()
            if self.ls.cookie:
                # Check whether HTTP_COOKIE contains the cookie of this particular session
                cookie_name = ''.join((self.form.cookie_name_prefix, str(id(self.ls))))
                if not (
                        cookie_name in self.form.cookies and
                        self.ls.cookie[cookie_name].value == self.form.cookies[cookie_name].value
                    ):
                    raise web2ldap.app.session.WrongSessionCookie()
            if web2ldapcnf.session_paranoid and \
               self.current_access_time-last_session_timestamp > web2ldapcnf.session_paranoid:
                # Store session with new session ID
                self.sid = self._session_store.rename(self.sid, self.env)
        else:
            self.ls = None
        # end of _get_session()

    def _del_session(self):
        """
        delete the current session
        """
        self._session_store.delete(self.sid)
        del self.ls
        self.sid = self.ls = None
        # end of _del_session()

    def _handle_delsid(self):
        """
        if del_sid form parameter is present then delete the obsolete session
        """
        try:
            del_sid = self.form.field['delsid'].value[0]
        except IndexError:
            return
        try:
            old_ls = self._session_store.retrieveSession(del_sid, self.env)
        except web2ldap.web.session.SessionException:
            pass
        else:
            # Remove session cookie
            self.form.unset_cookie(old_ls.cookie)
        # Explicitly remove old session
        self._session_store.delete(del_sid)
        # end of _handle_delsid()

    def _get_ldapconn_params(self):
        """
        Extract parameters either from LDAP URL in query string or real form input
        """
        if is_ldapurl(self.form.query_string):
            # Extract the connection parameters from a LDAP URL
            try:
                input_ldapurl = ExtendedLDAPUrl(self.form.query_string)
            except ValueError as err:
                raise ErrorExit(u'Error parsing LDAP URL: %s.' % (
                    self.form.utf2display(str(err))
                ))
            else:
                self.command = self.command or SCOPE2COMMAND[input_ldapurl.scope]
                if self.command in ('search', 'read'):
                    input_ldapurl.filterstr = input_ldapurl.filterstr or '(objectClass=*)'
                # Re-instantiate form based on command derived from LDAP URL
                self.form = FORM_CLASS.get(self.command, Web2LDAPForm)(self.inf, self.env)

        else:
            # Extract the connection parameters from form fields
            self._handle_delsid()
            if 'ldapurl' in self.form.input_field_names:
                # One form parameter with LDAP URL
                ldap_url_input = self.form.field['ldapurl'].value[0]
                try:
                    input_ldapurl = ExtendedLDAPUrl(ldap_url_input)
                except ValueError as err:
                    raise ErrorExit(
                        u'Error parsing LDAP URL: %s.' % (err,)
                    )
            else:
                input_ldapurl = ExtendedLDAPUrl()
                conntype = int(self.form.getInputValue('conntype', [0])[0])
                input_ldapurl.urlscheme = CONNTYPE2URLSCHEME[conntype]
                input_ldapurl.hostport = self.form.getInputValue('host', [None])[0]
                input_ldapurl.x_startTLS = str(
                    web2ldap.ldapsession.START_TLS_REQUIRED * (conntype == 1)
                )

        # Separate parameters for dn, who, cred and scope
        # have predecence over parameters specified in LDAP URL

        dn = self.form.getInputValue('dn', [input_ldapurl.dn])[0]

        who = self.form.getInputValue('who', [None])[0]
        if who is None:
            if input_ldapurl.who is not None:
                who = input_ldapurl.who
        else:
            input_ldapurl.who = who

        cred = self.form.getInputValue('cred', [None])[0]
        if cred is None:
            if input_ldapurl.cred is not None:
                cred = input_ldapurl.cred
        else:
            input_ldapurl.cred = cred

        assert isinstance(input_ldapurl.dn, str), TypeError(
            "Type of 'input_ldapurl.dn' must be str, was %r" % (input_ldapurl.dn)
        )
        assert input_ldapurl.who is None or isinstance(input_ldapurl.who, str), TypeError(
            "Type of 'input_ldapurl.who' must be str, was %r" % (input_ldapurl.who)
        )
        assert input_ldapurl.cred is None or isinstance(input_ldapurl.cred, str), TypeError(
            "Type of 'input_ldapurl.cred' must be str, was %r" % (input_ldapurl.cred)
        )
        assert isinstance(dn, str), TypeError("Argument 'dn' must be str, was %r" % (dn))
        assert who is None or isinstance(who, str), TypeError(
            "Type of 'who' must be str, was %r" % (who)
        )
        assert cred is None or isinstance(cred, str), TypeError(
            "Type of 'cred' must be str, was %r" % (cred)
        )

        if not ldap0.dn.is_dn(dn, flags=1):
            raise ErrorExit(u'Invalid DN.')

        scope_str = self.form.getInputValue(
            'scope',
            [
                {False:str(input_ldapurl.scope), True:''}[input_ldapurl.scope is None]
            ]
        )[0]
        if scope_str:
            input_ldapurl.scope = int(scope_str)
        else:
            input_ldapurl.scope = None

        return input_ldapurl, dn, who, cred
        # end of _get_ldapconn_params()

    def ldap_error_msg(self, ldap_err, template='{error_msg}<br>{matched_dn}'):
        """
        Converts a LDAPError exception into HTML error message

        ldap_err
          LDAPError instance
        template
          Raw binary string to be used as template
          (must contain only a single placeholder)
        """
        matched_dn = None
        if isinstance(ldap_err, ldap0.TIMEOUT) or not ldap_err.args:
            error_msg = u''
        elif isinstance(ldap_err, ldap0.INVALID_CREDENTIALS) and \
            AD_LDAP49_ERROR_PREFIX in ldap_err.args[0].get('info', b''):
            ad_error_code_pos = (
                ldap_err.args[0]['info'].find(AD_LDAP49_ERROR_PREFIX)+len(AD_LDAP49_ERROR_PREFIX)
            )
            ad_error_code = int(ldap_err.args[0]['info'][ad_error_code_pos:ad_error_code_pos+3], 16)
            error_msg = u'%s:\n%s (%s)' % (
                ldap_err.args[0]['desc'].decode(self.ls.charset),
                ldap_err.args[0].get('info', b'').decode(self.ls.charset),
                AD_LDAP49_ERROR_CODES.get(ad_error_code, u'unknown'),
            )
        else:
            try:
                error_desc = ldap_err.args[0]['desc'].decode(self.ls.charset)
                error_info = ldap_err.args[0].get('info', b'').decode(self.ls.charset)
            except UnicodeDecodeError:
                error_msg = str(ldap_err)
            except (TypeError, IndexError):
                error_msg = str(ldap_err)
            else:
                error_msg = '{desc}: {info}'.format(
                    desc=error_desc,
                    info=error_info,
                )

            try:
                matched_dn = ldap_err.args[0].get('matched', b'').decode(self.ls.charset)
            except AttributeError:
                matched_dn = None
        error_msg = error_msg.replace(u'\r', '').replace(u'\t', '')
        error_msg_html = self.form.utf2display(error_msg, lf_entity='<br>')
        # Add matchedDN to error message HTML if needed
        if matched_dn:
            matched_dn_html = '<br>Matched DN: %s' % (self.form.utf2display(matched_dn))
        else:
            matched_dn_html = ''
        return template.format(
            error_msg=error_msg_html,
            matched_dn=matched_dn_html
        )

    def run(self):
        """
        Really process the request
        """
        self.log(logging.DEBUG, 'Entering .run()')

        # check for valid command
        if self.command not in COMMAND_FUNCTION:

            self.log(logging.WARN, 'Received invalid command %r', self.command)
            self.url_redirect(u'Invalid web2ldap command')
            return

        # count command
        COMMAND_COUNT[self.command or 'connect'] += 1

        # initialize Form instance
        self.form = FORM_CLASS.get(self.command, Web2LDAPForm)(self.inf, self.env)

        #---------------------------------------------------------------
        # try-except block for gracefully exception handling in the UI
        #---------------------------------------------------------------

        try:

            if self.command in FORM_CLASS and not is_ldapurl(self.form.query_string):
                # get the input fields
                self.form.getInputFields()

            # Check access here
            if not check_access(self.env, self.command):
                self.log(
                    logging.WARN,
                    'Access denied from %r to command %r',
                    self.env[web2ldapcnf.httpenv_remote_addr],
                    self.command,
                )
                raise ErrorExit(u'Access denied.')

            # Handle simple early-exit commands
            if self.command in {'', 'urlredirect', 'monitor', 'locate', 'metrics'}:
                COMMAND_FUNCTION[self.command](self)
                return

            self._get_session()

            if self.command == 'disconnect':
                # Remove session cookie
                self.form.unset_cookie(self.ls.cookie)
                # Explicitly remove old session
                self._session_store.delete(self.sid)
                self.sid = None
                # Redirect to start page to avoid people bookmarking disconnect URL
                self.url_redirect(u'Disconnecting...', refresh_time=0)
                return

            self.ldap_url, self.dn, who, cred = self._get_ldapconn_params()

            self.command = self.command or {
                None: 'searchform',
                ldap0.SCOPE_BASE: 'read',
                ldap0.SCOPE_ONELEVEL: 'search',
                ldap0.SCOPE_SUBTREE: 'search',
            }[self.ldap_url.scope]

            #-------------------------------------------------
            # Connect to LDAP server
            #-------------------------------------------------

            if (
                    dns_available
                    and self.ldap_url.hostport == ''
                    and self.ldap_url.urlscheme == 'ldap'
                    and (self.ls is None or self.ls.uri is None)
                ):
                # Force a SRV RR lookup for dc-style DNs,
                # create list of URLs to connect to
                dns_srv_rrs = dc_dn_lookup(self.dn)
                init_uri_list = [
                    ExtendedLDAPUrl(urlscheme='ldap', hostport=host, dn=self.dn).connect_uri()
                    for host in dns_srv_rrs
                ]
                if not init_uri_list:
                    # No host specified in user's input
                    self._session_store.delete(self.sid)
                    self.sid = None
                    web2ldap.app.connect.w2l_connect(
                        self,
                        h1_msg='Connect failed',
                        error_msg='No host specified.'
                    )
                    return
                if len(init_uri_list) == 1:
                    init_uri = init_uri_list[0]
                else:
                    # more than one possible servers => let user choose one
                    web2ldap.app.srvrr.w2l_chasesrvrecord(self, init_uri_list)
                    return
            elif self.ldap_url.hostport is not None:
                init_uri = str(self.ldap_url.connect_uri()[:])
            else:
                init_uri = None

            if init_uri and (
                    self.ls is None or self.ls.uri is None or init_uri != self.ls.uri
                ):
                # Delete current LDAPSession instance and create new
                self._del_session()
                self._new_session()
                # Check whether access to target LDAP server is allowed
                if web2ldapcnf.hosts.restricted_ldap_uri_list and \
                   init_uri not in web2ldap.app.cnf.LDAP_URI_LIST_CHECK_DICT:
                    raise ErrorExit(u'Only pre-configured LDAP servers allowed.')
                # set this to make .cfg_param() retrieve correct site-specific config parameters
                self.ls.uri = init_uri
                # Connect to new specified host
                self.ls.open(
                    init_uri,
                    self.cfg_param('timeout', web2ldap.ldapsession.LDAP_DEFAULT_TIMEOUT),
                    self.ldap_url.get_starttls_extop(
                        self.cfg_param('starttls', web2ldap.ldapsession.START_TLS_NO)
                    ),
                    self.env,
                    self.cfg_param('session_track_control', 0),
                    tls_options=self.cfg_param('tls_options', {}),
                )
                # Set host-/backend-specific timeout
                self.ls.l.timeout = self.cfg_param('timeout', 60)
                # Store session data in case anything goes wrong after here
                # to give the exception handler a good chance
                self._session_store.save(self.sid, self.ls)

            # from here the code assumes that there is a valid LDAPSession instance
            if self.ls is None:
                # probably somebody entered invalid URL => exit here
                self.url_redirect('No valid session!')
                return

            if self.ls.uri is None:
                self._session_store.delete(self.sid)
                self.sid = None
                web2ldap.app.connect.w2l_connect(
                    self,
                    h1_msg='Connect failed',
                    error_msg='No valid LDAP connection.'
                )
                return

            # Store session data in case anything goes wrong after here
            # to give the exception handler a good chance
            self._session_store.save(self.sid, self.ls)
            self.dn = self.dn

            login_mech = self.form.getInputValue(
                'login_mech',
                [self.ldap_url.saslMech or '']
            )[0].upper() or None

            if (
                    who is not None and
                    cred is None and
                    (login_mech or '').encode('ascii') not in ldap0.sasl.SASL_NONINTERACTIVE_MECHS
                ):
                # first ask for password in a login form
                web2ldap.app.login.w2l_login(
                    self,
                    login_msg='',
                    who=who, relogin=0, nomenu=1,
                    login_default_mech=self.ldap_url.saslMech
                )
                return

            if (
                    (who is not None and cred is not None)
                    or
                    (
                        login_mech is not None
                        and
                        login_mech.encode('ascii') in ldap0.sasl.SASL_NONINTERACTIVE_MECHS
                    )
                ):
                self.dn = self.dn
                # real bind operation
                login_search_root = self.form.getInputValue(
                    'login_search_root',
                    [self.naming_context],
                )[0]
                try:
                    self.ls.bind(
                        who,
                        cred or '',
                        login_mech,
                        ''.join((
                            self.form.getInputValue('login_authzid_prefix', [''])[0],
                            self.form.getInputValue(
                                'login_authzid',
                                [self.ldap_url.saslAuthzId or ''],
                            )[0],
                        )) or None,
                        self.form.getInputValue('login_realm', [self.ldap_url.saslRealm])[0],
                        self.binddn_mapping,
                        loginSearchRoot=login_search_root,
                    )
                except ldap0.NO_SUCH_OBJECT as err:
                    web2ldap.app.login.w2l_login(
                        self,
                        login_msg=self.ldap_error_msg(err),
                        who=who, relogin=True
                    )
                    return
            else:
                # anonymous access
                self.ls.init_rootdse()

            # Check for valid LDAPSession and connection to provide reasonable
            # error message instead of logging exception in case user is playing
            # with manually generated URLs
            if not isinstance(self.ls, LDAPSession) or self.ls.uri is None:
                self.url_redirect(u'No valid LDAP connection!')
                return
            # Store session data in case anything goes wrong after here
            # to give the exception handler a good chance
            self._session_store.save(self.sid, self.ls)

            # trigger update of various DN-related class properties
            self.dn = self.dn

            # Execute the command module
            try:
                self.dispatch()
            except ldap0.SERVER_DOWN:
                # Try to reconnect to LDAP server and retry action
                self.ls.l.reconnect(self.ls.uri)
                self.dispatch()
            else:
                # Store current session
                self._session_store.save(self.sid, self.ls)

        except web2ldap.web.forms.FormException as form_error:
            log_exception(self.env, self.ls, self.dn, web2ldapcnf.log_error_details)
            exception_message(
                self,
                u'Error parsing form',
                u'Error parsing form:<br>%s' % (
                    self.form.utf2display(str(form_error)),
                ),
            )

        except ldap0.SERVER_DOWN as err:
            # Server is down and reconnecting impossible => remove session
            self._session_store.delete(self.sid)
            self.sid = None
            # Redirect to entry page
            web2ldap.app.connect.w2l_connect(
                self,
                h1_msg='Connect failed',
                error_msg='Connecting to %s impossible!<br>%s' % (
                    self.form.utf2display(init_uri or '-'),
                    self.ldap_error_msg(err)
                )
            )

        except ldap0.NO_SUCH_OBJECT as ldap_err:

            if dns_available:
                # first try to lookup dc-style DN via DNS
                host_list = dc_dn_lookup(self.dn)
                self.log(logging.DEBUG, 'host_list = %r', host_list)
                if host_list and ExtendedLDAPUrl(self.ls.uri).hostport not in host_list:
                    # Found LDAP server for this naming context via DNS SRV RR
                    web2ldap.app.srvrr.w2l_chasesrvrecord(self, host_list)
                    return

            # Normal error handling
            log_exception(self.env, self.ls, self.dn, web2ldapcnf.log_error_details)
            failed_dn = self.dn
            if 'matched' in ldap_err.args[0]:
                self.dn = ldap_err.args[0]['matched'].decode(self.ls.charset)
            exception_message(
                self,
                u'No such object',
                self.ldap_error_msg(
                    ldap_err,
                    template='{{error_msg}}<br>{0}{{matched_dn}}'.format(
                        self.display_dn(failed_dn)
                    )
                )
            )

        except (ldap0.PARTIAL_RESULTS, ldap0.REFERRAL) as err:
            web2ldap.app.referral.w2l_chasereferral(self, err)

        except (
                ldap0.INSUFFICIENT_ACCESS,
                ldap0.STRONG_AUTH_REQUIRED,
                ldap0.INAPPROPRIATE_AUTH,
                web2ldap.ldapsession.UsernameNotFound,
            ) as err:
            web2ldap.app.login.w2l_login(
                self,
                who=u'',
                login_msg=self.ldap_error_msg(err),
                relogin=True,
            )

        except (
                ldap0.INVALID_CREDENTIALS,
            ) as err:
            web2ldap.app.login.w2l_login(
                self,
                login_msg=self.ldap_error_msg(err),
                who=who, relogin=True,
            )

        except (
                web2ldap.ldapsession.InvalidSimpleBindDN,
                web2ldap.ldapsession.UsernameNotUnique,
            ) as err:
            web2ldap.app.login.w2l_login(
                self,
                login_msg=self.form.utf2display(str(err)),
                who=who, relogin=True,
            )

        except PasswordPolicyExpirationWarning as err:
            # Setup what's required for executing command 'passwd'
            self.dn = self.ls.l.whoami_s()[3:] or err.who
            # Output the change password form
            web2ldap.app.passwd.passwd_form(
                self,
                u'',
                self.dn,
                None,
                'Password change needed',
                self.form.utf2display(
                    u'Password will expire in %s!' % (
                        web2ldap.app.gui.ts2repr(
                            web2ldap.app.schema.syntaxes.Timespan.time_divisors,
                            u' ',
                            err.timeBeforeExpiration,
                        )
                    )
                ),
            )

        except PasswordPolicyException as err:
            # Setup what's required for executing command 'passwd'
            self.dn = self.ls.l.get_whoami_dn() or err.who
            # Output the change password form
            web2ldap.app.passwd.passwd_form(
                self,
                u'',
                self.dn,
                None,
                'Password change needed',
                self.form.utf2display(err.desc)
            )

        except (
                socket.error,
                socket.gaierror,
                IOError,
                UnicodeError,
            ) as err:
            log_exception(self.env, self.ls, self.dn, web2ldapcnf.log_error_details)
            exception_message(
                self,
                u'Unhandled %s' % err.__class__.__name__,
                self.form.utf2display(str(err)),
            )

        except ldap0.LDAPError as ldap_err:
            log_exception(self.env, self.ls, self.dn, web2ldapcnf.log_error_details)
            exception_message(
                self,
                u'Unhandled %s' % ldap_err.__class__.__name__,
                self.ldap_error_msg(ldap_err),
            )

        except ErrorExit as error_exit:
            self.log(logging.WARN, 'ErrorExit: %r', error_exit.Msg)
            exception_message(
                self,
                u'Error',
                error_exit.Msg,
            )

        except web2ldap.web.session.MaxSessionPerIPExceeded as session_err:
            self.log(logging.WARN, str(session_err))
            self.simple_msg(
                u'Client %s exceeded limit of max. %d sessions! Try later...' % (
                    session_err.remote_ip,
                    session_err.max_session_count,
                )
            )

        except web2ldap.web.session.MaxSessionCountExceeded as session_err:
            self.log(logging.WARN, str(session_err))
            self.simple_msg(u'Too many web sessions! Try later...')

        except web2ldap.web.session.SessionException:
            if self.command == 'disconnect':
                # Probably already disconnected => ignore exception and redirect to start page
                self.url_redirect(u'Disconnecting...', refresh_time=0)
            else:
                log_exception(self.env, self.ls, self.dn, web2ldapcnf.log_error_details)
                self.url_redirect(u'Session handling error.')

        except Exception:
            if hasattr(self, 'ls'):
                error_ls = self.ls
            else:
                error_ls = None
            log_exception(self.env, error_ls, self.dn, web2ldapcnf.log_error_details)
            self.simple_msg(u'Unhandled error!')

        # end of run()
