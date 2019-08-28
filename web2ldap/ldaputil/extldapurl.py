# -*- coding: utf-8 -*-
"""
ldaputil.ldapurl - extended LDAPUrl class

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0.ldapurl


LDAPSEARCH_TMPL = 'ldapsearch -LL -H "{uri}" {tls} -b "{dn}" -s {scope} {auth} "{filterstr}" {attrs}'


class ExtendedLDAPUrl(ldap0.ldapurl.LDAPUrl):
    """
    Class for LDAP URLs passed as query string derived from LDAPUrl
    """
    attr2extype = {
        'who': 'bindname',
        'cred': 'X-BINDPW',
        'x_startTLS': 'x-starttls',
        'saslMech': 'x-saslmech',
        'saslAuthzId': 'x-saslauthzid',
        'saslRealm': 'x-saslrealm',
    }

    def get_starttls_extop(self, min_starttls):
        """
        Returns a value indicating whether StartTLS ext.op. shall be used.
        Argument min_starttls indicates the minimum security level requested.
        0 No
        1 Yes, if possible. Proceed if not possible.
        2 Yes, mandantory. Abort if not possible.
        """
        if not self.extensions:
            return min_starttls
        try:
            ext_starttls = self.extensions.get('startTLS', self.extensions['starttls'])
        except KeyError:
            try:
                result = int(self.x_startTLS or '0')
            except ValueError:
                raise ValueError(u'LDAP URL extension x-starttls must be integer 0, 1 or 2.')
        else:
            result = int(ext_starttls.critical) + int(ext_starttls.extype.lower() == 'starttls')
        return max(result, min_starttls) # get_starttls_extop()

    def ldapsearch_cmd(self):
        """
        Returns string with OpenLDAP compatible ldapsearch command.
        """
        if self.attrs is None:
            attrs_str = ''
        else:
            attrs_str = ' '.join(self.attrs)
        scope_str = {
            0: 'base',
            1: 'one',
            2: 'sub',
            3: 'children',
        }[self.scope]
        if self.saslMech:
            auth_str = '-Y "{saslmech}"'.format(saslmech=self.saslMech)
        elif self.who:
            auth_str = '-x -D "{who}" -W'.format(who=self.who or '')
        else:
            auth_str = '-x -D "" -w ""'
        if self.x_startTLS:
            tls_str = '-ZZ'
        else:
            tls_str = ''
        if self.extensions:
            # FIX ME! Set extensions
            pass
        return LDAPSEARCH_TMPL.format(
            uri=self.connect_uri(),
            dn=self.dn,
            scope=scope_str,
            attrs=attrs_str,
            filterstr=self.filterstr or '(objectClass=*)',
            auth=auth_str,
            tls=tls_str,
        )
        # end of ldapsearch_cmd()
