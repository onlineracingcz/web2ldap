# -*- coding: ascii -*-
"""
ldaputil.ldapurl - extended LDAPUrl class

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

import ldap0.ldapurl


class ExtendedLDAPUrl(ldap0.ldapurl.LDAPUrl):
    """
    Class for LDAP URLs passed as query string derived from LDAPUrl
    """

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
                result = int(self.start_tls or '0')
            except ValueError:
                raise ValueError('LDAP URL extension x-starttls must be integer 0, 1 or 2.')
        else:
            result = int(ext_starttls.critical) + int(ext_starttls.extype.lower() == 'starttls')
        return max(result, min_starttls) # get_starttls_extop()
