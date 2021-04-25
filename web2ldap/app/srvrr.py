# -*- coding: utf-8 -*-
"""
web2ldap.app.srvrr: chase SRV RRs

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2021 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from ..web.forms import Select as SelectField
from .gui import (
    footer,
    main_menu,
    top_section,
)

SRVRR_TMPL = """
<h1>Entry located via DNS</h1>
%s\n%s
  %s might be located on different host:
  <p>%s</p>
  <fieldset title="User account info">
    <p>
      to host:port %s (%s)
      with identification search below %s.
    </p>
    <table summary="User account info">
      <tr>
        <td>Bind as</td>
        <td>
          <input name="who" maxlength="1024" size="40" value="%s">
        </td>
      </tr>
      <tr>
        <td>with password</td>
        <td>
          <input type="password" name="cred" maxlength="200" size="25" value="">
        </td>
      </tr>
    </table>
    <p>
      <input type="submit" value="%s">
    </p>
  </fieldset>
"""


def w2l_chasesrvrecord(app, host_list):
    """
    Present an input form to change to a server located via DNS SRV RR
    """
    host_select_field = SelectField(
        'host', 'Host selection', 1,
        options=host_list,
        default=host_list[0],
        ignoreCase=1,
    )
    top_section(
        app,
        'LDAP server located via DNS',
        main_menu(app),
        context_menu_list=[],
        main_div_id='Input'
    )
    app.outf.write(
        SRVRR_TMPL % (
            app.begin_form(app.command, 'POST'),
            app.form.hidden_field_html('dn', app.dn, u''),
            app.form.s2d(app.dn),
            host_select_field.input_html(),
            '', '', '', ''
            '',
            'Change host',
        )
    )
    app.form.hidden_fields(
        app.outf,
        ignore_fields={'ldapurl', 'host', 'dn', 'who', 'cred'},
    )
    app.outf.write('</form>\n')

    footer(app)
