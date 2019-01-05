# -*- coding: utf-8 -*-
"""
web2ldap.app.srvrr: chase SRV RRs

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import pyweblib.forms,web2ldap.app.gui

def w2l_ChaseSRVRecord(sid,outf,command,form,ls,dn,host_list):

  host_select_field = pyweblib.forms.Select(
    'host','Host selection',1,
    options=host_list,default=host_list[0],ignoreCase=1
  )
  web2ldap.app.gui.TopSection(
    sid,outf,command,form,ls,dn,
    'LDAP server located via DNS',
    web2ldap.app.gui.MainMenu(sid,form,ls,dn),
    context_menu_list=[],
    main_div_id='Input'
  )
  outf.write("""
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
    """  % (
      form.beginFormHTML(command,sid,'POST'),
      form.hiddenFieldHTML('dn',dn,u''),
      form.utf2display(dn),
      host_select_field.inputHTML(),
      # <fieldset>
        '','','',''
        '',
        'Change host',
      # </fieldset>
    )
  )
  form.hiddenInputFields(outf,['ldapurl','host','dn','who','cred'])
  outf.write('</form>\n')
  web2ldap.app.gui.Footer(outf,form)
