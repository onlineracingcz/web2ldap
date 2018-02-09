# -*- coding: utf-8 -*-
"""
w2lapp.srvrr: chase SRV RRs

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import pyweblib.forms,w2lapp.gui

def w2l_ChaseSRVRecord(sid,outf,command,form,ls,dn,host_list):

  host_select_field = pyweblib.forms.Select(
    'host','Host selection',1,
    options=host_list,default=host_list[0],ignoreCase=1
  )
  w2lapp.gui.TopSection(
    sid,outf,command,form,ls,dn,
    'LDAP server located via DNS',
    w2lapp.gui.MainMenu(sid,form,ls,dn),
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
  w2lapp.gui.Footer(outf,form)
