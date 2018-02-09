# -*- coding: utf-8 -*-
"""
w2lapp.dds: refresh entryTTL of dynamic entry with extended operation

web2ldap - a web-based LDAP Client,
see http://www.web2ldap.de for details

(c) by Michael Stroeder <michael@stroeder.com>

This module is distributed under the terms of the
GPL (GNU GENERAL PUBLIC LICENSE) Version 2
(see http://www.gnu.org/copyleft/gpl.html)
"""

from __future__ import absolute_import

import ldap,w2lapp.gui

from ldap.extop.dds import RefreshRequest,RefreshResponse

def DDSForm(sid,outf,form,ls,dn,Msg):

  if Msg:
    Msg = '<p class="ErrorMessage">%s</p>' % (Msg)
  else:
    Msg = '<p class="Message">Enter time-to-live for refresh request or leave empty for server-side default.</p>'

  w2lapp.gui.TopSection(
    sid,outf,'dds',form,ls,dn,'Refresh dynamic entry',
    w2lapp.gui.MainMenu(sid,form,ls,dn),
    context_menu_list=w2lapp.gui.ContextMenuSingleEntry(sid,form,ls,dn)
  )

  outf.write("""
    <h1>Refresh Dynamic Entry</h1>
    {text_info_message}
    {form_begin}
    {field_dn}
    <table>
      <tr><td>DN of entry:</td><td>{text_dn}</td></tr>
      <tr><td>Refresh TTL:</td><td>{field_dds_renewttlnum} {field_dds_renewttlfac}</td></tr>
    </table>
      <input type="submit" value="Refresh">
      </form>
    """.format(
      text_info_message=Msg,
      form_begin=form.beginFormHTML('dds',sid,'POST'),
      field_dn=form.hiddenFieldHTML('dn',dn,u''),
      text_dn=w2lapp.gui.DisplayDN(sid,form,ls,dn),
      field_dds_renewttlnum=form.field['dds_renewttlnum'].inputHTML(),
      field_dds_renewttlfac=form.field['dds_renewttlfac'].inputHTML(),
  ))

  w2lapp.gui.Footer(outf,form)
  return # DDSForm()


def w2l_DDS(sid,outf,command,form,ls,dn):

  if 'dds_renewttlnum' in form.inputFieldNames and \
     'dds_renewttlfac' in form.inputFieldNames:

    try:
      request_ttl = int(form.getInputValue('dds_renewttlnum',[None])[0])*int(form.getInputValue('dds_renewttlfac',[None])[0])
    except ValueError:
      request_ttl = None

    extreq = RefreshRequest(entryName=dn,requestTtl=request_ttl)
    try:
      extop_resp_obj = ls.l.extop_s(extreq,extop_resp_class=RefreshResponse)
    except ldap.SIZELIMIT_EXCEEDED as e:
      DDSForm(
        sid,outf,form,ls,dn,
        w2lapp.gui.LDAPError2ErrMsg(e,form,charset=form.accept_charset)
      )
    else:
      if request_ttl and extop_resp_obj.responseTtl!=request_ttl:
        Msg = '<p class="WarningMessage">Refreshed entry %s with TTL %d instead of %d.</p>' % (
          w2lapp.gui.DisplayDN(sid,form,ls,dn),
          extop_resp_obj.responseTtl,request_ttl
        )
      else:
        Msg = '<p class="SuccessMessage">Refreshed entry %s with TTL %d.</p>' % (
          w2lapp.gui.DisplayDN(sid,form,ls,dn),
          extop_resp_obj.responseTtl
        )
      w2lapp.gui.SimpleMessage(
        sid,outf,command,form,ls,dn,
        message=Msg,
        main_menu_list=w2lapp.gui.MainMenu(sid,form,ls,dn),
        context_menu_list=w2lapp.gui.ContextMenuSingleEntry(sid,form,ls,dn,dds_link=1)
      )

  else:

    ####################################################################
    # New requestTTL not yet provided => ask for it
    ####################################################################

    DDSForm(sid,outf,form,ls,dn,None)
