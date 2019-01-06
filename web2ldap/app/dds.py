# -*- coding: utf-8 -*-
"""
web2ldap.app.dds: refresh entryTTL of dynamic entry with extended operation

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import ldap0
from ldap0.extop.dds import RefreshRequest, RefreshResponse

import web2ldap.app.gui


def DDSForm(sid, outf, form, ls, dn, Msg):

    if Msg:
        Msg = '<p class="ErrorMessage">%s</p>' % (Msg)
    else:
        Msg = '<p class="Message">Enter time-to-live for refresh request or leave empty for server-side default.</p>'

    web2ldap.app.gui.TopSection(
        sid, outf, 'dds', form, ls, dn, 'Refresh dynamic entry',
        web2ldap.app.gui.MainMenu(sid, form, ls, dn),
        context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(sid, form, ls, dn)
    )

    outf.write(
        """
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
            form_begin=form.beginFormHTML('dds', sid, 'POST'),
            field_dn=form.hiddenFieldHTML('dn', dn, u''),
            text_dn=web2ldap.app.gui.DisplayDN(sid, form, ls, dn),
            field_dds_renewttlnum=form.field['dds_renewttlnum'].inputHTML(),
            field_dds_renewttlfac=form.field['dds_renewttlfac'].inputHTML(),
        )
    )

    web2ldap.app.gui.Footer(outf, form)
    return # DDSForm()


def w2l_DDS(sid, outf, command, form, ls, dn):

    if 'dds_renewttlnum' in form.inputFieldNames and \
         'dds_renewttlfac' in form.inputFieldNames:

        try:
            request_ttl = \
                int(form.getInputValue('dds_renewttlnum', [None])[0]) * \
                int(form.getInputValue('dds_renewttlfac', [None])[0])
        except ValueError:
            request_ttl = None

        extreq = RefreshRequest(entryName=dn, requestTtl=request_ttl)
        try:
            extop_resp_obj = ls.l.extop_s(extreq, extop_resp_class=RefreshResponse)
        except ldap0.SIZELIMIT_EXCEEDED as e:
            DDSForm(
                sid, outf, form, ls, dn,
                web2ldap.app.gui.LDAPError2ErrMsg(e, form, charset=form.accept_charset)
            )
        else:
            if request_ttl and extop_resp_obj.responseTtl != request_ttl:
                Msg = '<p class="WarningMessage">Refreshed entry %s with TTL %d instead of %d.</p>' % (
                    web2ldap.app.gui.DisplayDN(sid, form, ls, dn),
                    extop_resp_obj.responseTtl, request_ttl
                )
            else:
                Msg = '<p class="SuccessMessage">Refreshed entry %s with TTL %d.</p>' % (
                    web2ldap.app.gui.DisplayDN(sid, form, ls, dn),
                    extop_resp_obj.responseTtl
                )
            web2ldap.app.gui.SimpleMessage(
                sid, outf, command, form, ls, dn,
                message=Msg,
                main_menu_list=web2ldap.app.gui.MainMenu(sid, form, ls, dn),
                context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(sid, form, ls, dn, dds_link=1)
            )

    else:
        DDSForm(sid, outf, form, ls, dn, None)
