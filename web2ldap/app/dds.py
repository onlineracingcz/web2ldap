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


DDS_FORM_TMPL = """
<h1>Refresh Dynamic Entry</h1>
{text_info_message}
{form_begin}
{field_dn}
<table>
  <tr><td>DN of entry:</td><td>{text_dn}</td></tr>
  <tr>
    <td>Refresh TTL:</td><td>{field_dds_renewttlnum} {field_dds_renewttlfac}</td>
  </tr>
</table>
  <input type="submit" value="Refresh">
  </form>
"""


def dds_form(app, msg):
    """
    Output input form for entering TTL for dynamic entry refresh
    """
    if msg:
        msg = '<p class="ErrorMessage">%s</p>' % (msg)
    else:
        msg = (
            '<p class="Message">'
            'Enter time-to-live for refresh request or leave empty for server-side default.'
            '</p>'
        )
    web2ldap.app.gui.TopSection(
        app, 'Refresh dynamic entry',
        web2ldap.app.gui.MainMenu(app),
        context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(app),
    )
    app.outf.write(
        DDS_FORM_TMPL.format(
            text_info_message=msg,
            form_begin=app.form.beginFormHTML('dds', app.sid, 'POST'),
            field_dn=app.form.hiddenFieldHTML('dn', app.dn, u''),
            text_dn=web2ldap.app.gui.DisplayDN(app, app.dn),
            field_dds_renewttlnum=app.form.field['dds_renewttlnum'].inputHTML(),
            field_dds_renewttlfac=app.form.field['dds_renewttlfac'].inputHTML(),
        )
    )
    web2ldap.app.gui.Footer(app)
    return # dds_form()


def w2l_dds(app):
    """
    Dynamic entry refresh operation
    """

    if  'dds_renewttlnum' not in app.form.inputFieldNames or \
        'dds_renewttlfac' not in app.form.inputFieldNames:

        dds_form(app, None)
        return

    try:
        request_ttl = \
            int(app.form.getInputValue('dds_renewttlnum', [None])[0]) * \
            int(app.form.getInputValue('dds_renewttlfac', [None])[0])
    except ValueError:
        request_ttl = None

    extreq = RefreshRequest(entryName=app.dn, requestTtl=request_ttl)
    try:
        extop_resp_obj = app.ls.l.extop_s(extreq, extop_resp_class=RefreshResponse)
    except ldap0.SIZELIMIT_EXCEEDED as ldap_err:
        dds_form(app, web2ldap.app.gui.LDAPError2ErrMsg(ldap_err, app))
    else:
        if request_ttl and extop_resp_obj.responseTtl != request_ttl:
            msg = '<p class="WarningMessage">Refreshed entry %s with TTL %d instead of %d.</p>' % (
                web2ldap.app.gui.DisplayDN(app, app.dn),
                extop_resp_obj.responseTtl, request_ttl
            )
        else:
            msg = '<p class="SuccessMessage">Refreshed entry %s with TTL %d.</p>' % (
                web2ldap.app.gui.DisplayDN(app, app.dn),
                extop_resp_obj.responseTtl
            )
        web2ldap.app.gui.SimpleMessage(
            app,
            message=msg,
            main_menu_list=web2ldap.app.gui.MainMenu(app),
            context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(app, dds_link=1)
        )

    return # end of w2l_dds()
