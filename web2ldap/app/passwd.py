# -*- coding: utf-8 -*-
"""
web2ldap.app.passwd: change password associated with entry

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

import time

import ldap0
from ldap0.pw import random_string, unicode_pwd, ntlm_password_hash, PWD_ALPHABET
from ldap0.schema.models import AttributeType, ObjectClass, SchemaElementOIDSet
from ldap0.extop.passmod import PassmodRequest

import web2ldap.web.forms
import web2ldap.ldapsession
import web2ldap.app.cnf
import web2ldap.app.core
import web2ldap.app.gui
import web2ldap.app.login
from web2ldap.ldaputil.passwd import user_password_hash
from web2ldap.app.form import Web2LDAPForm_passwd


PASSWD_ACTIONS_DICT = dict([
    (action, (short_desc, long_desc))
    for action, short_desc, long_desc in Web2LDAPForm_passwd.passwd_actions
])

PASSWD_GEN_DEFAULT_LENGTH = 20

PASSWD_USERPASSWORD_OBJECT_CLASSES = (
    'simpleSecurityObject',
    'simpleAuthObject',
)


def get_all_attributes(schema, oc_list):
    """
    returns single dictionary with all possible attributes
    defined in the schema for a given list of object classes
    """
    required, allowed = schema.attribute_types(oc_list, raise_keyerror=False)
    result = SchemaElementOIDSet(schema, AttributeType, [])
    result.update(required)
    result.update(allowed)
    return result # get_all_attributes()


def password_change_url(app, passwd_who, passwd_input):
    """
    returns a web2ldap URL for directly accessing
    the password change form for the given entry
    """
    passwd_who_ldapurl_obj = app.ls.ldapUrl(passwd_who)
    passwd_who_ldapurl_obj.scope = ldap0.SCOPE_BASE
    passwd_who_ldapurl_obj.who = passwd_who.encode(app.ls.charset)
    passwd_who_ldapurl_obj.cred = passwd_input.encode(app.ls.charset)
    passwd_who_ldapurl_obj.cred = passwd_input.encode(app.ls.charset)
    passwd_who_ldapurl_obj.saslMech = None
    return '?'.join((
        app.form.action_url('passwd', None),
        str(passwd_who_ldapurl_obj),
    ))


def passwd_context_menu(app):
    """
    returns the context menu list for passwd dialogue
    """
    result = [
        app.anchor(
            'passwd', short_desc,
            [
                ('dn', app.dn),
                ('passwd_action', pa),
                ('passwd_who', app.dn),
            ],
            title=long_desc
        )
        for pa, short_desc, long_desc in Web2LDAPForm_passwd.passwd_actions
    ]
    # Menu entry for unlocking entry
    delete_param_list = [
        ('dn', app.dn),
        ('delete_ctrl', web2ldap.ldapsession.CONTROL_RELAXRULES),
    ]
    delete_param_list.extend([
        ('delete_attr', attr_type)
        for attr_type in (
            # Samba-Passwortattribute
            u'sambaBadPasswordCount', u'sambaBadPasswordTime',
            # draft-behera-ldap-password-policy
            u'pwdAccountLockedTime', u'pwdFailureTime',
            # SunONE/Netscape/Fedora/389 Directory Server
            u'passwordRetryCount', u'accountUnlockTime',
        )
        if app.schema.get_obj(AttributeType, attr_type.encode('ascii'), None) is not None
    ])
    result.append(
        app.anchor(
            'delete', 'Unlock',
            delete_param_list,
            title=u'Unlock locked out entry',
        )
    )
    # Menu entry for deleting all password-related attrs
    delete_param_list = [('dn', app.dn)]
    delete_param_list.extend([
        ('delete_attr', attr_type)
        for attr_type in (
            'userPassword',
            # Samba-Passwortattribute
            'sambaBadPasswordCount', 'sambaBadPasswordTime', 'sambaClearTextPassword',
            'sambaLMPassword', 'sambaNTPassword', 'sambaPasswordHistory',
            'sambaPreviousClearTextPassword',
            # draft-behera-ldap-password-policy
            'pwdAccountLockedTime', 'pwdHistory', 'pwdChangedTime', 'pwdFailureTime',
            'pwdReset', 'pwdPolicySubentry', 'pwdGraceUseTime',
            'pwdStartTime', 'pwdEndTime', 'pwdLastSuccess',
            # OpenDJ
            'ds-pwp-password-policy-dn',
            # SunONE/Netscape/Fedora/389 Directory Server
            'passwordExpirationTime', 'passwordExpWarned',
            'passwordRetryCount', 'accountUnlockTime', 'retryCountResetTime',
        )
        if app.schema.get_obj(AttributeType, attr_type, None) is not None
    ])
    result.append(
        app.anchor(
            'delete', 'Unset',
            delete_param_list,
            title=u'Delete password related attributes',
        )
    )
    return result


def password_self_change(ls, dn):
    """
    returns True, if user changes own password
    """
    return (ls.who is None) or (ls.who == dn)


def passwd_form(
        app,
        passwd_action, passwd_who, user_objectclasses,
        heading, error_msg
    ):
    """
    display a password change input form
    """

    # depending on the calling code part the necessary
    # input fields must be added to the form
    for field in Web2LDAPForm_passwd.fields():
        if field.name not in app.form.field:
            app.form.add_field(field)

    if error_msg:
        error_msg = '<p class="ErrorMessage">%s</p>' % (error_msg)

    # Determine whether password attribute is unicodePwd on MS AD
    unicode_pwd_avail = app.schema.sed[AttributeType].has_key('1.2.840.113556.1.4.90')

    # Determine whether user changes own password
    own_pwd_change = password_self_change(app.ls, passwd_who)

    all_attrs = get_all_attributes(app.schema, user_objectclasses)

    if not unicode_pwd_avail:

        config_hashtypes = app.cfg_param('passwd_hashtypes', [])
        if config_hashtypes:
            # The set of hash types are restricted by local configuration
            default_hashtypes = [
                hash_type
                for hash_type in web2ldap.ldaputil.passwd.AVAIL_USERPASSWORD_SCHEMES.items()
                if hash_type[0] in config_hashtypes
            ]
            app.form.field['passwd_scheme'].options = default_hashtypes

    nthash_available = '1.3.6.1.4.1.7165.2.1.25' in all_attrs
    show_clientside_pw_fields = passwd_action == 'setuserpassword' and not unicode_pwd_avail

    passwd_template_str = web2ldap.app.gui.ReadTemplate(
        app,
        'passwd_template',
        u'password form',
    )

    web2ldap.app.gui.TopSection(
        app,
        'Change password',
        web2ldap.app.gui.main_menu(app),
        context_menu_list=passwd_context_menu(app),
        main_div_id='Input',
    )

    app.outf.write(passwd_template_str.format(
        text_heading=heading,
        text_msg=error_msg or app.form.utf2display(PASSWD_ACTIONS_DICT[passwd_action][1]),
        form_begin=app.form.beginFormHTML('passwd', app.sid, 'POST'),
        value_dn=app.form.hiddenFieldHTML('dn', app.dn, u''),
        value_passwd_action=app.form.hiddenFieldHTML('passwd_action', passwd_action, u''),
        value_passwd_who=app.form.hiddenFieldHTML('passwd_who', passwd_who, u''),
        text_desc={False:'Change password for', True:'Change own password of'}[own_pwd_change],
        text_whoami=web2ldap.app.gui.WhoAmITemplate(app, passwd_who),
        disable_oldpw_start={False:'', True:'<!--'}[not own_pwd_change],
        disable_oldpw_end={False:'', True:'-->'}[not own_pwd_change],
        disable_ownuser_start={False:'', True:'<!--'}[own_pwd_change],
        disable_ownuser_end={False:'', True:'-->'}[own_pwd_change],
        disable_clientsidehashing_start={False:'', True:'<!--'}[not show_clientside_pw_fields],
        disable_clientsidehashing_end={False:'', True:'-->'}[not show_clientside_pw_fields],
        disable_syncnthash_start={False:'', True:'<!--'}[not (show_clientside_pw_fields and nthash_available)],
        disable_syncnthash_end={False:'', True:'-->'}[not (show_clientside_pw_fields and nthash_available)],
        disable_settimesync_start={False:'', True:'<!--'}[own_pwd_change or not show_clientside_pw_fields],
        disable_settimesync_end={False:'', True:'-->'}[own_pwd_change or not show_clientside_pw_fields],
        form_field_passwd_scheme=app.form.field['passwd_scheme'].inputHTML(),
        form_field_passwd_ntpasswordsync=app.form.field['passwd_ntpasswordsync'].inputHTML(),
        form_field_passwd_settimesync=app.form.field['passwd_settimesync'].inputHTML(checked=(not own_pwd_change)),
    ))

    web2ldap.app.gui.Footer(app)
    return # passwd_form()


def w2l_passwd(app):
    """
    Set new password in LDAP entries
    """

    # Determine the default value for passwd_action based on
    # server's visible configuration
    if PassmodRequest.requestName in app.ls.supportedExtension:
        # Password Modify extended operation seems to be announced in rootDSE
        passwd_action_default = u'passwdextop'
    else:
        passwd_action_default = u'setuserpassword'

    passwd_action = app.form.getInputValue('passwd_action', [None])[0] or passwd_action_default
    passwd_who = app.form.getInputValue('passwd_who', [app.dn])[0]

    user_entry = app.ls.l.read_s(passwd_who.encode(app.ls.charset), attrlist=['objectClass'])
    user_objectclasses = SchemaElementOIDSet(
        app.schema,
        ObjectClass,
        user_entry.get('objectClass', []),
    )

    if 'passwd_newpasswd' not in app.form.inputFieldNames:

        # New password not yet provided => ask for it
        #---------------------------------------------

        passwd_form(
            app,
            passwd_action, passwd_who,
            user_objectclasses,
            'Set password', ''
        )
        return

    # New password provided => (re)set it in entry
    #----------------------------------------------

    if len(app.form.field['passwd_newpasswd'].value) != 2:
        raise web2ldap.app.core.ErrorExit(u'Repeat password!')

    if app.form.field['passwd_newpasswd'].value[0] != app.form.field['passwd_newpasswd'].value[1]:
        passwd_form(
            app,
            passwd_action, passwd_who, user_objectclasses,
            heading='Password Error',
            error_msg='New passwords do not match!',
        )
        return

    old_password = app.form.getInputValue('passwd_oldpasswd', [None])[0]

    passwd_input = app.form.field['passwd_newpasswd'].value[0]

    no_passwd_input = not passwd_input
    if no_passwd_input:
        passwd_input = random_string(
            alphabet=app.cfg_param('passwd_genchars', PWD_ALPHABET),
            length=app.cfg_param('passwd_genlength', PASSWD_GEN_DEFAULT_LENGTH),
        )

    passwd_forcechange = app.form.getInputValue('passwd_forcechange', ['no'])[0] == 'yes'
    passwd_inform = app.form.getInputValue('passwd_inform', [''])[0]

    password_attr_types_msg = ''

    passwd_modlist = app.cfg_param('passwd_modlist', [])

    # Extend with appropriate user-must-change-password-after-reset attribute
    if passwd_forcechange:
        # draft-behera-password-policy
        if app.schema.sed[AttributeType].has_key('1.3.6.1.4.1.42.2.27.8.1.22'):
            passwd_modlist.append((ldap0.MOD_REPLACE, 'pwdReset', 'TRUE'))
        # MS AD
        elif app.schema.sed[AttributeType].has_key('1.2.840.113556.1.4.96'):
            passwd_modlist.append((ldap0.MOD_REPLACE, 'pwdLastSet', '0'))

    if not passwd_action:
        raise web2ldap.app.core.ErrorExit(u'No password action chosen.')

    elif passwd_action == 'passwdextop':

        # Modify password via Password Modify Extended Operation
        #--------------------------------------------------------

        try:
            app.ls.l.passwd_s(
                passwd_who.encode(app.ls.charset),
                (old_password or u'').encode(app.ls.charset) or None,
                passwd_input.encode(app.ls.charset)
            )
        except (
                ldap0.CONSTRAINT_VIOLATION,
                ldap0.UNWILLING_TO_PERFORM,
            ) as e:
            passwd_form(
                app,
                passwd_action, passwd_who, user_objectclasses,
                heading='Password Error',
                error_msg=app.ldap_error_msg(e)
            )
            return
        else:
            if passwd_modlist:
                app.ls.modifyEntry(passwd_who, passwd_modlist)
            if no_passwd_input:
                password_attr_types_msg = 'Generated password set by the server: %s' % (
                    app.form.utf2display(passwd_input)
                )
            else:
                password_attr_types_msg = 'Password set by the server.'

    elif passwd_action in {'setuserpassword', 'setunicodepwd'}:

        # Modify password via Modify Request
        #------------------------------------

        all_attrs = get_all_attributes(app.schema, user_objectclasses)

        if '2.5.4.35' not in all_attrs:
            # Current set of object classes do not allow userPassword attribute
            for aux_class in PASSWD_USERPASSWORD_OBJECT_CLASSES:
                try:
                    # Object classes must be visible
                    # Hint: this does not ensure we see all object classes
                    # but this check is definitely better than no check
                    if not user_objectclasses:
                        continue
                    # Ensure supplemental class is really AUXILIARY
                    if app.schema.get_inheritedattr(ObjectClass, aux_class, 'kind') != 2:
                        continue
                    # Ensure supplemental class is not already in set of object classes
                    if aux_class in user_objectclasses:
                        continue
                    passwd_modlist.append((ldap0.MOD_ADD, 'objectClass', [aux_class]))
                    break
                except KeyError:
                    pass

        passwd_scheme = app.form.getInputValue('passwd_scheme', [''])[0]

        # Set "standard" password of LDAP entry
        if '1.2.840.113556.1.4.90' in all_attrs:
            # Active Directory's password attribute unicodePwd
            passwd_attr_type = 'unicodePwd'
            new_passwd_value = unicode_pwd(password=passwd_input)
            passwd_scheme = ''
            if old_password:
                old_passwd_value = unicode_pwd(old_password)
        else:
            # Assume standard password attribute userPassword
            passwd_attr_type = 'userPassword'
            new_passwd_value = user_password_hash(
                passwd_input.encode(app.ls.charset),
                passwd_scheme.encode('ascii'),
            )
            if old_password:
                old_passwd_value = user_password_hash(old_password.encode(app.ls.charset), '')

        if password_self_change(app.ls, passwd_who) and old_password:
            passwd_modlist.extend((
                (
                    ldap0.MOD_DELETE,
                    passwd_attr_type,
                    [old_passwd_value],
                ),
                (
                    ldap0.MOD_ADD,
                    passwd_attr_type,
                    [new_passwd_value],
                ),
            ))
        else:
            passwd_modlist.append(
                (
                    ldap0.MOD_REPLACE,
                    passwd_attr_type,
                    [new_passwd_value]
                ),
            )

        passwd_settimesync = app.form.getInputValue('passwd_settimesync', ['no'])[0] == 'yes'

        pwd_change_timestamp = time.time()

        if passwd_settimesync and '1.3.6.1.1.1.1.5' in all_attrs:
            passwd_modlist.append(
                (
                    ldap0.MOD_REPLACE,
                    'shadowLastChange',
                    str(int(pwd_change_timestamp/86400)),
                )
            )

        passwd_ntpasswordsync = app.form.getInputValue('passwd_ntpasswordsync', ['no'])[0] == 'yes'

        # Samba password synchronization if requested
        if passwd_ntpasswordsync and '1.3.6.1.4.1.7165.2.1.25' in all_attrs:
            passwd_modlist.append(
                (
                    ldap0.MOD_REPLACE,
                    'sambaNTPassword',
                    ntlm_password_hash(passwd_input),
                )
            )
            if passwd_settimesync and '1.3.6.1.4.1.7165.2.1.27' in all_attrs:
                passwd_modlist.append(
                    (
                        ldap0.MOD_REPLACE,
                        'sambaPwdLastSet',
                        str(int(pwd_change_timestamp)),
                    )
                )

        password_attr_types_msg = 'Password-related attributes set: %s' % (', '.join(
            [
                app.form.utf2display(unicode(attr_type))
                for _, attr_type, _ in passwd_modlist
            ]
        ))
        if no_passwd_input:
            password_attr_types_msg += '<br>Generated password is: %s' % (
                app.form.utf2display(passwd_input)
            )

        # Modify password
        try:
            app.ls.modifyEntry(passwd_who, passwd_modlist)
        except (
                ldap0.CONSTRAINT_VIOLATION,
                ldap0.UNWILLING_TO_PERFORM,
            ) as e:
            passwd_form(
                app,
                passwd_action, passwd_who, user_objectclasses,
                heading='Password Error',
                error_msg=app.ldap_error_msg(e)
            )
            return
        except ldap0.NO_SUCH_ATTRIBUTE as e:
            passwd_form(
                app,
                passwd_action, passwd_who, user_objectclasses,
                heading='Password Error',
                error_msg=app.ldap_error_msg(
                    e, template=r"%s (Hint: Try without old password.)"
                )
            )
            return

    # Check if relogin is necessary
    if password_self_change(app.ls, passwd_who):
        try:
            app.ls.l.reconnect(app.ls.uri, reset_last_bind=True)
        except ldap0.INAPPROPRIATE_AUTH:
            pass
        app.ls.who = None
        # Display login form
        web2ldap.app.login.w2l_login(
            app,
            login_msg='New login is required!<br>'+password_attr_types_msg,
            who=passwd_who,
            relogin=False,
            nomenu=True
        )
    else:
        if passwd_inform == 'display_url':
            passwd_link = '<a href="%s">Password change URL</a>' % (
                password_change_url(app, passwd_who, passwd_input)
            )
        else:
            passwd_link = ''
        web2ldap.app.gui.SimpleMessage(
            app,
            message="""
            <p class="SuccessMessage">Changed password of entry %s</p>
            <p>%s</p>
            <p>%s</p>
            """ % (
                web2ldap.app.gui.DisplayDN(app, passwd_who),
                password_attr_types_msg,
                passwd_link,
            ),
            main_menu_list=web2ldap.app.gui.main_menu(app),
            context_menu_list=web2ldap.app.gui.ContextMenuSingleEntry(app)
        )
