"""
Auto-generate some posixAccount attribute values

Status:
Experimental => you have to understand what it internally does when enabling it!
"""

import ldap0

from web2ldap.msbase import Str1stValueDict
from web2ldap.app.plugins.nis import syntax_registry, UidNumber, GidNumber, IA5String


class HomeDirectory(IA5String):
    oid = 'HomeDirectory-oid'
    desc = 'Path of Unix home directory of the user'
    homeDirectoryTemplate = '/home/{uid}'

    def transmute(self, attrValues):
        if (
                not attrValues or
                not attrValues[0] or
                attrValues[0] == self.homeDirectoryTemplate.format(**{'uid':''})
            ):
            e = Str1stValueDict(self._entry, '')
            attrValues = [self.homeDirectoryTemplate.format(**e)]
        return attrValues

syntax_registry.reg_at(
    HomeDirectory.oid, [
        '1.3.6.1.1.1.1.3', # homeDirectory
    ]
)


class AutogenNumber(object):
    inputSize = 12
    minNewValue = 10000
    maxNewValue = 19999
    object_class = 'posixAccount'

    def formValue(self):
        if self.object_class.lower() not in set([oc.lower() for oc in self._entry['objectClass']]):
            return u''
        try:
            ldap_result = self._app.ls.l.search_s(
                self._app.naming_context.encode(self._app.ls.charset),
                ldap0.SCOPE_SUBTREE,
                '(&(objectClass={0})({1}>={2})({1}<={3}))'.format(
                    self.object_class,
                    self._at,
                    self.__class__.minNewValue,
                    self.__class__.maxNewValue
                ),
                attrlist=[self._at],
            )
        except (
                ldap0.NO_SUCH_OBJECT,
                ldap0.SIZELIMIT_EXCEEDED,
                ldap0.TIMELIMIT_EXCEEDED,
            ):
            # search failed => no value suggested
            return u''
        idnumber_set = set()
        for ldap_dn, ldap_entry in ldap_result:
            if ldap_dn is not None:
                ldap_dn = ldap_dn.decode(self._app.ls.charset)
                if ldap_dn == self._dn:
                    return ldap_entry[self._at][0].decode(self._app.ls.charset)
                else:
                    idnumber_set.add(int(ldap_entry[self._at][0]))
        for idnumber in range(self.__class__.minNewValue, self.maxNewValue+1):
            if idnumber in idnumber_set:
                self.__class__.minNewValue = idnumber
            else:
                break
        if idnumber > self.maxNewValue:
            # end of valid range reached => no value suggested
            return u''
        return str(idnumber)


class AutogenUIDNumber(UidNumber, AutogenNumber):
    oid = 'AutogenUIDNumber-oid'
    desc = 'numeric Unix-UID'
    minNewValue = 10000
    maxNewValue = 19999
    object_class = 'posixAccount'

    def formValue(self):
        form_value = UidNumber.formValue(self)
        if not form_value:
            form_value = AutogenNumber.formValue(self)
        return form_value # formValue()

syntax_registry.reg_at(
    AutogenUIDNumber.oid, [
        '1.3.6.1.1.1.1.0', # uidNumber
    ]
)


class AutogenGIDNumber(GidNumber, AutogenNumber):
    oid = 'AutogenGIDNumber-oid'
    desc = 'numeric Unix-GID'
    object_class = 'posixGroup'

    def formValue(self):
        form_value = GidNumber.formValue(self)
        if not form_value:
            form_value = AutogenNumber.formValue(self)
        return form_value # formValue()

syntax_registry.reg_at(
    AutogenGIDNumber.oid, [
        '1.3.6.1.1.1.1.1', # gidNumber
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
