# -*- coding: utf-8 -*-
"""
web2ldap plugin classes for OpenSSH-LPK
(see https://code.google.com/p/openssh-lpk/)
"""

from __future__ import absolute_import

import re
import hashlib
from base64 import b64encode

import paramiko

from web2ldap.app.schema.syntaxes import DirectoryString, syntax_registry

PARAMIKO_KEYCLASS = {
    'ssh-rsa': paramiko.RSAKey,
    'ssh-dss': paramiko.DSSKey,
}
#PARAMIKO_KEYCLASS.update({
#    'ecdsa-sha2-nistp256': ,
#    'ssh-ed25519': ,
#})


class SshPublicKey(DirectoryString):
    oid = 'SshPublicKey-oid'
    desc = 'SSH public key of a user'
    reObj = re.compile(
        '(^|.* )'
        '(ssh-rsa|ssh-dss|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|ssh-ed25519)'
        ' (?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(| .+)$'
    )
    # names of hash algorithms to be used when displaying fingerprint(s)
    hash_algorithms = ('md5', 'sha1', 'sha256', 'sha512')
    fileExt = 'pub'
    # minimum secure key size per algorithm
    min_key_size = {
        'ssh-rsa': 2048,
        'ssh-dss': 2048,
    }

    def sanitizeInput(self, attrValue):
        if attrValue:
            return DirectoryString.sanitizeInput(
                self, attrValue
            ).strip().replace('\r', '').replace('\n', '')
        return attrValue

    def _extract_pk_params(self, attrValue):
        attr_value = attrValue.decode(self._ls.charset)
        try:
            pk_type, pk_base64, pk_comment = attr_value.split(' ', 2)
        except ValueError:
            pk_comment = None
            pk_type, pk_base64 = attr_value.split(' ', 1)
        try:
            pk_bin = pk_base64.decode('base64')
            pk_fingerprints = dict([
                (hash_algo, hashlib.new(hash_algo, pk_bin).digest())
                for hash_algo in self.hash_algorithms
            ])
        except Exception:
            pk_bin, pk_fingerprints = None, None
        return pk_type, pk_comment, pk_bin, pk_fingerprints

    @staticmethod
    def _strip_padding(b64_val):
        i = len(b64_val)
        while b64_val[i-1] == '=':
            i = i - 1
        return b64_val[:i]

    @staticmethod
    def _get_key_size(pk_type, pk_bin):
        try:
            p = PARAMIKO_KEYCLASS[pk_type](data=pk_bin)
        except (KeyError, paramiko.SSHException):
            pk_size = None
        else:
            pk_size = p.get_bits()
        return pk_size

    def _validate(self, attrValue):
        valid = DirectoryString._validate(self, attrValue)
        if not valid:
            return False
        try:
            pk_type, _, pk_bin, _ = self._extract_pk_params(attrValue)
        except ValueError:
            return False
        if pk_type not in self.min_key_size:
            # no min-size defined for key type
            return True
        pk_size = self._get_key_size(pk_type, pk_bin)
        return (pk_size is None) or (pk_size >= self.min_key_size[pk_type])

    def _display_lines(
            self,
            valueindex,
            commandbutton,
            pk_type,
            pk_comment,
            pk_bin,
            pk_fingerprints,
        ):
        result = []
        result.append('<dt>SSH Key:</dt><dd><input readonly size="70" value="{}"></dd>'.format(
            DirectoryString.displayValue(self, valueindex, commandbutton)
        ))
        if pk_comment:
            result.append(
                '<dt>Key comment:</dt><dd>{}</dd>'.format(self._form.utf2display(pk_comment))
            )
        if pk_fingerprints:
            result.append('<dt>Fingerprints:</dt><dd><dl>')
            for hash_algo, pk_fingerprint in sorted(pk_fingerprints.items()):
                result.append(
                    '<dt>{0}:</dt><dd>{1}</dd>'.format(
                        hash_algo.upper(),
                        ':'.join([b.encode('hex') for b in pk_fingerprint]),
                    )
                )
            for hash_algo in ('sha1', 'sha256', 'sha512'):
                result.append(
                    '<dt>ssh-keygen -l -E {0}</dt><dd>{1}</dd>'.format(
                        hash_algo,
                        self._form.utf2display(
                            self._strip_padding(
                                b64encode(pk_fingerprints[hash_algo]).strip()
                            ).decode('ascii')
                        ),
                    )
                )
            result.append('</dl></dd>')
        if pk_bin:
            pk_size = self._get_key_size(pk_type, pk_bin)
            if pk_size is None:
                result.append('<dt>Key size:</dt><dd>unknown</dd>')
            else:
                result.append('<dt>Key size:</dt><dd>%d</dd>' % (pk_size))
        return result

    def displayValue(self, valueindex=0, commandbutton=False):
        pk_type, pk_comment, pk_bin, pk_fingerprints = self._extract_pk_params(self.attrValue)
        result = ['<dl>']
        result.extend(
            self._display_lines(
                valueindex,
                commandbutton,
                pk_type,
                pk_comment,
                pk_bin,
                pk_fingerprints,
            )
        )
        result.append('</dl>')
        return '\n'.join(result)


syntax_registry.reg_at(
    SshPublicKey.oid, [
        '1.3.6.1.4.1.24552.500.1.1.1.13', # sshPublicKey
    ]
)


# Register all syntax classes in this module
syntax_registry.reg_syntaxes(__name__)
