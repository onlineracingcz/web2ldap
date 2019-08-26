"""
pkix - classes for X.509v3 attributes/extensions specified in IETF-PKIX

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

from __future__ import absolute_import

# Pisces
from web2ldap.pisces import asn1
# mspki itself
from . import util, x500, x509, asn1types
from web2ldap.utctime import strptime


class GeneralName(asn1.Constructed):
    """
    GeneralName ::= CHOICE {
         otherName                       [0]     OtherName,
         rfc822Name                      [1]     IA5String,
         dNSName                         [2]     IA5String,
         x400Address                     [3]     ORAddress,
         directoryName                   [4]     Name,
         ediPartyName                    [5]     EDIPartyName,
         uniformResourceIdentifier       [6]     IA5String,
         iPAddress                       [7]     OCTET STRING,
         registeredID                    [8]     OBJECT IDENTIFIER}
    """
    tag_str = {
        0: 'otherName',
        1: 'rfc822Name',
        2: 'dNSName',
        3: 'x400Address',
        4: 'directoryName',
        5: 'ediPartyName',
        6: 'uniformResourceIdentifier',
        7: 'iPAddress',
        8: 'registeredID',
    }
    def __init__(self, val):
        self.tag = val.tag
        if self.tag == 4:
            self.val = x500.Name(val.val)
        else:
            self.val = val.val

    def __str__(self):
        return str(self.val)

    def __repr__(self):
        if self.tag == 7:
            ip_address_str = '.'.join(map(str, map(ord, self.val)))
            return '%s:%s' % (self.tag_str[self.tag], ip_address_str)
        return '%s:%s' % (self.tag_str[self.tag], self)

    def html(self):
        if self.tag == 1:
            return '<a href="mailto:%s">%s</a>' % (self, repr(self))
        elif self.tag == 4:
            return self.val.html()
        if self.tag == 6:
            return '<a target="%s" href="%s%s">%s</a>' % (
                asn1types.url_target,
                asn1types.url_prefix,
                self,
                self,
            )
        return repr(self)


class GeneralNames(asn1types.SequenceOf):
    """
    GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
    """
    item_class = GeneralName


class BasicConstraints(asn1types.AttributeSequence):
    """
    BasicConstraints ::= SEQUENCE {
         cA                      BOOLEAN DEFAULT FALSE,
         pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
    """
    attr_list = ['cA', 'pathLenConstraint']

    def __init__(self, val):
        asn1types.AttributeSequence.__init__(self, val)
        if len(self.val) > 0:
            self.cA = self.val[0]
        if len(self.val) == 2:
            self.pathLenConstraint = self.val[1]


class AuthorityKeyIdentifier(asn1types.AttributeSequence):
    """
    AuthorityKeyIdentifier ::= SEQUENCE {
       keyIdentifier             [0] KeyIdentifier           OPTIONAL,
       authorityCertIssuer       [1] GeneralNames            OPTIONAL,
       authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL  }
    """
    attr_list = ['keyIdentifier', 'authorityCertIssuer', 'authorityCertSerialNumber']

    def __init__(self, val):
        asn1types.AttributeSequence.__init__(self, val)
        for i in self.val:
            if i.tag == 0:
                self.keyIdentifier = KeyIdentifier(i.val)
            elif i.tag == 1:
                if isinstance(i.val, asn1.Constructed):
                    self.authorityCertIssuer = GeneralName(i.val)
                elif isinstance(i.val, asn1.Sequence):
                    self.authorityCertIssuer = GeneralNames(i.val)
            elif i.tag == 2:
                self.authorityCertSerialNumber = x509.CertificateSerialNumber(i.val)


class KeyIdentifier(asn1.OctetString):
    """
    KeyIdentifier ::= OCTET STRING
    """
    def __init__(self, val):
        asn1.OctetString.__init__(self, val)

    def __str__(self):
        return util.HexString(bytes(self.val))

    def __repr__(self):
        return '<%s: %s>' % (self.__class__.__name__, self)

    def html(self):
        return str(self)


class SubjectKeyIdentifier(KeyIdentifier):
    """
    SubjectKeyIdentifier ::= KeyIdentifier
    """


class KeyUsage(asn1types.BitString):
    """
    KeyUsage ::= BIT STRING {
         digitalSignature        (0),
         nonRepudiation          (1),
         keyEncipherment         (2),
         dataEncipherment        (3),
         keyAgreement            (4),
         keyCertSign             (5),
         cRLSign                 (6),
         encipherOnly            (7),
         decipherOnly            (8) }
    """
    bit_str = {
        0: 'digitalSignature',
        1: 'nonRepudiation',
        2: 'keyEncipherment',
        3: 'dataEncipherment',
        4: 'keyAgreement',
        5: 'keyCertSign',
        6: 'cRLSign',
        7: 'encipherOnly',
        8: 'decipherOnly'
    }

    def __str__(self):
        return asn1types.BitString.__str__(self)


class SubjectAltName(GeneralNames):
    """
    SubjectAltName ::= GeneralNames
    """


class IssuerAltName(GeneralNames):
    """
    IssuerAltName ::= GeneralNames
    """


class CertificateIssuer(GeneralNames):
    """
    IssuerAltName ::= GeneralNames
    """


class DistributionPointName(asn1.Contextual):
    """
    DistributionPointName ::= CHOICE {
         fullName                [0]     GeneralNames,
         nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }
    """
    tag_str = {
        0: 'fullName',
        1: 'nameRelativeToCRLIssuer',
    }

    def __init__(self, val):
        self.tag = val.tag
        if val.tag == 0:
            if isinstance(val, asn1.Constructed):
                self.val = GeneralName(val.val)
            elif isinstance(val, asn1.Sequence):
                self.val = GeneralNames(val.val)
            self.fullName = self.val
        elif val.tag == 1:
            self.val = x500.RelativeDistinguishedName(val.val)
            self.nameRelativeToCRLIssuer = self.val
        else:
            raise ValueError("Invalid tag %d for %s" % (val.tag, self.__class__.__name__))

    def __str__(self):
        return str(self.val)

    def __repr__(self):
        return '%s:%s' % (self.tag_str[self.tag], self)

    def html(self):
        return '%s:%s' % (self.tag_str[self.tag], self.val.html())


class DistributionPoint(asn1types.AttributeSequence):
    """
    DistributionPoint ::= SEQUENCE {
         distributionPoint       [0]     DistributionPointName OPTIONAL,
         reasons                 [1]     ReasonFlags OPTIONAL,
         cRLIssuer               [2]     GeneralNames OPTIONAL }
    """
    attr_list = ['distributionPoint', 'reasons', 'cRLIssuer']

    def __init__(self, val):
        asn1types.AttributeSequence.__init__(self, val)
        for i in self.val:
            if i.tag == 0:
                self.distributionPoint = DistributionPointName(i.val)
            elif i.tag == 1:
                self.reasons = ReasonFlags(i.val)
            elif i.tag == 2:
                if isinstance(i, asn1.Constructed):
                    self.cRLIssuer = GeneralName(i.val)
                elif isinstance(i, asn1.Sequence):
                    self.cRLIssuer = GeneralNames(i.val)
            else:
                raise ValueError("Invalid tag %d for %s" % (i.tag, self.__class__.__name__))


class CRLDistPointsSyntax(asn1types.SequenceOf):
    """
    CRLDistPointsSyntax ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
    """
    item_class = DistributionPoint


class CRLDistributionPoints(CRLDistPointsSyntax):
    """
    cRLDistributionPoints ::= {
         CRLDistPointsSyntax }
    """


class ReasonFlags(asn1types.BitString):
    """
    ReasonFlags ::= BIT STRING {
         unused                  (0),
         keyCompromise           (1),
         cACompromise            (2),
         affiliationChanged      (3),
         superseded              (4),
         cessationOfOperation    (5),
         certificateHold         (6) }
    """
    bit_str = {
        0: 'unused',
        1: 'keyCompromise',
        2: 'cACompromise',
        3: 'affiliationChanged',
        4: 'superseded',
        5: 'cessationOfOperation',
        6: 'certificateHold'
    }


class PrivateKeyUsagePeriod(asn1.Sequence):
    """
    PrivateKeyUsagePeriod ::= SEQUENCE {
         notBefore       [0]     GeneralizedTime OPTIONAL,
         notAfter        [1]     GeneralizedTime OPTIONAL }
    """

    def __init__(self, val):
        asn1.Sequence.__init__(self, val)
        self.notBefore = self.notAfter = None
        for i in self.val:
            if i.tag == 0:
                self.notBefore = strptime(i.val)
            elif i.tag == 1:
                self.notAfter = strptime(i.val)
            else:
                raise ValueError("Invalid tag %d for %s" % (i.tag, self.__class__.__name__))

    def __str__(self):
        result = []
        if self.notBefore:
            result.append('from %s' % (self.notBefore))
        if self.notAfter:
            result.append('until %s' % (self.notAfter))
        return ' '.join(result)


class ExtendedKeyUsage(asn1.Sequence):
    """
    extendedKeyUsage EXTENSION ::= {
            SYNTAX SEQUENCE SIZE (1..MAX) OF KeyPurposeId
            IDENTIFIED BY id-ce-extKeyUsage }

    KeyPurposeId ::= OBJECT IDENTIFIER

    -- PKIX-defined extended key purpose OIDs
    id-kp-serverAuth             OBJECT IDENTIFIER ::= { id-kp 1 }
    id-kp-clientAuth             OBJECT IDENTIFIER ::= { id-kp 2 }
    id-kp-codeSigning            OBJECT IDENTIFIER ::= { id-kp 3 }
    id-kp-emailProtection        OBJECT IDENTIFIER ::= { id-kp 4 }
    id-kp-ipsecEndSystem         OBJECT IDENTIFIER ::= { id-kp 5 }
    id-kp-ipsecTunnel            OBJECT IDENTIFIER ::= { id-kp 6 }
    id-kp-ipsecUser              OBJECT IDENTIFIER ::= { id-kp 7 }
    id-kp-timeStamping           OBJECT IDENTIFIER ::= { id-kp 8 }
    id-kp-OCSPSigning            OBJECT IDENTIFIER ::= { id-kp 9 }
    id-kp-dvcs                   OBJECT IDENTIFIER ::= { id-kp 10 }
    id-kp-sbgpCertAAServerAuth   OBJECT IDENTIFIER ::= { id-kp 11 }

    Also several OIDs from Microsoft and Netscape were added here
    """
    oid_str = {
        '1.3.6.1.4.1.311.10.3.1': 'msCTLSign',
        '1.3.6.1.4.1.311.10.3.3': 'msSGC',
        '1.3.6.1.4.1.311.10.3.4': 'msEFS',
        '1.3.6.1.4.1.311.2.1.21': 'msCodeInd',
        '1.3.6.1.4.1.311.2.1.22': 'msCodeCom',
        '1.3.6.1.5.5.7.3.1': 'serverAuth',
        '1.3.6.1.5.5.7.3.2': 'clientAuth',
        '1.3.6.1.5.5.7.3.3': 'codeSigning',
        '1.3.6.1.5.5.7.3.4': 'emailProtection',
        '1.3.6.1.5.5.7.3.5': 'ipsecEndSystem',
        '1.3.6.1.5.5.7.3.6': 'ipsecTunnel',
        '1.3.6.1.5.5.7.3.7': 'ipsecUser',
        '1.3.6.1.5.5.7.3.8': 'timeStamping',
        '1.3.6.1.5.5.7.3.9': 'OCSPSigning',
        '1.3.6.1.5.5.7.3.10': 'dvcs',
        '1.3.6.1.5.5.7.3.11': 'sbgpCertAAServerAuth',
        '2.16.840.1.113730.4.1': 'nsServerGatedCrypto',
    }

    def __str__(self):
        return ', '.join([
            self.oid_str.get(str(x), str(x))
            for x in self.val
        ])

    def __repr__(self):
        return str(self)


class PolicyInformation(asn1types.AttributeSequence):
    """
    PolicyInformation ::= SEQUENCE {
         policyIdentifier   CertPolicyId,
         policyQualifiers   SEQUENCE SIZE (1..MAX) OF
                                 PolicyQualifierInfo OPTIONAL }
    """
    attr_list = ['policyIdentifier', 'policyQualifiers']

    def __init__(self, val):
        asn1types.AttributeSequence.__init__(self, val)
        self.policyIdentifier = CertPolicyId(self.val[0].val)
        if len(val) > 1:
            self.policyQualifiers = PolicyQualifiers(self.val[1])


class CertificatePolicies(asn1types.SequenceOf):
    """
    certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
    """
    item_class = PolicyInformation


class CertPolicyId(asn1.OID):
    """
    CertPolicyId ::= OBJECT IDENTIFIER
    """


class PolicyQualifierInfo(asn1types.AttributeSequence):
    """
    PolicyQualifierInfo ::= SEQUENCE {
         policyQualifierId  PolicyQualifierId,
         qualifier          ANY DEFINED BY policyQualifierId }
    """
    attr_list = ['policyQualifierId', 'qualifier']

    def __init__(self, val):
        self.val = val
        self.policyQualifierId = PolicyQualifierId(self.val[0].val)
        if repr(self.val[0]) == '1.3.6.1.5.5.7.2.1':
            self.qualifier = CPSuri(self.val[1])
        if repr(self.val[0]) == '1.3.6.1.5.5.7.2.2':
            self.qualifier = UserNotice(self.val[1])


class PolicyQualifiers(asn1types.SequenceOf):
    item_class = PolicyQualifierInfo


class PolicyQualifierId(asn1.OID):
    """
    id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
    id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
    id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }

    PolicyQualifierId ::=
         OBJECT IDENTIFIER ( id-qt-cps | id-qt-unotice )
    """
    def __init__(self, val):
        #asn1.OID.__init__(self, val)
        self.val = val


class CPSuri(asn1.IA5String):
    """
    CPSuri ::= IA5String
    """
    def __init__(self, val):
        asn1.IA5String.__init__(self, val)

    def html(self):
        return '<a target="%s" href="%s%s">%s</a>' % (
            asn1types.url_target,
            asn1types.url_prefix,
            self.val,
            self.val,
        )


class UserNotice(asn1types.AttributeSequence):
    """
    UserNotice ::= SEQUENCE {
         noticeRef        NoticeReference OPTIONAL,
         explicitText     DisplayText OPTIONAL}
    """
    attr_list = ['noticeRef', 'explicitText']

    def __init__(self, val):
        asn1types.AttributeSequence.__init__(self, val)
        for i in self.val:
            if isinstance(i, asn1.Sequence):
                self.noticeRef = NoticeReference(i)
            else:
                self.explicitText = DisplayText(i)


class NoticeReference(asn1types.AttributeSequence):
    """
    NoticeReference ::= SEQUENCE {
         organization     DisplayText,
         noticeNumbers    SEQUENCE OF INTEGER }
    """
    attr_list = ['organization', 'noticeNumbers']

    def __init__(self, val):
        asn1types.AttributeSequence.__init__(self, val)
        self.organization = DisplayText(self.val[0])
        self.noticeNumbers = self.val[1]


class DisplayText(asn1.ASN1Object):
    """
    DisplayText ::= CHOICE {
         visibleString    VisibleString  (SIZE (1..200)),
         bmpString        BMPString      (SIZE (1..200)),
         utf8String       UTF8String     (SIZE (1..200)) }
    """


class AccessDescription(asn1types.AttributeSequence):
    """
    AccessDescription  ::=  SEQUENCE {
            accessMethod          OBJECT IDENTIFIER,
            accessLocation        GeneralName  }
    """
    attr_list = ['accessMethod', 'accessLocation']

    def __init__(self, val):
        asn1types.AttributeSequence.__init__(self, val)
        self.accessMethod = self.val[0]
        self.accessLocation = GeneralName(self.val[1])


class AuthorityInfoAccessSyntax(asn1types.SequenceOf):
    """
    AuthorityInfoAccessSyntax  ::=
            SEQUENCE SIZE (1..MAX) OF AccessDescription
    """
    item_class = AccessDescription


class IssuingDistributionPoint(asn1types.AttributeSequence):
    """
    issuingDistributionPoint ::= SEQUENCE {
         distributionPoint       [0] DistributionPointName OPTIONAL,
         onlyContainsUserCerts   [1] BOOLEAN DEFAULT FALSE,
         onlyContainsCACerts     [2] BOOLEAN DEFAULT FALSE,
         onlySomeReasons         [3] ReasonFlags OPTIONAL,
         indirectCRL             [4] BOOLEAN DEFAULT FALSE }
    """
    attr_list = [
        'distributionPoint',
        'onlyContainsUserCerts',
        'onlyContainsCACerts',
        'onlySomeReasons',
        'indirectCRL',
    ]

    def __init__(self, val):
        asn1types.AttributeSequence.__init__(self, val)
        for i in self.val:
            if i.tag == 0:
                self.distributionPoint = DistributionPointName(i.val)
            elif i.tag == 1:
                self.onlyContainsUserCerts = asn1.Boolean(i.val)
            elif i.tag == 2:
                self.onlyContainsCACerts = asn1.Boolean(i.val)
            elif i.tag == 3:
                self.onlySomeReasons = ReasonFlags(i.val)
            elif i.tag == 4:
                self.indirectCRL = asn1.Boolean(i.val)


class CRLNumber(asn1.ASN1Object):
    """
    cRLNumber ::= INTEGER (0..MAX)
    """


class SubjectDirectoryAttributes(asn1types.SequenceOf):
    """
    SubjectDirectoryAttributes ::= SEQUENCE SIZE (1..MAX) OF Attribute
    """
    item_class = x500.AttributeTypeAndValue


class SkipCerts(asn1.ASN1Object):
    """
    SkipCerts ::= INTEGER (0..MAX)
    """


class PolicyConstraints(asn1types.AttributeSequence):
    """
    PolicyConstraints ::= SEQUENCE {
         requireExplicitPolicy           [0] SkipCerts OPTIONAL,
         inhibitPolicyMapping            [1] SkipCerts OPTIONAL }

    SkipCerts ::= INTEGER (0..MAX)
    """
    attr_list = [
        'requireExplicitPolicy',
        'inhibitPolicyMapping',
    ]

    def __init__(self, val):
        asn1types.AttributeSequence.__init__(self, val)
        for i in self.val:
            if i.tag == 0:
                self.requireExplicitPolicy = SkipCerts(i.val)
            elif i.tag == 1:
                self.inhibitPolicyMapping = SkipCerts(i.val)


class CRLReason(asn1.Contextual):
    """
     CRLReason ::= ENUMERATED {
          unspecified             (0),
          keyCompromise           (1),
          cACompromise            (2),
          affiliationChanged      (3),
          superseded              (4),
          cessationOfOperation    (5),
          certificateHold         (6),
               -- value 7 is not used
          removeFromCRL           (8),
          privilegeWithdrawn      (9),
          aACompromise           (10) }
    """
    enum_dict = {
        0: 'unspecified',
        1: 'keyCompromise',
        2: 'cACompromise',
        3: 'affiliationChanged',
        4: 'superseded',
        5: 'cessationOfOperation',
        6: 'certificateHold',
        8: 'removeFromCRL',
        9: 'privilegeWithdrawn',
        10: 'aACompromise',
    }

    def __init__(self, val):
        self.val = ord(val)

    def __str__(self):
        try:
            return '%s (%d)' % (self.enum_dict[self.val], self.val)
        except KeyError:
            return str(self.val)

    def __repr__(self):
        return str(self)
