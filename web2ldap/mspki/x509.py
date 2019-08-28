"""
x509.py - X.509 certificate objects

web2ldap - a web-based LDAP Client,
see https://www.web2ldap.de for details

(c) 1998-2019 by Michael Stroeder <michael@stroeder.com>

This software is distributed under the terms of the
Apache License Version 2.0 (Apache-2.0)
https://www.apache.org/licenses/LICENSE-2.0
"""

# Python standard lib
import hashlib

from web2ldap.utctime import strptime
from web2ldap.pisces import asn1

from . import util, x500, asn1helper



class Attribute(asn1.ASN1Object):
    """
    Base class for all attributes and extensions.

    Do not use directly! Just for saving typing methods again and again...
    """
    def __init__(self, val):
        self.val = val

    def __repr__(self):
        return '<x509.%s: %s>' % (self.__class__.__name__, self)


class Version(Attribute):
    """[0]  EXPLICIT Version DEFAULT v1"""

    def __int__(self):
        if self.val is None:
            return 1
        else:
            try:
                return int(self.val)+1
            except TypeError:
                raise TypeError('Expected int for X.509 version number, got %r' % (self.val))

    def __str__(self):
        if self.val is None:
            return str(1)
        return '%d (0x%X)' % (self.val+1, self.val)


class CertificateSerialNumber(Attribute):
    """CertificateSerialNumber ::= INTEGER"""

    def __init__(self, val):
        if isinstance(val, bytes):
            val = util.bytestolong(val)
        self.val = val

    def __int__(self):
        return int(self.val)

    def __hex__(self):
        return hex(self.val)

    def __str__(self):
        if self.val is not None:
            return '%d (0x%X)' % (self.val, self.val)
        return repr(None)


class X509SignedObject:
    """
    Base class for X.509 certificates and CRLs

    This class should not be used directly!
    """

    def __init__(self, buf):
        self.val = asn1.parse(buf)

    def signatureAlgorithm(self, oids=None):
        """Algorithm used when creating signature"""
        if oids:
            return asn1helper.GetOIDDescription(self.val[1].val[0], oids)
        return self.val[1].val[0]

    def signatureValue(self):
        """Certificate's signature value"""
        return self.val[2].val


class Certificate(X509SignedObject):
    """
    Class for X.509 certificates

    Certificate  ::=  SEQUENCE  {
         tbsCertificate       TBSCertificate,
         signatureAlgorithm   AlgorithmIdentifier,
         signatureValue       BIT STRING  }

    TBSCertificate  ::=  SEQUENCE  {
         version         [0]  EXPLICIT Version DEFAULT v1,
         serialNumber         CertificateSerialNumber,
         signature            AlgorithmIdentifier,
         issuer               Name,
         validity             Validity,
         subject              Name,
         subjectPublicKeyInfo SubjectPublicKeyInfo,
         issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
                              -- If present, version shall be v2 or v3
         subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
                              -- If present, version shall be v2 or v3
         extensions      [3]  EXPLICIT Extensions OPTIONAL
                              -- If present, version shall be v3
         }
    """

    def __init__(self, buf):
        X509SignedObject.__init__(self, buf)
        # Nested object with certificate data
        self.tbsCertificate = self.val[0]
        self._buf = buf
        # Try to determine if optional version field is present
        # FIX ME!!! This is a pretty ugly hack!

        if hasattr(self.tbsCertificate[0], 'tag') and \
           self.tbsCertificate[0].tag == 0:
            # no version number present
            self._version = Version(self.tbsCertificate[0].val)
            self._tbsoffset = 1
        else:
            # version number present and encoded in contextual object
            self._version = Version(None)
            self._tbsoffset = 0

    def version(self):
        """X.509 certificate version number as integer"""
        return self._version

    def serialNumber(self):
        """Certificate's serial number as long integer"""
        return CertificateSerialNumber(self.tbsCertificate[self._tbsoffset+0])

    def signature(self, oids=None):
        """Certificate's signature"""
        if oids:
            return asn1helper.GetOIDDescription(self.tbsCertificate[self._tbsoffset+1].val[0], oids)
        return self.tbsCertificate[self._tbsoffset+1].val[0]

    def issuer(self):
        """Issuer's distinguished name"""
        return x500.Name(self.tbsCertificate[self._tbsoffset+2])

    def validity(self):
        """
        Returns tuple (notBefore, notAfter)

        notBefore, notAfter are instances of datetime.datetime
        containing UTCTime of begin and end of validity period.
        """
        return (
            strptime(self.tbsCertificate[self._tbsoffset+3][0].val),
            strptime(self.tbsCertificate[self._tbsoffset+3][1].val)
        )

    def subject(self):
        """Subject's distinguished name"""
        return x500.Name(self.tbsCertificate[self._tbsoffset+4])

    def subjectPublicKeyInfo(self, oids=None):
        """Subject's public key"""
        if oids:
            alg = asn1helper.GetOIDDescription(
                self.tbsCertificate[self._tbsoffset+5].val[0].val[0], oids
            )
        else:
            alg = self.tbsCertificate[self._tbsoffset+5].val[0].val[0]
        modulus, publicExponent = asn1.parse(self.tbsCertificate[self._tbsoffset+5].val[1].val)
        return (alg, modulus, publicExponent)

    def fingerprint(self, digest_algo, delimiter=':'):
        """returns fingerprint in dotted notation (delimiter between bytes)"""
        return util.HexString(hashlib.new(digest_algo, self._buf).digest(), delimiter)

    def issuerUniqueID(self):
        """Get subjectUniqueID (tag 1)"""
        for i in range(self._tbsoffset+6, len(self.tbsCertificate)):
            if isinstance(self.tbsCertificate[i], asn1.Contextual):
                if self.tbsCertificate[i].tag == 1:
                    return self.tbsCertificate[i]
        return None

    def subjectUniqueID(self):
        """Get subjectUniqueID (tag 2)"""
        for i in range(self._tbsoffset+6, len(self.tbsCertificate)):
            if isinstance(self.tbsCertificate[i], asn1.Contextual):
                if self.tbsCertificate[i].tag == 2:
                    return self.tbsCertificate[i]
        return None


class CRL(X509SignedObject):
    """
    Class for X.509 CRLs

    CertificateList  ::=  SEQUENCE  {
         tbsCertList          TBSCertList,
         signatureAlgorithm   AlgorithmIdentifier,
         signatureValue       BIT STRING  }

    TBSCertList  ::=  SEQUENCE  {
         version                 Version OPTIONAL,
                                      -- if present, shall be v2
         signature               AlgorithmIdentifier,
         issuer                  Name,
         thisUpdate              Time,
         nextUpdate              Time OPTIONAL,
         revokedCertificates     SEQUENCE OF SEQUENCE  {
              userCertificate         CertificateSerialNumber,
              revocationDate          Time,
              crlEntryExtensions      Extensions OPTIONAL
                                            -- if present, shall be v2
                                   }  OPTIONAL,
         crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                            -- if present, shall be v2
                                   }
    """

    def __init__(self, buf):
        X509SignedObject.__init__(self, buf)
        # Nested object with CRL data
        self.tbsCertList = self.val[0]
        # Try to determine if optional version field is present
        # FIX ME!!! This is a pretty ugly hack!
        if isinstance(self.tbsCertList[0], asn1.Sequence):
            self._version = Version(None)
            self._tbsoffset = 0
        else:
            self._version = Version(self.tbsCertList[0])
            self._tbsoffset = 1

    def version(self):
        """X.509 CRL version number as integer"""
        return self._version

    def signature(self, oids=None):
        """Certificate's signature algorithm"""
        if oids:
            return asn1helper.GetOIDDescription(
                self.tbsCertList[self._tbsoffset+0].val[0],
                oids
            )
        return self.tbsCertList[self._tbsoffset+0].val[0]

    def issuer(self):
        """Issuer's distinguished name"""
        return x500.Name(self.tbsCertList[self._tbsoffset+1])

    def thisUpdate(self):
        """Returns time tuple of thisUpdate"""
        return strptime(self.tbsCertList[self._tbsoffset+2].val)

    def nextUpdate(self):
        """Returns UTCTime of nextUpdate if present, None else"""
        if isinstance(self.tbsCertList[self._tbsoffset+3], asn1.UTCTime) or \
           isinstance(self.tbsCertList[self._tbsoffset+3], asn1.GeneralizedTime):
            return strptime(self.tbsCertList[self._tbsoffset+3].val)
        return None

    def revokedCertificates(self):
        """
        Get list of revoked certificates.

        Each list member is a tuple
        (
          userCertificate,          # serial number of revoked certificate
                                    # as long integer
          revocationDate,           # time tuple of revocation timestamp
          crlEntryExtensions        # optional (None if not present)
        )
        """
        revokeList = []
        # Check whether nextUpdate is there
        if isinstance(self.tbsCertList[self._tbsoffset+3], asn1.UTCTime) or \
           isinstance(self.tbsCertList[self._tbsoffset+3], asn1.GeneralizedTime):
            crl_offset = 4
        else:
            # nextUpdate is missing
            crl_offset = 3
        if len(self.tbsCertList) >= self._tbsoffset+crl_offset+1 and \
           (not hasattr(self.tbsCertList[self._tbsoffset+crl_offset], 'tag') or \
           self.tbsCertList[self._tbsoffset+crl_offset].tag != 0):
            for i in self.tbsCertList[self._tbsoffset+crl_offset].val:
                i_len = len(i)
                if i_len in {2, 3}:
                    userCertificate = i[0]
                    revocationDate = strptime(str(i[1].val))
                else:
                    raise ValueError(
                        "Item in revokedCertificates list has invalid length (%d)." % (i_len)
                    )
                if i_len == 3:
                    from .x509v3 import Extensions as x509v3_Extensions
                    crlEntryExtensions = x509v3_Extensions(i[2])
                else:
                    crlEntryExtensions = None
                revokeList.append((userCertificate, revocationDate, crlEntryExtensions))
        return revokeList
