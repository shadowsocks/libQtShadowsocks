/*
 * qca_cert.h - Qt Cryptographic Architecture
 * Copyright (C) 2003-2007  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004-2006  Brad Hards <bradh@frogmouth.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

/**
   \file qca_cert.h

   Header file for PGP key and X.509 certificate related classes

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_CERT_H
#define QCA_CERT_H

#include <QMap>
#include <QDateTime>
#include "qca_core.h"
#include "qca_publickey.h"

namespace QCA {

class CertContext;
class CSRContext;
class CRLContext;
class Certificate;
class CRL;
class CertificateCollection;
class CertificateChain;


/**
   Certificate Request Format
*/
enum CertificateRequestFormat
{
	PKCS10, ///< standard PKCS#10 format
	SPKAC   ///< Signed Public Key and Challenge (Netscape) format
};

/**
   Known types of information stored in certificates

   This enumerator offers a convenient way to work with common types.
*/
enum CertificateInfoTypeKnown
{
	CommonName,             ///< The common name (eg person), id = "2.5.4.3"
	Email,                  ///< Email address, id = "GeneralName.rfc822Name"
	EmailLegacy,            ///< PKCS#9 Email field, id = "1.2.840.113549.1.9.1"
	Organization,           ///< An organisation (eg company), id = "2.5.4.10"
	OrganizationalUnit,     ///< An part of an organisation (eg a division or branch), id = "2.5.4.11"
	Locality,               ///< The locality (eg city, a shire, or part of a state), id = "2.5.4.7"
	IncorporationLocality,  ///< The locality of incorporation (EV certificates), id = "1.3.6.1.4.1.311.60.2.1.1"
	State,                  ///< The state within the country, id = "2.5.4.8"
	IncorporationState,     ///< The state of incorporation (EV certificates), id = "1.3.6.1.4.1.311.60.2.1.2"
	Country,                ///< The country, id = "2.5.4.6"
	IncorporationCountry,   ///< The country of incorporation (EV certificates), id = "1.3.6.1.4.1.311.60.2.1.3"
	URI,                    ///< Uniform Resource Identifier, id = "GeneralName.uniformResourceIdentifier"
	DNS,                    ///< DNS name, id = "GeneralName.dNSName"
	IPAddress,              ///< IP address, id = "GeneralName.iPAddress"
	XMPP                    ///< XMPP address (see http://www.ietf.org/rfc/rfc3920.txt), id = "1.3.6.1.5.5.7.8.5"
};

/**
   \class CertificateInfoType qca_cert.h QtCrypto

   Certificate information type

   This class represents a type of information being stored in
   a certificate.  It can be created either using a known type
   (from the Known enumerator) or an identifier string (usually
   an OID).  Types created either way are interchangeable.

   Types also have the notion of a Section.  Some types may
   reside in the Distinguished Name field of a certificate, and
   some types may reside in the Subject Alternative Name field.
   This class is capable of representing a type from either
   section.

   In the general case, applications will want to use the
   CertificateInfoTypeKnown enumerator types.  These are from RFC3280
   (http://www.ietf.org/rfc/rfc3280.txt) except where shown.

   The entries for IncorporationLocality, IncorporationState
   and IncorporationCountry are the same as Locality, State
   and Country respectively, except that the Extended
   Validation (EV) certificate guidelines (published by the
   %Certificate Authority / Browser Forum, see
   http://www.cabforum.org) distinguish between the place of
   where the company does business (which is the Locality /
   State / Country combination) and the jurisdiction where the
   company is legally incorporated (the IncorporationLocality
   / IncorporationState / IncorporationCountry combination).

   \sa Certificate::subjectInfo() and Certificate::issuerInfo()
   \sa CRL::issuerInfo()

   \ingroup UserAPI
*/
class QCA_EXPORT CertificateInfoType
{
public:
	/**
	   Section of the certificate that the information belongs in
	*/
	enum Section
	{
		DN,              ///< Distinguished name (the primary name)
		AlternativeName  ///< Alternative name
	};

	/**
	   Standard constructor
	*/
	CertificateInfoType();

	/**
	   Construct a new type

	   The section will be derived by \a known.

	   \param known the type as part of the CertificateInfoTypeKnown
	   enumerator
	*/
	CertificateInfoType(CertificateInfoTypeKnown known);

	/**
	   Construct a new type

	   \param id the type as an identifier string (OID or internal)
	   \param section the section this type belongs in

	   \sa id
	*/
	CertificateInfoType(const QString &id, Section section);

	/**
	   Standard copy constructor

	   \param from the certificate information to copy from
	*/
	CertificateInfoType(const CertificateInfoType &from);

	~CertificateInfoType();

	/**
	   Standard assignment operator

	   \param from the certificate information to assign from
	*/
	CertificateInfoType & operator=(const CertificateInfoType &from);

	/**
	   The section the type is part of
	*/
	Section section() const;

	/**
	   The type as part of the CertificateInfoTypeKnown enumerator

	   This function may return a value that does not exist in the
	   enumerator.  In that case, you may use id() to determine the
	   type.
	*/
	CertificateInfoTypeKnown known() const;

	/**
	   The type as an identifier string

	   For types that have OIDs, this function returns an OID in string
	   form.  For types that do not have OIDs, this function returns an
	   internal identifier string whose first character is not a digit
	   (this allows you to tell the difference between an OID and an
	   internal identifier).

	   It is hereby stated that General Names (of the X.509 Subject
	   Alternative Name) shall use the internal identifier format
	   "GeneralName.[rfc field name]".  For example, the rfc822Name
	   field would have the identifier "GeneralName.rfc822Name".

	   Applications should not store, use, or compare against internal
	   identifiers unless the identifiers are explicitly documented
	   (e.g. GeneralName).
	*/
	QString id() const;

	/**
	   Comparison operator

	   \param other the certificate information to compare with this
	   certificate information.
	*/
	bool operator<(const CertificateInfoType &other) const;

	/**
	   Comparison operator

	   \param other the certificate information to compare with this
	   certificate information.
	*/
	bool operator==(const CertificateInfoType &other) const;

	/**
	   Inequality operator

	   \param other the certificate information to compare with this
	   certificate information.
	*/
	inline bool operator!=(const CertificateInfoType &other) const
	{
		return !(*this == other);
	}

private:
	class Private;
	QSharedDataPointer<Private> d;
};

/**
   \class CertificateInfoPair qca_cert.h QtCrypto

   One entry in a certificate information list

   \ingroup UserAPI
*/
class QCA_EXPORT CertificateInfoPair
{
public:
	/**
	   Standard constructor
	*/
	CertificateInfoPair();

	/**
	   Construct a new pair

	   \param type the type of information stored in this pair
	   \param value the value of the information to be stored
	*/
	CertificateInfoPair(const CertificateInfoType &type, const QString &value);

	/**
	   Standard copy constructor

	   \param from the information pair to copy from
	*/
	CertificateInfoPair(const CertificateInfoPair &from);

	~CertificateInfoPair();

	/**
	   Standard assignment operator

	   \param from the information pair to assign from
	*/
	CertificateInfoPair & operator=(const CertificateInfoPair &from);

	/**
	   The type of information stored in the pair
	*/
	CertificateInfoType type() const;

	/**
	   The value of the information stored in the pair
	*/
	QString value() const;

	/**
	   Comparison operator

	   \param other the certificate information pair to compare with this
	   certificate information pair.
	*/
	bool operator==(const CertificateInfoPair &other) const;

	/**
	   Inequality operator

	   \param other the certificate information pair to compare with this
	   certificate information pair.
	*/
	inline bool operator!=(const CertificateInfoPair &other) const
	{
		return !(*this == other);
	}

private:
	class Private;
	QSharedDataPointer<Private> d;
};


/**
   Known types of certificate constraints

   This enumerator offers a convenient way to work with common types.
*/
enum ConstraintTypeKnown
{
	// KeyUsage
	DigitalSignature,    ///< %Certificate can be used to create digital signatures, id = "KeyUsage.digitalSignature"
	NonRepudiation,      ///< %Certificate can be used for non-repudiation, id = "KeyUsage.nonRepudiation"
	KeyEncipherment,     ///< %Certificate can be used for encrypting / decrypting keys, id = "KeyUsage.keyEncipherment"
	DataEncipherment,    ///< %Certificate can be used for encrypting / decrypting data, id = "KeyUsage.dataEncipherment"
	KeyAgreement,        ///< %Certificate can be used for key agreement, id = "KeyUsage.keyAgreement"
	KeyCertificateSign,  ///< %Certificate can be used for key certificate signing, id = "KeyUsage.keyCertSign"
	CRLSign,             ///< %Certificate can be used to sign %Certificate Revocation Lists, id = "KeyUsage.crlSign"
	EncipherOnly,        ///< %Certificate can only be used for encryption, id = "KeyUsage.encipherOnly"
	DecipherOnly,        ///< %Certificate can only be used for decryption, id = "KeyUsage.decipherOnly"

	// ExtKeyUsage
	ServerAuth,       ///< %Certificate can be used for server authentication (e.g. web server), id = "1.3.6.1.5.5.7.3.1". This is an extended usage constraint.
	ClientAuth,       ///< %Certificate can be used for client authentication (e.g. web browser), id = "1.3.6.1.5.5.7.3.2". This is an extended usage constraint.
	CodeSigning,      ///< %Certificate can be used to sign code, id = "1.3.6.1.5.5.7.3.3". This is an extended usage constraint.
	EmailProtection,  ///< %Certificate can be used to sign / encrypt email, id = "1.3.6.1.5.5.7.3.4". This is an extended usage constraint.
	IPSecEndSystem,   ///< %Certificate can be used to authenticate a endpoint in IPSEC, id = "1.3.6.1.5.5.7.3.5". This is an extended usage constraint.
	IPSecTunnel,      ///< %Certificate can be used to authenticate a tunnel in IPSEC, id = "1.3.6.1.5.5.7.3.6". This is an extended usage constraint.
	IPSecUser,        ///< %Certificate can be used to authenticate a user in IPSEC, id = "1.3.6.1.5.5.7.3.7". This is an extended usage constraint.
	TimeStamping,     ///< %Certificate can be used to create a "time stamp" signature, id = "1.3.6.1.5.5.7.3.8". This is an extended usage constraint.
	OCSPSigning       ///< %Certificate can be used to sign an Online %Certificate Status Protocol (OCSP) assertion, id = "1.3.6.1.5.5.7.3.9". This is an extended usage constraint.
};

/**
   \class ConstraintType qca_cert.h QtCrypto

   Certificate constraint

   X.509 certificates can be constrained in their application - that is, some
   certificates can only be used for certain purposes. This class is used to
   identify an approved purpose for a certificate.

   \note It is common for a certificate to have more than one purpose.

   \ingroup UserAPI
*/
class QCA_EXPORT ConstraintType
{
public:
	/**
	   Section of the certificate that the constraint belongs in
	*/
	enum Section
	{
		KeyUsage,          ///< Stored in the key usage section
		ExtendedKeyUsage   ///< Stored in the extended key usage section
	};

	/**
	   Standard constructor
	*/
	ConstraintType();

	/**
	   Construct a new constraint

	   The section will be derived by \a known.

	   \param known the type as part of the ConstraintTypeKnown
	   enumerator
	*/
	ConstraintType(ConstraintTypeKnown known);

	/**
	   Construct a new constraint

	   \param id the type as an identifier string (OID or internal)
	   \param section the section this type belongs in

	   \sa id
	*/
	ConstraintType(const QString &id, Section section);

	/**
	   Standard copy constructor

	   \param from the constraint type to copy from
	*/
	ConstraintType(const ConstraintType &from);

	~ConstraintType();

	/**
	   Standard assignment operator

	   \param from the constraint type to assign from
	*/
	ConstraintType & operator=(const ConstraintType &from);

	/**
	   The section the constraint is part of
	*/
	Section section() const;

	/**
	   The type as part of the ConstraintTypeKnown enumerator

	   This function may return a value that does not exist in the
	   enumerator.  In that case, you may use id() to determine the
	   type.
	*/
	ConstraintTypeKnown known() const;

	/**
	   The type as an identifier string

	   For types that have OIDs, this function returns an OID in string
	   form.  For types that do not have OIDs, this function returns an
	   internal identifier string whose first character is not a digit
	   (this allows you to tell the difference between an OID and an
	   internal identifier).

	   It is hereby stated that the KeyUsage bit fields shall use the
	   internal identifier format "KeyUsage.[rfc field name]".  For
	   example, the keyEncipherment field would have the identifier
	   "KeyUsage.keyEncipherment".

	   Applications should not store, use, or compare against internal
	   identifiers unless the identifiers are explicitly documented
	   (e.g. KeyUsage).
	*/
	QString id() const;

	/**
	   Comparison operator

	   \param other the constraint type to compare with this constraint
	*/
	bool operator<(const ConstraintType &other) const;

	/**
	   Comparison operator

	   \param other the constraint type to compare with this constraint
	*/
	bool operator==(const ConstraintType &other) const;

	/**
	   Inequality operator

	   \param other the constraint type to compare with this constraint
	*/
	inline bool operator!=(const ConstraintType &other) const
	{
		return !(*this == other);
	}

private:
	class Private;
	QSharedDataPointer<Private> d;
};

/**
   Specify the intended usage of a certificate
*/
enum UsageMode
{
	UsageAny             = 0x00, ///< Any application, or unspecified
	UsageTLSServer       = 0x01, ///< server side of a TLS or SSL connection
	UsageTLSClient       = 0x02, ///< client side of a TLS or SSL connection
	UsageCodeSigning     = 0x04, ///< code signing certificate
	UsageEmailProtection = 0x08, ///< email (S/MIME) certificate
	UsageTimeStamping    = 0x10, ///< time stamping certificate
	UsageCRLSigning      = 0x20  ///< certificate revocation list signing certificate
};

/**
   The validity (or otherwise) of a certificate
*/
enum Validity
{
	ValidityGood,            ///< The certificate is valid
	ErrorRejected,           ///< The root CA rejected the certificate purpose
	ErrorUntrusted,          ///< The certificate is not trusted
	ErrorSignatureFailed,    ///< The signature does not match
	ErrorInvalidCA,          ///< The Certificate Authority is invalid
	ErrorInvalidPurpose,     ///< The purpose does not match the intended usage
	ErrorSelfSigned,         ///< The certificate is self-signed, and is not found in the list of trusted certificates
	ErrorRevoked,            ///< The certificate has been revoked
	ErrorPathLengthExceeded, ///< The path length from the root CA to this certificate is too long
	ErrorExpired,            ///< The certificate has expired, or is not yet valid (e.g. current time is earlier than notBefore time)
	ErrorExpiredCA,          ///< The Certificate Authority has expired
	ErrorValidityUnknown = 64  ///< Validity is unknown
};

/**
   The conditions to validate for a certificate
*/
enum ValidateFlags
{
	ValidateAll     = 0x00,  // Verify all conditions
	ValidateRevoked = 0x01,  // Verify the certificate was not revoked
	ValidateExpired = 0x02,  // Verify the certificate has not expired
	ValidatePolicy  = 0x04   // Verify the certificate can be used for a specified purpose
};

/**
   Certificate properties type

   With this container, the information is not necessarily stored
   in the same sequence as the certificate format itself.  Use this
   container if the order the information is/was stored does not
   matter for you (this is the case with most applications).

   Additionally, the EmailLegacy type should not be used with this
   container.  Use Email instead.
*/
typedef QMultiMap<CertificateInfoType, QString> CertificateInfo;

/**
   \class CertificateInfoOrdered qca_cert.h QtCrypto

   Ordered certificate properties type

   This container stores the information in the same sequence as
   the certificate format itself.

   \ingroup UserAPI
*/
class CertificateInfoOrdered : public QList<CertificateInfoPair>
{
public:
	/**
	   Convert to RFC 1779 string format
	*/
	inline QString toString() const;

	/**
	   Return a new CertificateInfoOrdered that only contains
	   the Distinguished Name (DN) types found in this object.
	*/
	inline CertificateInfoOrdered dnOnly() const;
};

/**
   Convert to RFC 1779 string format

   \param in the certificate info to convert
*/
QCA_EXPORT QString orderedToDNString(const CertificateInfoOrdered &in);

/**
   Return a new CertificateInfoOrdered that only contains
   the Distinguished Name (DN) types found in the input object.

   \param in the certificate info to extract from
*/
QCA_EXPORT CertificateInfoOrdered orderedDNOnly(const CertificateInfoOrdered &in);

inline QString CertificateInfoOrdered::toString() const
{
	return orderedToDNString(*this);
}

inline CertificateInfoOrdered CertificateInfoOrdered::dnOnly() const
{
	return orderedDNOnly(*this);
}

/**
   %Certificate constraints type
*/
typedef QList<ConstraintType> Constraints;

/**
   Create a list of unique friendly names among a list of certificates

   \param list the list of certificates for which a friendly name is required.

*/
QCA_EXPORT QStringList makeFriendlyNames(const QList<Certificate> &list);

/**
   \class CertificateOptions qca_cert.h QtCrypto

   %Certificate options

   \note In SPKAC mode, all options are ignored except for challenge

   \ingroup UserAPI
*/
class QCA_EXPORT CertificateOptions
{
public:
	/**
	   Create a Certificate options set

	   \param format the format to create the certificate request in
	*/
	CertificateOptions(CertificateRequestFormat format = PKCS10);

	/**
	   Standard copy constructor

	   \param from the Certificate Options to copy into this object
	*/
	CertificateOptions(const CertificateOptions &from);
	~CertificateOptions();

	/**
	   Standard assignment operator

	   \param from the Certificate Options to copy into this object
	*/
	CertificateOptions & operator=(const CertificateOptions &from);

	/**
	   test the format type for this certificate
	*/
	CertificateRequestFormat format() const;

	/**
	   Specify the format for this certificate

	   \param f the format to use
	*/
	void setFormat(CertificateRequestFormat f);

	/**
	   Test if the certificate options object is valid

	   \return true if the certificate options object is valid
	*/
	bool isValid() const;

	/**
	   The challenge part of the certificate

	   For CertificateRequest only

	   \sa setChallenge
	*/
	QString challenge() const;

	/**
	   Information on the subject of the certificate

	   \sa setInfo
	*/
	CertificateInfo info() const;

	/**
	   Information on the subject of the certificate, in the
	   exact order the items will be written

	   \sa setInfoOrdered
	*/
	CertificateInfoOrdered infoOrdered() const;

	/**
	   List the constraints on this certificate
	*/
	Constraints constraints() const;

	/**
	   list the policies on this certificate
	*/
	QStringList policies() const;

	/**
	   list of URI locations for CRL files

	   each URI refers to the same CRL file

	   For Certificate creation only
	*/
	QStringList crlLocations() const;

	/**
	   list of URI locations for issuer certificate files

	   each URI refers to the same issuer file

	   For Certificate creation only
	*/
	QStringList issuerLocations() const;

	/**
	   list of URI locations for OCSP services

	   For Certificate creation only
	*/
	QStringList ocspLocations() const;

	/**
	   test if the certificate is a CA cert

	   \sa setAsCA
	   \sa setAsUser
	*/
	bool isCA() const;

	/**
	   return the path limit on this certificate
	*/
	int pathLimit() const;

	/**
	   The serial number for the certificate

	   For Certificate creation only
	*/
	BigInteger serialNumber() const;

	/**
	   the first time the certificate will be valid

	   For Certificate creation only
	*/
	QDateTime notValidBefore() const;

	/**
	   the last time the certificate is valid

	   For Certificate creation only
	*/
	QDateTime notValidAfter() const;

	/**
	   Specify the challenge associated with this
	   certificate

	   \param s the challenge string

	   \sa challenge()
	*/
	void setChallenge(const QString &s);

	/**
	   Specify information for the the subject associated with the
	   certificate

	   \param info the information for the subject

	   \sa info()
	*/
	void setInfo(const CertificateInfo &info);

	/**
	   Specify information for the the subject associated with the
	   certificate

	   \param info the information for the subject

	   \sa info()
	*/
	void setInfoOrdered(const CertificateInfoOrdered &info);

	/**
	   set the constraints on the certificate

	   \param constraints the constraints to be used for the certificate
	*/
	void setConstraints(const Constraints &constraints);

	/**
	   set the policies on the certificate

	   \param policies the policies to be used for the certificate
	*/
	void setPolicies(const QStringList &policies);

	/**
	   set the CRL locations of the certificate

	   each location refers to the same CRL.

	   \param locations a list of URIs to CRL files
	*/
	void setCRLLocations(const QStringList &locations);

	/**
	   set the issuer certificate locations of the certificate

	   each location refers to the same issuer file.

	   \param locations a list of URIs to issuer certificate files
	*/
	void setIssuerLocations(const QStringList &locations);

	/**
	   set the OCSP service locations of the certificate

	   \param locations a list of URIs to OCSP services
	*/
	void setOCSPLocations(const QStringList &locations);

	/**
	   set the certificate to be a CA cert

	   \param pathLimit the number of intermediate certificates allowable
	*/
	void setAsCA(int pathLimit = 8); // value from Botan

	/**
	   set the certificate to be a user cert (this is the default)
	*/
	void setAsUser();

	/**
	   Set the serial number property on this certificate

	   \param i the serial number to use
	*/
	void setSerialNumber(const BigInteger &i);

	/**
	   Set the validity period for the certificate

	   \param start the first time this certificate becomes valid
	   \param end the last time this certificate is valid
	*/
	void setValidityPeriod(const QDateTime &start, const QDateTime &end);

private:
	class Private;
	Private *d;
};

/**
   \class Certificate qca_cert.h QtCrypto

   Public Key (X.509) certificate

   This class contains one X.509 certificate

   \ingroup UserAPI
*/
class QCA_EXPORT Certificate : public Algorithm
{
public:
	/**
	   Create an empty Certificate
	*/
	Certificate();

	/**
	   Create a Certificate from a PEM encoded file

	   \param fileName the name (and path, if required)
	   of the file that contains the PEM encoded certificate
	*/
	Certificate(const QString &fileName);

	/**
	   Create a Certificate with specified options and a specified private
	   key

	   \param opts the options to use
	   \param key the private key for this certificate
	   \param provider the provider to use to create this key, if a
	   particular provider is required
	*/
	Certificate(const CertificateOptions &opts, const PrivateKey &key, const QString &provider = QString());

	/**
	   Standard copy constructor

	   \param from the certificate to copy from
	*/
	Certificate(const Certificate &from);

	~Certificate();

	/**
	   Standard assignment operator

	   \param from the Certificate to assign from
	*/
	Certificate & operator=(const Certificate &from);

	/**
	   Test if the certificate is empty (null)
	   \return true if the certificate is null
	*/
	bool isNull() const;

	/**
	   The earliest date that the certificate is valid
	*/
	QDateTime notValidBefore() const;

	/**
	   The latest date that the certificate is valid
	*/
	QDateTime notValidAfter() const;

	/**
	   Properties of the subject of the certificate, as a QMultiMap

	   This is the method that provides information on the
	   subject organisation, common name, DNS name, and so
	   on. The list of information types (i.e. the key to
	   the multi-map) is a CertificateInfoType. The values
	   are a list of QString.

	   An example of how you can iterate over the list is:
	   \code
foreach( QString dns, info.values(QCA::DNS) )
{
	std::cout << "    " << qPrintable(dns) << std::endl;
}
	   \endcode
	*/
	CertificateInfo subjectInfo() const;

	/**
	   Properties of the subject of the certificate, as 
	   an ordered list (QList of CertificateInfoPair).

	   This allows access to the certificate information 
	   in the same order as they appear in a certificate.
	   Each pair in the list has a type and a value.

	   For example:
	   \code
CertificateInfoOrdered info = cert.subjectInfoOrdered();
// info[0].type == CommonName
// info[0].value == "example.com"
	   \endcode

	   \sa subjectInfo for an unordered version
	   \sa issuerInfoOrdered for the ordered information on the issuer
	   \sa CertificateInfoPair for the elements in the list
	*/
	CertificateInfoOrdered subjectInfoOrdered() const;

	/**
	   Properties of the issuer of the certificate

	   \sa subjectInfo for how the return value works.
	*/
	CertificateInfo issuerInfo() const;

	/**
	   Properties of the issuer of the certificate, as 
	   an ordered list (QList of CertificateInfoPair).

	   This allows access to the certificate information 
	   in the same order as they appear in a certificate.
	   Each pair in the list has a type and a value.

	   \sa issuerInfo for an unordered version
	   \sa subjectInfoOrdered for the ordered information on the subject
	   \sa CertificateInfoPair for the elements in the list
	*/
	CertificateInfoOrdered issuerInfoOrdered() const;

	/**
	   The constraints that apply to this certificate
	*/
	Constraints constraints() const;

	/**
	   The policies that apply to this certificate

	   Policies are specified as strings containing OIDs
	*/
	QStringList policies() const;

	/**
	   List of URI locations for CRL files

	   Each URI refers to the same CRL file
	*/
	QStringList crlLocations() const;

	/**
	   List of URI locations for issuer certificate files

	   Each URI refers to the same issuer file
	*/
	QStringList issuerLocations() const;

	/**
	   List of URI locations for OCSP services
	*/
	QStringList ocspLocations() const;

	/**
	   The common name of the subject of the certificate

	   Common names are normally the name of a person, company or
	   organisation
	*/
	QString commonName() const;

	/**
	   The serial number of the certificate
	*/
	BigInteger serialNumber() const;

	/**
	   The public key associated with the subject of the certificate
	*/
	PublicKey subjectPublicKey() const;

	/**
	   Test if the Certificate is valid as a Certificate Authority

	   \return true if the Certificate is valid as a Certificate Authority
	*/
	bool isCA() const;

	/**
	   Test if the Certificate is self-signed

	   \return true if the certificate is self-signed
	*/
	bool isSelfSigned() const;

	/**
	   Test if the Certificate has signed another Certificate
	   object and is therefore the issuer

	   \param other the certificate to test

	   \return true if this certificate is the issuer of the argument
	*/
	bool isIssuerOf(const Certificate &other) const;

	/**
	   The upper bound of the number of links in the certificate
	   chain, if any
	*/
	int pathLimit() const;

	/**
	   The signature algorithm used for the signature on this certificate
	*/
	SignatureAlgorithm signatureAlgorithm() const;

	/**
	   The key identifier associated with the subject
	*/
	QByteArray subjectKeyId() const;

	/**
	   The key identifier associated with the issuer
	*/
	QByteArray issuerKeyId() const;

	/**
	   Check the validity of a certificate

	   \param trusted a collection of trusted certificates
	   \param untrusted a collection of additional certificates, not
	   necessarily trusted
	   \param u the use required for the certificate
	   \param vf the conditions to validate

	   \note This function may block
	*/
	Validity validate(const CertificateCollection &trusted, const CertificateCollection &untrusted, UsageMode u = UsageAny, ValidateFlags vf = ValidateAll) const;

	/**
	   Export the Certificate into a DER format
	*/
	QByteArray toDER() const;

	/**
	   Export the Certificate into a PEM format
	*/
	QString toPEM() const;

	/**
	   Export the Certificate into PEM format in a file

	   \param fileName the name of the file to use
	*/
	bool toPEMFile(const QString &fileName) const;

	/**
	   Import the certificate from DER

	   \param a the array containing the certificate in DER format
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the Certificate corresponding to the certificate in the
	   provided array
	*/
	static Certificate fromDER(const QByteArray &a, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Import the certificate from PEM format

	   \param s the string containing the certificate in PEM format
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the Certificate corresponding to the certificate in the
	   provided string
	*/
	static Certificate fromPEM(const QString &s, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Import the certificate from a file

	   \param fileName the name (and path, if required) of the file
	   containing the certificate in PEM format
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the Certificate corresponding to the certificate in the
	   provided string
	*/
	static Certificate fromPEMFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Test if the subject of the certificate matches a specified host
	   name

	   This will return true (indicating a match), if the specified host
	   name meets the RFC 2818 validation rules with this certificate.

	   If the host is an internationalized domain name, then it must be
	   provided in unicode format, not in IDNA ACE/punycode format.

	   \param host the name of the host to compare to
	*/
	bool matchesHostName(const QString &host) const;

	/**
	   Test for equality of two certificates

	   \param a the certificate to compare this certificate with

	   \return true if the two certificates are the same
	*/
	bool operator==(const Certificate &a) const;

	/**
	   Inequality operator

	   \param other the certificate to compare this certificate with
	*/
	inline bool operator!=(const Certificate &other) const
	{
		return !(*this == other);
	}

	/**
	   \internal

	   \param c context (internal)
	*/
	void change(CertContext *c);

private:
	class Private;
	friend class Private;
	QSharedDataPointer<Private> d;

	friend class CertificateChain;
	Validity chain_validate(const CertificateChain &chain, const CertificateCollection &trusted, const QList<CRL> &untrusted_crls, UsageMode u, ValidateFlags vf) const;
	CertificateChain chain_complete(const CertificateChain &chain, const QList<Certificate> &issuers, Validity *result) const;
};

/**
   \class CertificateChain qca_cert.h QtCrypto

   A chain of related Certificates

   CertificateChain is a list (a QList) of certificates that are related by
   the signature from one to another. If Certificate C signs Certificate B,
   and Certificate B signs Certificate A, then C, B and A form a chain.

   The normal use of a CertificateChain is from a end-user Certificate (called
   the primary, equivalent to QList::first()) through some intermediate
   Certificates to some other Certificate (QList::last()), which might be a
   root Certificate Authority, but does not need to be.

   You can build up the chain using normal QList operations, such as
   QList::append().

   \sa QCA::CertificateCollection for an alternative way to represent a group
   of Certificates that do not necessarily have a chained relationship.

   \ingroup UserAPI
*/
class CertificateChain : public QList<Certificate>
{
public:
	/**
	   Create an empty certificate chain
	*/
	inline CertificateChain() {}

	/**
	   Create a certificate chain, starting at the specified certificate

	   \param primary the end-user certificate that forms one end of the
	   chain
	*/
	inline CertificateChain(const Certificate &primary) { append(primary); }

	/**
	   Return the primary (end-user) Certificate
	*/
	inline const Certificate & primary() const { return first(); }

	/**
	   Check the validity of a certificate chain

	   \param trusted a collection of trusted certificates
	   \param untrusted_crls a list of additional CRLs, not necessarily
	   trusted
	   \param u the use required for the primary certificate
	   \param vf the conditions to validate

	   \note This function may block

	   \sa Certificate::validate()
	*/
	inline Validity validate(const CertificateCollection &trusted, const QList<CRL> &untrusted_crls = QList<CRL>(), UsageMode u = UsageAny, ValidateFlags vf = ValidateAll) const;

	/**
	   Complete a certificate chain for the primary certificate, using the
	   rest of the certificates in the chain object, as well as those in
	   \a issuers, as possible issuers in the chain.  If there are issuers
	   missing, then the chain might be incomplete (at the worst case, if
	   no issuers exist for the primary certificate, then the resulting
	   chain will consist of just the primary certificate).  Use the
	   \a result argument to find out if there was a problem during
	   completion.  A result of ValidityGood means the chain was completed
	   successfully.

	   The newly constructed CertificateChain is returned.

	   If the certificate chain is empty, then this will return an empty
	   CertificateChain object.

	   \param issuers a pool of issuers to draw from as necessary
	   \param result the result of the completion operation

	   \note This function may block

	   \sa validate
	*/
	inline CertificateChain complete(const QList<Certificate> &issuers = QList<Certificate>(), Validity *result = 0) const;
};

inline Validity CertificateChain::validate(const CertificateCollection &trusted, const QList<CRL> &untrusted_crls, UsageMode u, ValidateFlags vf) const
{
	if(isEmpty())
		return ErrorValidityUnknown;
	return first().chain_validate(*this, trusted, untrusted_crls, u, vf);
}

inline CertificateChain CertificateChain::complete(const QList<Certificate> &issuers, Validity *result) const
{
	if(isEmpty())
		return CertificateChain();
	return first().chain_complete(*this, issuers, result);
}

/**
   \class CertificateRequest qca_cert.h QtCrypto

   %Certificate Request

   A CertificateRequest is a unsigned request for a Certificate

   \ingroup UserAPI
*/
class QCA_EXPORT CertificateRequest : public Algorithm
{
public:
	/**
	   Create an empty certificate request
	*/
	CertificateRequest();

	/**
	   Create a certificate request based on the contents of a file

	   \param fileName the file (and path, if necessary) containing a PEM
	   encoded certificate request
	*/
	CertificateRequest(const QString &fileName);

	/**
	   Create a certificate request based on specified options

	   \param opts the options to use in the certificate request
	   \param key the private key that matches the certificate being
	   requested
	   \param provider the provider to use, if a specific provider is
	   required
	*/
	CertificateRequest(const CertificateOptions &opts, const PrivateKey &key, const QString &provider = QString());

	/**
	   Standard copy constructor

	   \param from the request to copy from
	*/
	CertificateRequest(const CertificateRequest &from);

	~CertificateRequest();

	/**
	   Standard assignment operator

	   \param from the request to assign from
	*/
	CertificateRequest & operator=(const CertificateRequest &from);

	/**
	   test if the certificate request is empty

	   \return true if the certificate request is empty, otherwise false
	*/
	bool isNull() const;

	/**
	   Test if the certificate request can use a specified format

	   \param f the format to test for
	   \param provider the provider to use, if a specific provider is
	   required

	   \return true if the certificate request can use the specified
	   format
	*/
	static bool canUseFormat(CertificateRequestFormat f, const QString &provider = QString());

	/**
	   the format that this Certificate request is in
	*/
	CertificateRequestFormat format() const;

	/**
	   Information on the subject of the certificate being requested

	   \note this only applies to PKCS#10 format certificate requests

	   \sa subjectInfoOrdered for a version that maintains order
	   in the subject information.
	*/
	CertificateInfo subjectInfo() const;

	/**
	   Information on the subject of the certificate being requested, as 
	   an ordered list (QList of CertificateInfoPair).

	   \note this only applies to PKCS#10 format certificate requests

	   \sa subjectInfo for a version that does not maintain order, but
	   allows access based on a multimap.
	   \sa CertificateInfoPair for the elements in the list
	*/
	CertificateInfoOrdered subjectInfoOrdered() const;

	/**
	   The constraints that apply to this certificate request

	   \note this only applies to PKCS#10 format certificate requests
	*/
	Constraints constraints() const;

	/**
	   The policies that apply to this certificate request

	   \note this only applies to PKCS#10 format certificate requests
	*/
	QStringList policies() const;

	/**
	   The public key belonging to the issuer
	*/
	PublicKey subjectPublicKey() const;

	/**
	   Test if this Certificate Request is for a Certificate Authority
	   certificate

	   \note this only applies to PKCS#10 format certificate requests
	*/
	bool isCA() const;

	/**
	   The path limit for the certificate in this Certificate Request

	   \note this only applies to PKCS#10 format certificate requests
	*/
	int pathLimit() const;

	/**
	   The challenge associated with this certificate request
	*/
	QString challenge() const;

	/**
	   The algorithm used to make the signature on this certificate
	   request
	*/
	SignatureAlgorithm signatureAlgorithm() const;

	/**
	   Test for equality of two certificate requests

	   \param csr the certificate request to be compared to this certificate request

	   \return true if the two certificate requests are the same
	*/
	bool operator==(const CertificateRequest &csr) const;

	/**
	   Inequality operator

	   \param other the certificate request to be compared to this certificate request
	*/
	inline bool operator!=(const CertificateRequest &other) const
	{
		return !(*this == other);
	}

	/**
	   Export the Certificate Request into a DER format

	   \note this only applies to PKCS#10 format certificate requests
	*/
	QByteArray toDER() const;

	/**
	   Export the Certificate Request into a PEM format

	   \note this only applies to PKCS#10 format certificate requests
	*/
	QString toPEM() const;

	/**
	   Export the Certificate into PEM format in a file

	   \param fileName the name of the file to use

	   \note this only applies to PKCS#10 format certificate requests
	*/
	bool toPEMFile(const QString &fileName) const;

	/**
	   Import the certificate request from DER

	   \param a the array containing the certificate request in DER format
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the CertificateRequest corresponding to the certificate
	   request in the provided array

	   \note this only applies to PKCS#10 format certificate requests
	*/
	static CertificateRequest fromDER(const QByteArray &a, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Import the certificate request from PEM format

	   \param s the string containing the certificate request in PEM
	   format
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the CertificateRequest corresponding to the certificate
	   request in the provided string

	   \note this only applies to PKCS#10 format certificate requests
	*/
	static CertificateRequest fromPEM(const QString &s, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Import the certificate request from a file

	   \param fileName the name (and path, if required) of the file
	   containing the certificate request in PEM format
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the CertificateRequest corresponding to the certificate
	   request in the provided string

	   \note this only applies to PKCS#10 format certificate requests
	*/
	static CertificateRequest fromPEMFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Export the CertificateRequest to a string

	   \return the string corresponding to the certificate request

	   \note this only applies to SPKAC format certificate requests
	*/
	QString toString() const;

	/**
	   Import the CertificateRequest from a string

	   \param s the string containing to the certificate request
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the CertificateRequest corresponding to the certificate
	   request in the provided string

	   \note this only applies to SPKAC format certificate requests
	*/
	static CertificateRequest fromString(const QString &s, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   \internal

	   \param c context (internal)
	*/
	void change(CSRContext *c);

private:
	class Private;
	friend class Private;
	QSharedDataPointer<Private> d;
};

/**
   \class CRLEntry qca_cert.h QtCrypto

   Part of a CRL representing a single certificate

   \ingroup UserAPI
*/
class QCA_EXPORT CRLEntry
{
public:
	/**
	   The reason why the certificate has been revoked
	*/
	enum Reason
	{
		Unspecified,        ///< reason is unknown
		KeyCompromise,      ///< private key has been compromised
		CACompromise,       ///< certificate authority has been compromised
		AffiliationChanged,
		Superseded,         ///< certificate has been superseded
		CessationOfOperation,
		CertificateHold,    ///< certificate is on hold
		RemoveFromCRL,      ///< certificate was previously in a CRL, but is now valid
		PrivilegeWithdrawn,
		AACompromise        ///< attribute authority has been compromised
	};

	/**
	   create an empty CRL entry
	*/
	CRLEntry();

	/**
	   create a CRL entry

	   \param c the certificate to revoke
	   \param r the reason that the certificate is being revoked
	*/
	explicit CRLEntry(const Certificate &c, Reason r = Unspecified);

	/**
	   create a CRL entry

	   \param serial the serial number of the Certificate being revoked
	   \param time the time the Certificate was revoked (or will be
	   revoked)
	   \param r the reason that the certificate is being revoked
	*/
	CRLEntry(const BigInteger serial, const QDateTime &time, Reason r = Unspecified);

	/**
	   Copy constructor

	   \param from the CRLEntry to copy from
	*/
	CRLEntry(const CRLEntry &from);

	~CRLEntry();

	/**
	   Standard assignment operator

	   \param from the CRLEntry to copy from
	*/
	CRLEntry & operator=(const CRLEntry &from);

	/**
	   The serial number of the certificate that is the subject of this CRL entry
	*/
	BigInteger serialNumber() const;

	/**
	   The time this CRL entry was created
	*/
	QDateTime time() const;

	/**
	   Test if this CRL entry is empty
	*/
	bool isNull() const;

	/**
	   The reason that this CRL entry was created

	   Alternatively, you might like to think of this as the reason that
	   the subject certificate has been revoked
	*/
	Reason reason() const;

	/**
	   Test if one CRL entry is "less than" another

	   CRL entries are compared based on their serial number

	   \param a the CRL entry to be compared to this CRL entry.
	*/
	bool operator<(const CRLEntry &a) const;

	/**
	   Test for equality of two CRL Entries

	   \param a the CRL entry to be compared to this CRL entry.

	   \return true if the two certificates are the same
	*/
	bool operator==(const CRLEntry &a) const;

	/**
	   Inequality operator

	   \param other the CRL entry to be compared to this CRL entry.
	*/
	inline bool operator!=(const CRLEntry &other) const
	{
		return !(*this == other);
	}

private:
	BigInteger _serial;
	QDateTime _time;
	Reason _reason;

	class Private;
	Private *d;
};

/**
   \class CRL qca_cert.h QtCrypto

   %Certificate Revocation List

   A %CRL is a list of certificates that are special in some
   way. The normal reason for including a certificate on a %CRL
   is that the certificate should no longer be used. For
   example, if a key is compromised, then the associated
   certificate may no longer provides appropriate
   security. There are other reasons why a certificate may be
   placed on a %CRL, as shown in the CRLEntry::Reason
   enumeration.

   \sa CertificateCollection for a way to handle Certificates
   and CRLs as a single entity.
   \sa CRLEntry for the %CRL segment representing a single Certificate.

   \ingroup UserAPI
*/
class QCA_EXPORT CRL : public Algorithm
{
public:
	CRL();

	/**
	   Standard copy constructor

	   \param from the revocation list to copy from
	*/
	CRL(const CRL &from);

	~CRL();

	/**
	   Standard assignment operator

	   \param from the revocation list to assign from
	*/
	CRL & operator=(const CRL &from);

	/**
	   Test if the CRL is empty

	   \return true if the CRL is entry, otherwise return false
	*/
	bool isNull() const;

	/**
	   Information on the issuer of the CRL as a QMultiMap.

	   \sa issuerInfoOrdered for a version that maintains the order
	   of information fields as per the underlying CRL.
	*/
	CertificateInfo issuerInfo() const;

	/**
	   Information on the issuer of the CRL as an ordered list
	   (QList of CertificateInfoPair).

	   \sa issuerInfo for a version that allows lookup based on
	   a multimap.
	   \sa CertificateInfoPair for the elements in the list
	*/
	CertificateInfoOrdered issuerInfoOrdered() const;

	/**
	   The CRL serial number. Note that serial numbers are a
	   CRL extension, and not all certificates have one.

	   \return the CRL serial number, or -1 if there is no serial number
	*/
	int number() const;

	/**
	   the time that this CRL became (or becomes) valid
	*/
	QDateTime thisUpdate() const;

	/**
	   the time that this CRL will be obsoleted 

	   you should obtain an updated CRL at this time
	*/
	QDateTime nextUpdate() const;

	/**
	    a list of the revoked certificates in this CRL
	*/
	QList<CRLEntry> revoked() const;

	/**
	   The signature algorithm used for the signature on this CRL
	*/
	SignatureAlgorithm signatureAlgorithm() const;

	/**
	   The key identification of the CRL issuer
	*/
	QByteArray issuerKeyId() const;

	/**
	   Test for equality of two %Certificate Revocation Lists

	   \param a the CRL to be compared to this CRL 

	   \return true if the two CRLs are the same
	*/
	bool operator==(const CRL &a) const;

	/**
	   Inequality operator

	   \param other the CRL to be compared to this CRL 
	*/
	inline bool operator!=(const CRL &other) const
	{
		return !(*this == other);
	}

	/**
	   Export the %Certificate Revocation List (CRL) in DER format

	   \return an array containing the CRL in DER format
	*/
	QByteArray toDER() const;

	/**
	   Export the %Certificate Revocation List (CRL) in PEM format

	   \return a string containing the CRL in PEM format
	*/
	QString toPEM() const;

	/**
	   Export the %Certificate Revocation List (CRL) into PEM format in a
	   file

	   \param fileName the name of the file to use
	*/
	bool toPEMFile(const QString &fileName) const;

	/**
	   Import a DER encoded %Certificate Revocation List (CRL)

	   \param a the array containing the CRL in DER format
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the CRL corresponding to the contents of the array
	*/
	static CRL fromDER(const QByteArray &a, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Import a PEM encoded %Certificate Revocation List (CRL)

	   \param s the string containing the CRL in PEM format
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the CRL corresponding to the contents of the string
	*/
	static CRL fromPEM(const QString &s, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Import a PEM encoded %Certificate Revocation List (CRL) from a file

	   \param fileName the name (and path, if required) of the file
	   containing the certificate in PEM format
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the CRL in the file
	*/
	static CRL fromPEMFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   \internal

	   \param c context (internal)
	*/
	void change(CRLContext *c);

private:
	class Private;
	friend class Private;
	QSharedDataPointer<Private> d;
};

/**
   \class CertificateCollection qca_cert.h QtCrypto

   Bundle of Certificates and CRLs

   CertificateCollection provides a bundle of Certificates and Certificate
   Revocation Lists (CRLs), not necessarily related.

   \sa QCA::CertificateChain for a representation of a chain of Certificates
   related by signatures.

   \ingroup UserAPI
*/
class QCA_EXPORT CertificateCollection
{
public:
	/**
	   Create an empty Certificate / CRL collection
	*/
	CertificateCollection();

	/**
	   Standard copy constructor

	   \param from the CertificateCollection to copy from
	*/
	CertificateCollection(const CertificateCollection &from);

	~CertificateCollection();

	/**
	   Standard assignment operator

	   \param from the CertificateCollection to copy from
	*/
	CertificateCollection & operator=(const CertificateCollection &from);

	/**
	   Append a Certificate to this collection

	   \param cert the Certificate to add to this CertificateCollection
	*/
	void addCertificate(const Certificate &cert);

	/**
	   Append a CRL to this collection

	   \param crl the certificate revokation list to add to this
	   CertificateCollection
	*/
	void addCRL(const CRL &crl);

	/**
	   The Certificates in this collection
	*/
	QList<Certificate> certificates() const;

	/**
	   The CRLs in this collection
	*/
	QList<CRL> crls() const;

	/**
	   Add another CertificateCollection to this collection

	   \param other the CertificateCollection to add to this collection
	*/
	void append(const CertificateCollection &other);

	/**
	   Add another CertificateCollection to this collection

	   \param other the CertificateCollection to add to this collection
	*/
	CertificateCollection operator+(const CertificateCollection &other) const;

	/**
	   Add another CertificateCollection to this collection

	   \param other the CertificateCollection to add to this collection
	*/
	CertificateCollection & operator+=(const CertificateCollection &other);

	/**
	   test if the CertificateCollection can be imported and exported to
	   PKCS#7 format

	   \param provider the provider to use, if a specific provider is
	   required

	   \return true if the CertificateCollection can be imported and
	   exported to PKCS#7 format
	*/
	static bool canUsePKCS7(const QString &provider = QString());

	/**
	   export the CertificateCollection to a plain text file

	   \param fileName the name (and path, if required) to write the
	   contents of the CertificateCollection to

	   \return true if the export succeeded, otherwise false
	*/
	bool toFlatTextFile(const QString &fileName);

	/**
	   export the CertificateCollection to a PKCS#7 file

	   \param fileName the name (and path, if required) to write the
	   contents of the CertificateCollection to
	   \param provider the provider to use, if a specific provider is
	   required

	   \return true if the export succeeded, otherwise false
	*/
	bool toPKCS7File(const QString &fileName, const QString &provider = QString());

	/**
	   import a CertificateCollection from a text file

	   \param fileName the name (and path, if required) to read the
	   certificate collection from
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the CertificateCollection corresponding to the contents of
	   the file specified in fileName
	*/
	static CertificateCollection fromFlatTextFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   import a CertificateCollection from a PKCS#7 file

	   \param fileName the name (and path, if required) to read the
	   certificate collection from
	   \param result a pointer to a ConvertResult, which if not-null will
	   be set to the conversion status
	   \param provider the provider to use, if a specific provider is
	   required

	   \return the CertificateCollection corresponding to the contents of
	   the file specified in fileName
	*/
	static CertificateCollection fromPKCS7File(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

private:
	class Private;
	QSharedDataPointer<Private> d;
};

/**
   \class CertificateAuthority qca_cert.h QtCrypto

   A %Certificate Authority is used to generate Certificates and
   %Certificate Revocation Lists (CRLs).

   \ingroup UserAPI
*/
class QCA_EXPORT CertificateAuthority : public Algorithm
{
public:
	/**
	   Create a new %Certificate Authority

	   \param cert the CA certificate
	   \param key the private key associated with the CA certificate
	   \param provider the provider to use, if a specific provider is
	   required
	*/
	CertificateAuthority(const Certificate &cert, const PrivateKey &key, const QString &provider);

	/**
	   Copy constructor

	   \param from the CertificateAuthority to copy from
	*/
	CertificateAuthority(const CertificateAuthority &from);

	~CertificateAuthority();

	/**
	   Standard assignment operator

	   \param from the CertificateAuthority to copy from
	*/
	CertificateAuthority & operator=(const CertificateAuthority &from);

	/**
	   The Certificate belonging to the %CertificateAuthority

	   This is the Certificate that was passed as an argument to the
	   constructor
	*/
	Certificate certificate() const;

	/**
	   Create a new Certificate by signing the provider CertificateRequest

	   \param req the CertificateRequest to sign
	   \param notValidAfter the last date that the Certificate will be
	   valid
	*/
	Certificate signRequest(const CertificateRequest &req, const QDateTime &notValidAfter) const;

	/**
	   Create a new Certificate

	   \param key the Public Key to use to create the Certificate
	   \param opts the options to use for the new Certificate
	*/
	Certificate createCertificate(const PublicKey &key, const CertificateOptions &opts) const;

	/**
	   Create a new Certificate Revocation List (CRL)

	   \param nextUpdate the date that the CRL will be updated

	   \return an empty CRL
	*/
	CRL createCRL(const QDateTime &nextUpdate) const;

	/**
	   Update the CRL to include new entries

	   \param crl the CRL to update
	   \param entries the entries to add to the CRL
	   \param nextUpdate the date that this CRL will be updated

	   \return the update CRL
	*/
	CRL updateCRL(const CRL &crl, const QList<CRLEntry> &entries, const QDateTime &nextUpdate) const;

private:
	class Private;
	Private *d;
};

/**
   \class KeyBundle qca_cert.h QtCrypto

   Certificate chain and private key pair

   KeyBundle is essentially a convience class that holds a
   certificate chain and an associated private key. This class
   has a number of methods that make it particularly suitable
   for accessing a PKCS12 (.p12) format file, however it can
   be used as just a container for a Certificate, its
   associated PrivateKey and optionally additional
   X.509 Certificate that form a chain.

   For more information on PKCS12 "Personal Information
   Exchange Syntax Standard", see <a
   href="ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1.pdf">ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-12/pkcs-12v1.pdf</a>. 

   \ingroup UserAPI
*/
class QCA_EXPORT KeyBundle
{
public:
	/**
	   Create an empty KeyBundle
	*/
	KeyBundle();

	/**
	   Create a KeyBundle from a PKCS12 (.p12) encoded
	   file

	   This constructor requires appropriate plugin (provider)
	   support. You must check for the "pkcs12" feature
	   before using this constructor.

	   \param fileName the name of the file to read from
	   \param passphrase the passphrase that is applicable to the file

	   \sa fromFile for a more flexible version of the
	   same capability.

	   \note This synchronous operation may require event handling, and so
	   it must not be called from the same thread as an EventHandler.
	*/
	explicit KeyBundle(const QString &fileName, const SecureArray &passphrase = SecureArray());

	/**
	   Standard copy constructor

	   \param from the KeyBundle to use as source
	*/
	KeyBundle(const KeyBundle &from);

	~KeyBundle();

	/**
	   Standard assignment operator

	   \param from the KeyBundle to use as source
	*/
	KeyBundle & operator=(const KeyBundle &from);

	/**
	   Test if this key is empty (null)
	*/
	bool isNull() const;

	/**
	   The name associated with this key.

	   This is also known as the "friendly name", and if
	   present, is typically suitable to be displayed to
	   the user.

	   \sa setName
	*/
	QString name() const;

	/**
	   The public certificate part of this bundle

	   \sa setCertificateChainAndKey
	*/
	CertificateChain certificateChain() const;

	/**
	   The private key part of this bundle

	   \sa setCertificateChainAndKey
	*/
	PrivateKey privateKey() const;

	/**
	   Specify the name of this bundle

	   \param s the name to use
	*/
	void setName(const QString &s);

	/**
	   Set the public certificate and private key

	   \param c the CertificateChain containing the public part of the
	   Bundle
	   \param key the private key part of the Bundle

	   \sa privateKey, certificateChain for getters
	*/
	void setCertificateChainAndKey(const CertificateChain &c, const PrivateKey &key);

	/**
	   Export the key bundle to an array in PKCS12 format.

	   This method requires appropriate plugin (provider)
	   support - you must check for the "pkcs12" feature,
	   as shown below.

	   \code
if( QCA::isSupported("pkcs12") )
{
	// can use I/O
	byteArray = bundle.toArray( "pass phrase" );
}
else
{
	// not possible to use I/O
}
	   \endcode

	   \param passphrase the passphrase to use to protect the bundle
	   \param provider the provider to use, if a specific provider is
	   required
	*/
	QByteArray toArray(const SecureArray &passphrase, const QString &provider = QString()) const;

	/**
	   Export the key bundle to a file in PKCS12 (.p12) format

	   This method requires appropriate plugin (provider)
	   support - you must check for the "pkcs12" feature,
	   as shown below.

	   \code
if( QCA::isSupported("pkcs12") )
{
	// can use I/O
	bool result = bundle.toFile( filename, "pass phrase" );
}
else
{
	// not possible to use I/O
}
	   \endcode

	   \param fileName the name of the file to save to
	   \param passphrase the passphrase to use to protect the bundle
	   \param provider the provider to use, if a specific provider is
	   required
	*/
	bool toFile(const QString &fileName, const SecureArray &passphrase, const QString &provider = QString()) const;

	/**
	   Import the key bundle from an array in PKCS12 format

	   This method requires appropriate plugin (provider)
	   support - you must check for the "pkcs12" feature,
	   as shown below.

	   \code
if( QCA::isSupported("pkcs12") )
{
	// can use I/O
	bundle = QCA::KeyBundle::fromArray( array, "pass phrase" );
}
else
{
	// not possible to use I/O
}
	   \endcode

	   \param a the array to import from
	   \param passphrase the passphrase for the encoded bundle
	   \param result pointer to the result of the import process
	   \param provider the provider to use, if a specific provider is
	   required

	   \sa QCA::KeyLoader for an asynchronous loader approach.

	   \note This synchronous operation may require event handling, and so
	   it must not be called from the same thread as an EventHandler.
	*/
	static KeyBundle fromArray(const QByteArray &a, const SecureArray &passphrase = SecureArray(), ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Import the key bundle from a file in PKCS12 (.p12) format

	   This method requires appropriate plugin (provider)
	   support - you must check for the "pkcs12" feature,
	   as shown below.

	   \code
if( QCA::isSupported("pkcs12") )
{
	// can use I/O
	bundle = QCA::KeyBundle::fromFile( filename, "pass phrase" );
}
else
{
	// not possible to use I/O
}
	   \endcode

	   \param fileName the name of the file to read from
	   \param passphrase the passphrase for the encoded bundle
	   \param result pointer to the result of the import process
	   \param provider the provider to use, if a specific provider is
	   required

	   \sa QCA::KeyLoader for an asynchronous loader approach.

	   \note This synchronous operation may require event handling, and so
	   it must not be called from the same thread as an EventHandler.
	*/
	static KeyBundle fromFile(const QString &fileName, const SecureArray &passphrase = SecureArray(), ConvertResult *result = 0, const QString &provider = QString());

private:
	class Private;
	QSharedDataPointer<Private> d;
};

/**
   \class PGPKey qca_cert.h QtCrypto

   Pretty Good Privacy key 

   This holds either a reference to an item in a real PGP keyring,
   or a standalone item created using the from*() functions.

   Note that with the latter method, the key is of no use besides
   being informational.  The key must be in a keyring
   (that is, inKeyring() == true) to actually do crypto with it.

   \ingroup UserAPI
*/
class QCA_EXPORT PGPKey : public Algorithm
{
public:
	/**
	   Create an empty PGP key
	*/
	PGPKey();

	/**
	   Create a PGP key from an encoded file

	   \param fileName the name (and path, if required) of the file
	   that the PGP key is to be loaded from.

	   \sa fromFile for a version that allows better error checking / validation 
	   \sa toFile for a method to write out the key.
	*/
	PGPKey(const QString &fileName);

	/**
	   Standard copy constructor

	   \param from the PGPKey to use as the source
	*/
	PGPKey(const PGPKey &from);

	~PGPKey();

	/**
	   Standard assignment operator

	   \param from the PGPKey to use as the source
	*/
	PGPKey & operator=(const PGPKey &from);

	/**
	   Test if the PGP key is empty (null)

	   \return true if the PGP key is null
	*/
	bool isNull() const;

	/**
	   The Key identification for the PGP key
	*/
	QString keyId() const;

	/**
	   The primary user identification for the key
	*/
	QString primaryUserId() const;

	/**
	   The list of all user identifications associated with the key
	*/
	QStringList userIds() const;

	/**
	   Test if the PGP key is the secret key

	   \return true if the PGP key is the secret key
	*/
	bool isSecret() const;

	/**
	   The creation date for the key
	*/
	QDateTime creationDate() const;

	/**
	   The expiration date for the key
	*/
	QDateTime expirationDate() const;

	/**
	   The key fingerpint

	   This will return the PGP fingerprint as a string. It comprises 40
	   hex digits, without spaces.
	*/
	QString fingerprint() const;

	/**
	   Test if this key is in a keyring

	   \return true if the key is in a keyring

	   \note keys that are not in a keyring cannot be used for encryption,
	   decryption, signing or verification
	*/
	bool inKeyring() const;

	/**
	   Test if the key is trusted

	   \return true if the key is trusted
	*/
	bool isTrusted() const;

	/**
	   Export the key to an array.

	   This will export the key in a binary format (that is, not in an 
	   "ascii armoured" form).

	   \sa fromArray for a static import method.
	   \sa toString for an "ascii armoured" export method.
	*/
	QByteArray toArray() const;

	/**
	   Export the key to a string

	   This will export the key in an "ascii armoured" form.

	   \sa fromString for a static import method.
	   \sa toArray for a binary format export method.
	*/
	QString toString() const;

	/**
	   Export the key to a file

	   \param fileName the name of the file to save the key to
	*/
	bool toFile(const QString &fileName) const;

	/**
	   Import the key from an array

	   \param a the array to import from
	   \param result if not null, this will be set to the result of the
	   import process
	   \param provider the provider to use, if a particular provider is
	   required
	*/
	static PGPKey fromArray(const QByteArray &a, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Import the key from a string

	   \param s the string to import from
	   \param result if not null, this will be set to the result of the
	   import process
	   \param provider the provider to use, if a particular provider is
	   required
	*/
	static PGPKey fromString(const QString &s, ConvertResult *result = 0, const QString &provider = QString());

	/**
	   Import the key from a file

	   \param fileName string containing the name of the file to import
	   from
	   \param result if not null, this will be set to the result of the
	   import process
	   \param provider the provider to use, if a particular provider is
	   required
	*/
	static PGPKey fromFile(const QString &fileName, ConvertResult *result = 0, const QString &provider = QString());

private:
	class Private;
	Private *d;
};

/**
   \class KeyLoader qca_cert.h QtCrypto

   Asynchronous private key loader

   GUI applications generally must use KeyLoader to load private keys.  This
   is because the synchronous private key loading functions, for example
   QCA::PrivateKey::fromPEMFile(), cannot be used within the same thread as an
   EventHandler, and most GUI applications will use EventHandler from the main
   thread.  KeyLoader does not have this problem.  It can be used from any
   thread, including the same thread as EventHandler.

   The KeyLoader class allows you to asynchronously load stand-alone private
   keys (QCA::PrivateKey) or private keys with a certificate (QCA::KeyBundle)
   with a signal that advises of completion.

   To use this class to load a PrivateKey, you create a KeyLoader object then
   use one of the loadPrivateKeyFrom...() functions, depending on the format
   for your key. These functions return immediately.  When you get the
   finished() signal, you can check that the loading operation succeeded
   (using convertResult()) and then obtain the PrivateKey using the
   privateKey() function.

   The same process applies for loading a KeyBundle, except that you use
   either loadKeyBundleFromFile() or loadKeyBundleFromArray() instead of the
   loadPrivateKeyFrom...() function, and use keyBundle() instead of
   privateKey().

   The loader may need a passphrase to complete the loading of the key or key
   bundle.  You should use the QCA::EventHandler class to ensure that you deal
   with this correctly.

   \note %QCA also provides synchronous private key loading using
   QCA::PrivateKey::fromPEMFile(), QCA::PrivateKey::fromPEM() and
   QCA::PrivateKey::fromDER(). %QCA provides synchronous key bundle loading
   using QCA::KeyBundle::fromArray() and QCA::KeyBundle::fromFile().

   \ingroup UserAPI
*/
class QCA_EXPORT KeyLoader : public QObject
{
	Q_OBJECT
public:
	/**
	   Create a KeyLoader object.

	   \param parent the parent object for this object
	*/
	KeyLoader(QObject *parent = 0);
	~KeyLoader();

	/**
	   Initiate an asynchronous loading of a PrivateKey from a PEM format
	   file.

	   This function will return immediately.

	   \param fileName the name of the file (and path, if necessary) to
	   load the key from
	*/
	void loadPrivateKeyFromPEMFile(const QString &fileName);

	/**
	   Initiate an asynchronous loading of a PrivateKey from a PEM format
	   string.

	   This function will return immediately.

	   \param s the string containing the PEM formatted key
	*/
	void loadPrivateKeyFromPEM(const QString &s);

	/**
	   Initiate an asynchronous loading of a PrivateKey from a DER format
	   array.

	   This function will return immediately.

	   \param a the array containing the DER formatted key
	*/
	void loadPrivateKeyFromDER(const SecureArray &a);

	/**
	   Initiate an asynchronous loading of a KeyBundle from a file

	   This function will return immediately.

	   \param fileName the name of the file (and path, if necessary) to
	   load the key bundle from
	*/
	void loadKeyBundleFromFile(const QString &fileName);

	/**
	   Initiate an asynchronous loading of a KeyBundle from an array

	   This function will return immediately.

	   \param a the array containing the key bundle
	*/
	void loadKeyBundleFromArray(const QByteArray &a);

	/**
	   The result of the loading process.

	   This is not valid until the finished() signal has been emitted.
	*/
	ConvertResult convertResult() const;

	/**
	   The private key that has been loaded.

	   This is only valid if loadPrivateKeyFromPEMFile(),
	   loadPrivateKeyFromPEM() or loadPrivateKeyFromDER() has been used,
	   the load has completed (that is, finished() has been emitted), and
	   the conversion succeeded (that is, convertResult() returned
	   ConvertGood).
	*/
	PrivateKey privateKey() const;

	/**
	   The key bundle that has been loaded.

	   This is only valid if loadKeyBundleFromFile() or
	   loadKeyBundleFromArray() has been used, the load has completed
	   (that is, finished() has been emitted), and the conversion
	   succeeded (that is, convertResult() returned ConvertGood).
	*/
	KeyBundle keyBundle() const;

Q_SIGNALS:
	/**
	   Signal that is emitted when the load process has completed.

	   \note The load process may not have completed successfully - check
	   the result of convertResult() to confirm this before using the
	   privateKey() or keyBundle() results.
	*/
	void finished();

private:
	Q_DISABLE_COPY(KeyLoader)

	class Private;
	friend class Private;
	Private *d;
};

}

#endif
