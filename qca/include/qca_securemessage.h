/*
 * qca_securemessage.h - Qt Cryptographic Architecture
 * Copyright (C) 2003-2007  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004,2005  Brad Hards <bradh@frogmouth.net>
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
   \file qca_securemessage.h

   Header file for secure message (PGP, CMS) classes

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_SECUREMESSAGE_H
#define QCA_SECUREMESSAGE_H

#include <QObject>
#include "qca_core.h"
#include "qca_publickey.h"
#include "qca_cert.h"

class QDateTime;

namespace QCA {

class SecureMessageSystem;

/**
   \class SecureMessageKey qca_securemessage.h QtCrypto

   Key for SecureMessage system

   \ingroup UserAPI
*/
class QCA_EXPORT SecureMessageKey
{
public:
	/**
	   The key type
	*/
	enum Type
	{
		None, ///< no key
		PGP,  ///< Pretty Good Privacy key
		X509  ///< X.509 CMS key
	};

	/**
	   Construct an empty key
	*/
	SecureMessageKey();

	/**
	   Standard copy constructor

	   \param from the source key
	*/
	SecureMessageKey(const SecureMessageKey &from);

	~SecureMessageKey();

	/**
	   Standard assignment operator

	   \param from the source key
	*/
	SecureMessageKey & operator=(const SecureMessageKey &from);

	/**
	   Returns true for null object
	*/
	bool isNull() const;

	/**
	   The key type
	*/
	Type type() const;

	/**
	   Public key part of a PGP key
	*/
	PGPKey pgpPublicKey() const;

	/**
	   Private key part of a PGP key
	*/
	PGPKey pgpSecretKey() const;

	/**
	   Set the public key part of a PGP key

	   \param pub the PGP public key
	*/
	void setPGPPublicKey(const PGPKey &pub);

	/**
	   Set the private key part of a PGP key

	   \param sec the PGP secretkey
	*/
	void setPGPSecretKey(const PGPKey &sec);

	/**
	   The X.509 certificate chain (public part) for this key
	*/
	CertificateChain x509CertificateChain() const;

	/**
	   The X.509 private key part of this key
	*/
	PrivateKey x509PrivateKey() const;

	/**
	   Set the public key part of this X.509 key.

	   \param c the Certificate chain containing the public keys
	*/
	void setX509CertificateChain(const CertificateChain &c);

	/**
	   Set the private key part of this X.509 key.

	   \param k the private key
	*/
	void setX509PrivateKey(const PrivateKey &k);

	/**
	   Set the public and private part of this X.509 key with KeyBundle.

	   \param kb the public and private key bundle
	*/
	void setX509KeyBundle(const KeyBundle &kb);

	/**
	   Test if this key contains a private key part
	*/
	bool havePrivate() const;

	/**
	   The name associated with this key

	   For a PGP key, this is the primary user ID

	   For an X.509 key, this is the Common Name
	*/
	QString name() const;

private:
	class Private;
	QSharedDataPointer<Private> d;
};

/**
   A list of message keys
*/
typedef QList<SecureMessageKey> SecureMessageKeyList;

/**
   \class SecureMessageSignature qca_securemessage.h QtCrypto

   SecureMessage signature

   \ingroup UserAPI
*/
class QCA_EXPORT SecureMessageSignature
{
public:
	/**
	   The result of identity verification
	*/
	enum IdentityResult
	{
		Valid,            ///< indentity is verified, matches signature
		InvalidSignature, ///< valid key provided, but signature failed
		InvalidKey,       ///< invalid key provided
		NoKey             ///< identity unknown
	};

	/**
	   Create an empty signature check object.

	   User applications don't normally need to create signature checks. You normally
	   get the object back as a result of a SecureMessage operation.
	*/
	SecureMessageSignature();

	/**
	   Create a signature check object

	   User applications don't normally need to create signature checks. You normally
	   get the object back as a result of a SecureMessage operation.

	   \param r the result of the check
	   \param v the Validity of the key validation check
	   \param key the key associated with the signature
	   \param ts the timestamp associated with the signature
	*/
	SecureMessageSignature(IdentityResult r, Validity v, const SecureMessageKey &key, const QDateTime &ts);

	/**
	   Standard copy constructor

	   \param from the source signature object
	*/
	SecureMessageSignature(const SecureMessageSignature &from);

	~SecureMessageSignature();

	/**
	   Standard assignment operator

	   \param from the source signature object
	*/
	SecureMessageSignature & operator=(const SecureMessageSignature &from);

	/**
	   get the results of the identity check on this signature
	*/
	IdentityResult identityResult() const;

	/**
	   get the results of the key validation check on this signature
	*/
	Validity keyValidity() const;

	/**
	   get the key associated with this signature
	*/
	SecureMessageKey key() const;

	/**
	   get the timestamp associated with this signature
	*/
	QDateTime timestamp() const;

private:
	class Private;
	QSharedDataPointer<Private> d;
};

/**
   A list of signatures
*/
typedef QList<SecureMessageSignature> SecureMessageSignatureList;


/**
   \class SecureMessage qca_securemessage.h QtCrypto

   Class representing a secure message

   SecureMessage presents a unified interface for working with both
   OpenPGP and CMS (S/MIME) messages.  Prepare the object by calling
   setFormat(), setRecipient(), and setSigner() as necessary, and then
   begin the operation by calling an appropriate 'start' function, such
   as startSign().

   Here is an example of how to perform a Clearsign operation using PGP:

   \code
// first make the SecureMessageKey
PGPKey myPGPKey = getSecretKeyFromSomewhere();
SecureMessageKey key;
key.setPGPSecretKey(myPGPKey);

// our data to sign
QByteArray plain = "Hello, world";

// let's do it
OpenPGP pgp;
SecureMessage msg(&pgp);
msg.setSigner(key);
msg.startSign(SecureMessage::Clearsign);
msg.update(plain);
msg.end();
msg.waitForFinished(-1);

if(msg.success())
{
	QByteArray result = msg.read();
	// result now contains the clearsign text data
}
else
{
	// error
	...
}
   \endcode

   Performing a CMS sign operation is similar.  Simply set up the
   SecureMessageKey with a Certificate instead of a PGPKey, and operate on a
   CMS object instead of an OpenPGP object.

   \sa SecureMessageKey
   \sa SecureMessageSignature
   \sa OpenPGP
   \sa CMS

   \ingroup UserAPI
*/
class QCA_EXPORT SecureMessage : public QObject, public Algorithm
{
	Q_OBJECT
public:
	/**
	   The type of secure message
	*/
	enum Type
	{
		OpenPGP, ///< a Pretty Good Privacy message
		CMS      ///< a Cryptographic Message Syntax message
	};

	/**
	   The type of message signature
	*/
	enum SignMode
	{
		Message,    ///< the message includes the signature
		Clearsign,  ///< the message is clear signed
		Detached    ///< the signature is detached
	};

	/**
	   Formats for secure messages
	*/
	enum Format
	{
		Binary, ///< DER/binary
		Ascii   ///< PEM/ascii-armored
	};

	/**
	   Errors for secure messages
	*/
	enum Error
	{
		ErrorPassphrase,       ///< passphrase was either wrong or not provided
		ErrorFormat,           ///< input format was bad
		ErrorSignerExpired,    ///< signing key is expired
		ErrorSignerInvalid,    ///< signing key is invalid in some way
		ErrorEncryptExpired,   ///< encrypting key is expired
		ErrorEncryptUntrusted, ///< encrypting key is untrusted
		ErrorEncryptInvalid,   ///< encrypting key is invalid in some way
		ErrorNeedCard,         ///< pgp card is missing
		ErrorCertKeyMismatch,  ///< certificate and private key don't match
		ErrorUnknown,          ///< other error
		ErrorSignerRevoked,    ///< signing key is revoked
		ErrorSignatureExpired, ///< signature is expired
		ErrorEncryptRevoked    ///< encrypting key is revoked
	};

	/**
	   Create a new secure message

	   This constructor uses an existing
	   SecureMessageSystem object (for example, an OpenPGP
	   or CMS object) to generate a specific kind of
	   secure message.

	   \param system a pre-existing and configured SecureMessageSystem
	   object
	*/
	SecureMessage(SecureMessageSystem *system);
	~SecureMessage();

	/**
	   The Type of secure message
	*/
	Type type() const;

	/**
	   Test if the message type supports multiple
	   (parallel) signatures.

	   \return true if the secure message support multiple
	   parallel signatures

	   \note PGP cannot do this - it is primarily a CMS
	   feature
	*/
	bool canSignMultiple() const;

	/**
	   True if the SecureMessageSystem can clearsign
	   messages.

	   \note CMS cannot clearsign - this is normally only
	   available for PGP
	*/
	bool canClearsign() const;

	/**
	   True if the SecureMessageSystem can both sign and
	   encrypt (in the same operation).

	   \note CMS cannot do an integrated sign/encrypt -
	   this is normally only available for PGP. You can do
	   separate signing and encrypting operations on the
	   same message with CMS though.
	*/
	bool canSignAndEncrypt() const;

	/**
	   Reset the object state to that of original construction.
	   Now a new operation can be performed immediately.
	*/
	void reset();

	/**
	   Returns true if bundling of the signer certificate chain is
	   enabled
	*/
	bool bundleSignerEnabled() const;

	/**
	   Returns true if inclusion of S/MIME attributes is enabled
	*/
	bool smimeAttributesEnabled() const;

	/**
	   Return the format type set for this message
	*/
	Format format() const;

	/**
	   Return the recipient(s) set for this message with setRecipient() or
	   setRecipients()
	*/
	SecureMessageKeyList recipientKeys() const;

	/**
	   Return the signer(s) set for this message with setSigner() or
	   setSigners()
	*/
	SecureMessageKeyList signerKeys() const;

	/**
	   For CMS only, this will bundle the signer certificate chain
	   into the message.  This allows a message to be verified
	   on its own, without the need to have obtained the signer's
	   certificate in advance.  Email clients using S/MIME often
	   bundle the signer, greatly simplifying key management.

	   This behavior is enabled by default.

	   \param b whether to bundle (if true) or not (false)
	*/
	void setBundleSignerEnabled(bool b);

	/**
	   For CMS only, this will put extra attributes into the
	   message related to S/MIME, such as the preferred
	   type of algorithm to use in replies.  The attributes
	   used are decided by the provider.

	   This behavior is enabled by default.

	   \param b whether to embed extra attribues (if true) or not (false)
	*/
	void setSMIMEAttributesEnabled(bool b);

	/**
	   Set the Format used for messages

	   The default is Binary.

	   \param f whether to use Binary or Ascii
	*/
	void setFormat(Format f);

	/**
	   Set the recipient for an encrypted message

	   \param key the recipient's key

	   \sa setRecipients
	*/
	void setRecipient(const SecureMessageKey &key);

	/**
	   Set the list of recipients for an encrypted message.

	   For a list with one item, this has the same effect as setRecipient.

	   \param keys the recipients' key

	   \sa setRecipient
	*/
	void setRecipients(const SecureMessageKeyList &keys);

	/**
	   Set the signer for a signed message.

	   This is used for both creating signed messages as well as for
	   verifying CMS messages that have no signer bundled.

	   \param key the key associated with the signer

	   \sa setSigners
	*/
	void setSigner(const SecureMessageKey &key);

	/**
	   Set the list of signers for a signed message.

	   This is used for both creating signed messages as well as for
	   verifying CMS messages that have no signer bundled.

	   For a list with one item, this has the same effect as setSigner.

	   \param keys the key associated with the signer

	   \sa setSigner
	*/
	void setSigners(const SecureMessageKeyList &keys);

	/**
	   Start an encryption operation

	   You will normally use this with some code along
	   these lines:
	   \code
encryptingObj.startEncrypt();
encryptingObj.update(message);
// perhaps some more update()s
encryptingObj.end();
	   \endcode

	   Each update() may (or may not) result in some
	   encrypted data, as indicated by the readyRead()
	   signal being emitted. Alternatively, you can wait
	   until the whole message is available (using either
	   waitForFinished(), or use the finished()
	   signal. The encrypted message can then be read
	   using the read() method.
	*/
	void startEncrypt();

	/**
	   Start an decryption operation

	   You will normally use this with some code along
	   these lines:
	   \code
decryptingObj.startEncrypt();
decryptingObj.update(message);
// perhaps some more update()s
decryptingObj.end();
	   \endcode

	   Each update() may (or may not) result in some
	   decrypted data, as indicated by the readyRead()
	   signal being emitted. Alternatively, you can wait
	   until the whole message is available (using either
	   waitForFinished(), or the finished()
	   signal). The decrypted message can then be read
	   using the read() method.

	   \note If decrypted result is also signed (not for
	   CMS), then the signature will be verified during
	   this operation.
	*/
	void startDecrypt();

	/**
	   Start a signing operation

	   You will normally use this with some code along
	   these lines:
	   \code
signingObj.startSign(QCA::SecureMessage::Detached)
signingObj.update(message);
// perhaps some more update()s
signingObj.end();
	   \endcode

	   For Detached signatures, you won't get any results
	   until the whole process is done - you either
	   waitForFinished(), or use the finished() signal, to
	   figure out when you can get the signature (using
	   the signature() method, not using read()). For
	   other formats, you can use the readyRead() signal
	   to determine when there may be part of a signed
	   message to read().

	   \param m the mode that will be used to generate the
	   signature
	*/
	void startSign(SignMode m = Message);

	/**
	   Start a verification operation

	   \param detachedSig the detached signature to
	   verify. Do not pass a signature for other signature
	   types.
	*/
	void startVerify(const QByteArray &detachedSig = QByteArray());

	/**
	   Start a combined signing and encrypting
	   operation. You use this in the same way as
	   startEncrypt().

	   \note This may not be possible (e.g. CMS
	   cannot do this) - see canSignAndEncrypt() for a
	   suitable test.
	*/
	void startSignAndEncrypt();

	/**
	   Process a message (or the next part of a message)
	   in the current operation. You need to have already
	   set up the message (startEncrypt(), startDecrypt(),
	   startSign(), startSignAndEncrypt() and
	   startVerify()) before calling this method.

	   \param in the data to process
	*/
	void update(const QByteArray &in);

	/**
	   Read the available data.

	   \note For detached signatures, you don't get
	   anything back using this method. Use signature() to
	   get the detached signature().
	*/
	QByteArray read();

	/**
	   The number of bytes available to be read.
	*/
	int bytesAvailable() const;

	/**
	   Complete an operation.

	   You need to call this method after you have
	   processed the message (which you pass in as the
	   argument to update().

	   \note the results of the operation are not
	   available as soon as this method returns. You need
	   to wait for the finished() signal, or use
	   waitForFinished().
	*/
	void end();

	/**
	   Block until the operation (encryption, decryption,
	   signing or verifying) completes.

	   \param msecs the number of milliseconds to wait for
	   the operation to complete. Pass -1 to wait
	   indefinitely.

	   \note You should not use this in GUI
	   applications where the blocking behaviour looks
	   like a hung application. Instead, connect the
	   finished() signal to a slot that handles the
	   results.

	   \note This synchronous operation may require event handling, and so
	   it must not be called from the same thread as an EventHandler.
	*/
	bool waitForFinished(int msecs = 30000);

	/**
	   Indicates whether or not the operation was successful
	   or failed.  If this function returns false, then
	   the reason for failure can be obtained with errorCode().

	   \sa errorCode
	   \sa diagnosticText
	*/
	bool success() const;

	/**
	   Returns the failure code.

	   \sa success
	   \sa diagnosticText
	*/
	Error errorCode() const;

	/**
	   The signature for the message. This is only used
	   for Detached signatures. For other message types,
	   you get the message and signature together using
	   read().
	*/
	QByteArray signature() const;

	/**
	   The name of the hash used for the signature process
	*/
	QString hashName() const;

	/**
	   Test if the message was signed.

	   This is true for OpenPGP if the decrypted message
	   was also signed.

	   \return true if the message was signed.
	*/
	bool wasSigned() const;

	/**
	   Verify that the message signature is correct.

	   \return true if the signature is valid for the
	   message, otherwise return false
	*/
	bool verifySuccess() const;

	/**
	   Information on the signer for the message
	*/
	SecureMessageSignature signer() const;

	/**
	   Information on the signers for the message. 

	   This is only meaningful if the message type supports
	   multiple signatures (see canSignMultiple() for a
	   suitable test).
	*/
	SecureMessageSignatureList signers() const;

	/**
	   Returns a log of technical information about the operation,
	   which may be useful for presenting to the user in an
	   advanced error dialog.
	*/
	QString diagnosticText() const;

Q_SIGNALS:
	/**
	   This signal is emitted when there is some data to
	   read. Typically you connect this signal to a slot
	   that does a read() of the available data.

	   \note This signal does not mean that the processing
	   of a message is necessarily complete - see
	   finished().
	*/
	void readyRead();

	/**
	   This signal is emitted when data has been accepted
	   by the message processor.

	   \param bytes the number of bytes written
	*/
	void bytesWritten(int bytes);

	/**
	   This signal is emitted when the message is fully
	   processed.
	*/
	void finished();

private:
	Q_DISABLE_COPY(SecureMessage)

	class Private;
	friend class Private;
	Private *d;
};

/**
   \class SecureMessageSystem qca_securemessage.h QtCrypto

   Abstract superclass for secure messaging systems

   \sa SecureMessage
   \sa SecureMessageKey

   \ingroup UserAPI
*/
class QCA_EXPORT SecureMessageSystem : public QObject, public Algorithm
{
	Q_OBJECT
public:
	~SecureMessageSystem();

protected:
	/**
	   Protected constructor for SecureMessageSystem
	   classes. You are meant to be using a subclass (such
	   as OpenPGP or CMS) - you only need to worry about
	   this class if you are creating a whole new
	   SecureMessageSystem type.

	   \param parent the parent object for this object
	   \param type the name of the Type of
	   SecureMessageSystem to create
	   \param provider the provider to use, if a specific
	   provider is required.
	*/
	SecureMessageSystem(QObject *parent, const QString &type, const QString &provider);

private:
	Q_DISABLE_COPY(SecureMessageSystem)
};

/**
   \class OpenPGP qca_securemessage.h QtCrypto

   Pretty Good Privacy messaging system

   \sa SecureMessage
   \sa SecureMessageKey

   \ingroup UserAPI

*/
class QCA_EXPORT OpenPGP : public SecureMessageSystem
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param parent the parent object for this object
	   \param provider the provider to use, if a specific
	   provider is required
	*/
	explicit OpenPGP(QObject *parent = 0, const QString &provider = QString());
	~OpenPGP();

private:
	Q_DISABLE_COPY(OpenPGP)

	class Private;
	Private *d;
};

/**
   \class CMS qca_securemessage.h QtCrypto

   Cryptographic Message Syntax messaging system

   Cryptographic Message Syntax (%CMS) "is used to digitally
   sign, digest, authenticate, or encrypt arbitrary message
   content.  The %CMS describes an encapsulation syntax for
   data protection.  It supports digital signatures and
   encryption.  The syntax allows multiple encapsulations; one
   encapsulation envelope can be nested inside another.
   Likewise, one party can digitally sign some previously
   encapsulated data.  It also allows arbitrary attributes,
   such as signing time, to be signed along with the message
   content, and provides for other attributes such as
   countersignatures to be associated with a signature." (from
   <a href="http://www.ietf.org/rfc/rfc3852.txt">RFC3852</a>
   "Cryptographic Message Syntax")

   \sa SecureMessage
   \sa SecureMessageKey

   \ingroup UserAPI

*/
class QCA_EXPORT CMS : public SecureMessageSystem
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param parent the parent object for this object
	   \param provider the provider to use, if a specific
	   provider is required
	*/
	explicit CMS(QObject *parent = 0, const QString &provider = QString());
	~CMS();

	/**
	   Return the trusted certificates set for this object
	*/
	CertificateCollection trustedCertificates() const;

	/**
	   Return the untrusted certificates set for this object
	*/
	CertificateCollection untrustedCertificates() const;

	/**
	   Return the private keys set for this object
	*/
	SecureMessageKeyList privateKeys() const;

	/**
	   Set the trusted certificates to use for the
	   messages built using this CMS object.

	   \param trusted the collection of trusted
	   certificates to use
	*/
	void setTrustedCertificates(const CertificateCollection &trusted);

	/**
	   Set the untrusted certificates to use for the
	   messages built using this CMS object.

	   This function is useful when verifying messages that don't
	   contain the certificates (or intermediate signers) within
	   the CMS blob.  In order to verify such messages, you'll
	   have to pass the possible signer certs with this function.

	   \param untrusted the collection of untrusted
	   certificates to use
	*/
	void setUntrustedCertificates(const CertificateCollection &untrusted);

	/**
	   Set the private keys to use for the messages built
	   using this CMS object.

	   Keys are required for decrypting and signing (not
	   for encrypting or verifying).

	   \param keys the collection of keys to use
	*/
	void setPrivateKeys(const SecureMessageKeyList &keys);

private:
	Q_DISABLE_COPY(CMS)

	class Private;
	Private *d;
};

}

#endif
