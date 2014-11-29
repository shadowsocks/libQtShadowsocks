/*
 * qcaprovider.h - QCA Plugin API
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
   \file qcaprovider.h

   Header file for provider implementation classes (plugins)

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCAPROVIDER_H
#define QCAPROVIDER_H

#include "qca_core.h"
#include "qca_basic.h"
#include "qca_publickey.h"
#include "qca_cert.h"
#include "qca_keystore.h"
#include "qca_securelayer.h"
#include "qca_securemessage.h"

#include <limits>

#ifndef DOXYGEN_NO_PROVIDER_API

/**
   \defgroup ProviderAPI QCA provider API

   This group of classes is not normally needed 
   by application writers, but can be used to extend QCA if
   required
*/

/**
   \class QCAPlugin qcaprovider.h QtCrypto

   Provider plugin base class

   QCA loads cryptographic provider plugins with QPluginLoader.  The QObject
   obtained when loading the plugin must implement the QCAPlugin interface.
   This is done by inheriting QCAPlugin, and including
   Q_INTERFACES(QCAPlugin) in your class declaration.

   For example:
\code
class MyPlugin : public QObject, public QCAPlugin
{
	Q_OBJECT
	Q_INTERFACES(QCAPlugin)
public:
	virtual Provider *createProvider() { ... }
};
\endcode

   There is only one function to reimplement, called createProvider().  This
   function should return a newly allocated Provider instance.

   \ingroup ProviderAPI
*/
class QCA_EXPORT QCAPlugin
{
public:
	/**
	   Destructs the object
	*/
	virtual ~QCAPlugin() {}

	/**
	   Returns a newly allocated Provider instance.
	*/
	virtual QCA::Provider *createProvider() = 0;
};

Q_DECLARE_INTERFACE(QCAPlugin, "com.affinix.qca.Plugin/1.0")

namespace QCA {

/**
   \class InfoContext qcaprovider.h QtCrypto

   Extended provider information

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.

   \ingroup ProviderAPI
*/
class QCA_EXPORT InfoContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	InfoContext(Provider *p) : BasicContext(p, QStringLiteral("info") ) {}

	/**
	   The hash algorithms supported by the provider
	*/
	virtual QStringList supportedHashTypes() const;

	/**
	   The cipher algorithms supported by the provider
	*/
	virtual QStringList supportedCipherTypes() const;

	/**
	   The mac algorithms supported by the provider
	*/
	virtual QStringList supportedMACTypes() const;
};

/**
   \class RandomContext qcaprovider.h QtCrypto

   Random provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want Random instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT RandomContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	RandomContext(Provider *p) : BasicContext(p, QStringLiteral("random")) {}

	/**
	   Return an array of random bytes

	   \param size the number of random bytes to return
	*/
	virtual SecureArray nextBytes(int size) = 0;
};

/**
   \class HashContext qcaprovider.h QtCrypto

   Hash provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want Hash instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT HashContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	   \param type the name of the type of hash provided by this context
	*/
	HashContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Reset the object to its initial state
	*/
	virtual void clear() = 0;

	/**
	   Process a chunk of data

	   \param a the input data to process
	*/
	virtual void update(const MemoryRegion &a) = 0;

	/**
	   Return the computed hash
	*/
	virtual MemoryRegion final() = 0;
};

/**
   \class CipherContext qcaprovider.h QtCrypto

   Cipher provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want Cipher instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT CipherContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	   \param type the name of the type of cipher provided by this context

	   \note type includes the name of the cipher (e.g. "aes256"), the operating
	   mode (e.g. "cbc" or "ofb") and the padding type (e.g. "pkcs7") if any.
	*/
	CipherContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Set up the object for encrypt/decrypt

	   \param dir the direction for the cipher (encryption/decryption)
	   \param key the symmetric key to use for the cipher
	   \param iv the initialization vector to use for the cipher (not used in ECB mode)
	*/
	virtual void setup(Direction dir, const SymmetricKey &key, const InitializationVector &iv) = 0;

	/**
	   Returns the KeyLength for this cipher
	*/
	virtual KeyLength keyLength() const = 0;

	/**
	   Returns the block size for this cipher
	*/
	virtual int blockSize() const = 0;

	/**
	   Process a chunk of data.  Returns true if successful.

	   \param in the input data to process
	   \param out pointer to an array that should store the result
	*/
	virtual bool update(const SecureArray &in, SecureArray *out) = 0;

	/**
	   Finish the cipher processing.  Returns true if successful.

	   \param out pointer to an array that should store the result
	*/
	virtual bool final(SecureArray *out) = 0;
};

/**
   \class MACContext qcaprovider.h QtCrypto

   Message authentication code provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want
   MessageAuthenticationCode instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT MACContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor
	   \param p the provider associated with this context
	   \param type the name of the type of MAC algorithm provided by this context
	*/
	MACContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Set up the object for hashing

	   \param key the key to use with the MAC.
	*/
	virtual void setup(const SymmetricKey &key) = 0;

	/**
	   Returns the KeyLength for this MAC algorithm
	*/
	virtual KeyLength keyLength() const = 0;

	/**
	   Process a chunk of data

	   \param in the input data to process
	*/
	virtual void update(const MemoryRegion &in) = 0;

	/**
	   Compute the result after processing all data

	   \param out pointer to an array that should store the result
	*/
	virtual void final(MemoryRegion *out) = 0;

protected:
	/**
	   Returns a KeyLength that supports any length
	*/
	KeyLength anyKeyLength() const
	{
		// this is used instead of a default implementation to make sure that
		// provider authors think about it, at least a bit.
		// See Meyers, Effective C++, Effective C++ (2nd Ed), Item 36
		return KeyLength( 0, INT_MAX, 1 );
	}
};

/**
   \class KDFContext qcaprovider.h QtCrypto

   Key derivation function provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want KeyDerivationFunction
   instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT KDFContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	   \param type the name of the KDF provided by this context (including algorithm)
	*/
	KDFContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Create a key and return it

	   \param secret the secret part (typically password)
	   \param salt the salt / initialization vector
	   \param keyLength the length of the key to be produced
	   \param iterationCount the number of iterations of the derivation algorith,
	*/
	virtual SymmetricKey makeKey(const SecureArray &secret, const InitializationVector &salt, unsigned int keyLength, unsigned int iterationCount) = 0;

	/**
	   Create a key and return it

	   \param secret the secret part (typically password)
	   \param salt the salt / initialization vector
	   \param keyLength the length of the key to be produced
	   \param msecInterval the maximum time to compute the key, in milliseconds
	   \param iterationCount a pointer to store the number of iterations of the derivation algorithm,
	*/
	virtual SymmetricKey makeKey(const SecureArray &secret,
								 const InitializationVector &salt,
								 unsigned int keyLength,
								 int msecInterval,
								 unsigned int *iterationCount) = 0;
};

/**
   \class DLGroupContext qcaprovider.h QtCrypto

   Discrete logarithm provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want DLGroup instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT DLGroupContext : public Provider::Context
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	DLGroupContext(Provider *p) : Provider::Context(p, QStringLiteral("dlgroup")) {}

	/**
	   The DLGroupSets supported by this object
	*/
	virtual QList<DLGroupSet> supportedGroupSets() const = 0;

	/**
	   Returns true if there is a result to obtain
	*/
	virtual bool isNull() const = 0;

	/**
	   Attempt to create P, Q, and G values from the specified group set

	   If \a block is true, then this function blocks until completion.
	   Otherwise, this function returns immediately and finished() is
	   emitted when the operation completes.

	   If an error occurs during generation, then the operation will
	   complete and isNull() will return true.

	   \param set the group set to generate the key from
	   \param block whether to block (true) or not (false)
	*/
	virtual void fetchGroup(DLGroupSet set, bool block) = 0;

	/**
	   Obtain the result of the operation.  Ensure isNull() returns false
	   before calling this function.

	   \param p the P value
	   \param q the Q value
	   \param g the G value
	*/
	virtual void getResult(BigInteger *p, BigInteger *q, BigInteger *g) const = 0;

Q_SIGNALS:
	/**
	   Emitted when the fetchGroup() operation completes in non-blocking
	   mode.
	*/
	void finished();
};

/**
   \class PKeyBase qcaprovider.h QtCrypto

   Public key implementation provider base

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want PKey, PublicKey, or
   PrivateKey instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT PKeyBase : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the Provider associated with this context
	   \param type type of key provided by this context
	*/
	PKeyBase(Provider *p, const QString &type);

	/**
	   Returns true if this object is not valid.  This is the default
	   state, and the object may also become this state if a conversion
	   or generation function fails.
	*/
	virtual bool isNull() const = 0;

	/**
	   Returns the type of public key
	*/
	virtual PKey::Type type() const = 0;

	/**
	   Returns true if this is a private key, otherwise false
	*/
	virtual bool isPrivate() const = 0;

	/**
	   Returns true if the components of this key are accessible and
	   whether it can be serialized into an output format.  Private keys
	   from a smart card device will often not be exportable.
	*/
	virtual bool canExport() const = 0;

	/**
	   If the key is a private key, this function will convert it into a
	   public key (all private key data includes the public data as well,
	   which is why this is possible).  If the key is already a public
	   key, then this function has no effect.
	*/
	virtual void convertToPublic() = 0;

	/**
	   Returns the number of bits in the key
	*/
	virtual int bits() const = 0;

	/**
	   Returns the maximum number of bytes that can be encrypted by this
	   key

	   \param alg the algorithm to be used for encryption
	*/
	virtual int maximumEncryptSize(EncryptionAlgorithm alg) const;

	/**
	   Encrypt data

	   \param in the input data to encrypt
	   \param alg the encryption algorithm to use
	*/
	virtual SecureArray encrypt(const SecureArray &in, EncryptionAlgorithm alg);

	/**
	   Decrypt data

	   \param in the input data to decrypt
	   \param out pointer to an array to store the plaintext result
	   \param alg the encryption algorithm used to generate the input
	   data
	*/
	virtual bool decrypt(const SecureArray &in, SecureArray *out, EncryptionAlgorithm alg);

	/**
	   Begin a signing operation

	   \param alg the signature algorithm to use
	   \param format the signature format to use
	*/
	virtual void startSign(SignatureAlgorithm alg, SignatureFormat format);

	/**
	   Begin a verify operation

	   \param alg the signature algorithm used by the input signature
	   \param format the signature format used by the input signature
	*/
	virtual void startVerify(SignatureAlgorithm alg, SignatureFormat format);

	/**
	   Process the plaintext input data for either signing or verifying,
	   whichever operation is active.

	   \param in the input data to process
	*/
	virtual void update(const MemoryRegion &in);

	/**
	   Complete a signing operation, and return the signature value

	   If there is an error signing, an empty array is returned.
	*/
	virtual QByteArray endSign();

	/**
	   Complete a verify operation, and return true if successful

	   If there is an error verifying, this function returns false.

	   \param sig the signature to verify with the input data
	*/
	virtual bool endVerify(const QByteArray &sig);

	/**
	   Compute a symmetric key based on this private key and some other
	   public key

	   Essentially for Diffie-Hellman only.

	   \param theirs the other side (public key) to be used for key generation.
	*/
	virtual SymmetricKey deriveKey(const PKeyBase &theirs);

Q_SIGNALS:
	/**
	   Emitted when an asynchronous operation completes on this key.
	   Such operations will be documented that they emit this signal.
	*/
	void finished();
};

/**
   \class RSAContext qcaprovider.h QtCrypto

   RSA provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want RSAPublicKey or
   RSAPrivateKey instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT RSAContext : public PKeyBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	RSAContext(Provider *p) : PKeyBase(p, QStringLiteral("rsa")) {}

	/**
	   Generate an RSA private key

	   If \a block is true, then this function blocks until completion.
	   Otherwise, this function returns immediately and finished() is
	   emitted when the operation completes.

	   If an error occurs during generation, then the operation will
	   complete and isNull() will return true.

	   \param bits the length of the key to generate, in bits
	   \param exp the exponent to use for generation
	   \param block whether to use blocking mode
	*/
	virtual void createPrivate(int bits, int exp, bool block) = 0;

	/**
	   Create an RSA private key based on the five components

	   \param n the N parameter
	   \param e the public exponent
	   \param p the P parameter
	   \param q the Q parameter
	   \param d the D parameter
	*/
	virtual void createPrivate(const BigInteger &n, const BigInteger &e, const BigInteger &p, const BigInteger &q, const BigInteger &d) = 0;

	/**
	   Create an RSA public key based on the two public components

	   \param n the N parameter
	   \param e the public exponent
	*/
	virtual void createPublic(const BigInteger &n, const BigInteger &e) = 0;

	/**
	   Returns the public N component of this RSA key
	*/
	virtual BigInteger n() const = 0;

	/**
	   Returns the public E component of this RSA key
	*/
	virtual BigInteger e() const = 0;

	/**
	   Returns the private P component of this RSA key
	*/
	virtual BigInteger p() const = 0;

	/**
	   Returns the private Q component of this RSA key
	*/
	virtual BigInteger q() const = 0;

	/**
	   Returns the private D component of this RSA key
	*/
	virtual BigInteger d() const = 0;
};

/**
   \class DSAContext qcaprovider.h QtCrypto

   DSA provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want DSAPublicKey or
   DSAPrivateKey instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT DSAContext : public PKeyBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	DSAContext(Provider *p) : PKeyBase(p, QStringLiteral("dsa")) {}

	/**
	   Generate a DSA private key

	   If \a block is true, then this function blocks until completion.
	   Otherwise, this function returns immediately and finished() is
	   emitted when the operation completes.

	   If an error occurs during generation, then the operation will
	   complete and isNull() will return true.

	   \param domain the domain values to use for generation
	   \param block whether to use blocking mode
	*/
	virtual void createPrivate(const DLGroup &domain, bool block) = 0;

	/**
	   Create a DSA private key based on its numeric components

	   \param domain the domain values to use for generation
	   \param y the public Y component
	   \param x the private X component
	*/
	virtual void createPrivate(const DLGroup &domain, const BigInteger &y, const BigInteger &x) = 0;

	/**
	   Create a DSA public key based on its numeric components

	   \param domain the domain values to use for generation
	   \param y the public Y component
	*/
	virtual void createPublic(const DLGroup &domain, const BigInteger &y) = 0;

	/**
	   Returns the public domain component of this DSA key
	*/
	virtual DLGroup domain() const = 0;

	/**
	   Returns the public Y component of this DSA key
	*/
	virtual BigInteger y() const = 0;

	/**
	   Returns the private X component of this DSA key
	*/
	virtual BigInteger x() const = 0;
};

/**
   \class DHContext qcaprovider.h QtCrypto

   Diffie-Hellman provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want DHPublicKey or
   DHPrivateKey instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT DHContext : public PKeyBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	DHContext(Provider *p) : PKeyBase(p, QStringLiteral("dh")) {}

	/**
	   Generate a Diffie-Hellman private key

	   If \a block is true, then this function blocks until completion.
	   Otherwise, this function returns immediately and finished() is
	   emitted when the operation completes.

	   If an error occurs during generation, then the operation will
	   complete and isNull() will return true.

	   \param domain the domain values to use for generation
	   \param block whether to use blocking mode
	*/
	virtual void createPrivate(const DLGroup &domain, bool block) = 0;

	/**
	   Create a Diffie-Hellman private key based on its numeric
	   components

	   \param domain the domain values to use for generation
	   \param y the public Y component
	   \param x the private X component
	*/
	virtual void createPrivate(const DLGroup &domain, const BigInteger &y, const BigInteger &x) = 0;

	/**
	   Create a Diffie-Hellman public key based on its numeric
	   components

	   \param domain the domain values to use for generation
	   \param y the public Y component
	*/
	virtual void createPublic(const DLGroup &domain, const BigInteger &y) = 0;

	/**
	   Returns the public domain component of this Diffie-Hellman key
	*/
	virtual DLGroup domain() const = 0;

	/**
	   Returns the public Y component of this Diffie-Hellman key
	*/
	virtual BigInteger y() const = 0;

	/**
	   Returns the private X component of this Diffie-Hellman key
	*/
	virtual BigInteger x() const = 0;
};

/**
   \class PKeyContext qcaprovider.h QtCrypto

   Public key container provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want PKey, PublicKey, or
   PrivateKey instead.

   This object "holds" a public key object.  By default it contains no key
   (key() returns 0), but you can put a key into it with setKey(), or you
   can call an import function such as publicFromDER().

   \ingroup ProviderAPI
*/
class QCA_EXPORT PKeyContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	PKeyContext(Provider *p) : BasicContext(p, QStringLiteral("pkey")) {}

	/**
	   Returns a list of supported public key types
	*/
	virtual QList<PKey::Type> supportedTypes() const = 0;

	/**
	   Returns a list of public key types that can be serialized and
	   deserialized into DER and PEM format
	*/
	virtual QList<PKey::Type> supportedIOTypes() const = 0;

	/**
	   Returns a list of password-based encryption algorithms that are
	   supported for private key serialization and deserialization
	*/
	virtual QList<PBEAlgorithm> supportedPBEAlgorithms() const = 0;

	/**
	   Returns the key held by this object, or 0 if there is no key
	*/
	virtual PKeyBase *key() = 0;

	/**
	   Returns the key held by this object, or 0 if there is no key
	*/
	virtual const PKeyBase *key() const = 0;

	/**
	   Sets the key for this object.  If this object already had a key,
	   then the old one is destructed.  This object takes ownership of
	   the key.

	   \param key the key to be set for this object
	*/
	virtual void setKey(PKeyBase *key) = 0;

	/**
	   Attempt to import a key from another provider.  Returns true if
	   successful, otherwise false.

	   Generally this function is used if the specified key's provider
	   does not support serialization, but your provider does.  The call
	   to this function would then be followed by an export function,
	   such as publicToDER().

	   \param key the key to be imported
	*/
	virtual bool importKey(const PKeyBase *key) = 0;

	/**
	   Convert a public key to DER format, and return the value

	   Returns an empty array on error.
	*/
	virtual QByteArray publicToDER() const;

	/**
	   Convert a public key to PEM format, and return the value

	   Returns an empty string on error.
	*/
	virtual QString publicToPEM() const;

	/**
	   Read DER-formatted input and convert it into a public key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	*/
	virtual ConvertResult publicFromDER(const QByteArray &a);

	/**
	   Read PEM-formatted input and convert it into a public key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	*/
	virtual ConvertResult publicFromPEM(const QString &s);

	/**
	   Convert a private key to DER format, and return the value

	   Returns an empty array on error.

	   \param passphrase the passphrase to encode the result with, or an
	   empty array if no encryption is desired
	   \param pbe the encryption algorithm to use, if applicable
	*/
	virtual SecureArray privateToDER(const SecureArray &passphrase, PBEAlgorithm pbe) const;

	/**
	   Convert a private key to PEM format, and return the value

	   Returns an empty string on error.

	   \param passphrase the passphrase to encode the result with, or an
	   empty array if no encryption is desired
	   \param pbe the encryption algorithm to use, if applicable
	*/
	virtual QString privateToPEM(const SecureArray &passphrase, PBEAlgorithm pbe) const;

	/**
	   Read DER-formatted input and convert it into a private key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	   \param passphrase the passphrase needed to decrypt, if applicable
	*/
	virtual ConvertResult privateFromDER(const SecureArray &a, const SecureArray &passphrase);

	/**
	   Read PEM-formatted input and convert it into a private key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	   \param passphrase the passphrase needed to decrypt, if applicable
	*/
	virtual ConvertResult privateFromPEM(const QString &s, const SecureArray &passphrase);
};

/**
   \class CertBase qcaprovider.h QtCrypto

   X.509 certificate and certificate request provider base

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want Certificate,
   CertificateRequest, or CRL instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT CertBase : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	   \param type the type of certificate-like object provided by this context
	*/
	CertBase(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Convert this object to DER format, and return the value

	   Returns an empty array on error.
	*/
	virtual QByteArray toDER() const = 0;

	/**
	   Convert this object to PEM format, and return the value

	   Returns an empty string on error.
	*/
	virtual QString toPEM() const = 0;

	/**
	   Read DER-formatted input and convert it into this object

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	*/
	virtual ConvertResult fromDER(const QByteArray &a) = 0;

	/**
	   Read PEM-formatted input and convert it into this object

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	*/
	virtual ConvertResult fromPEM(const QString &s) = 0;
};

/**
   \class CertContextProps qcaprovider.h QtCrypto

   X.509 certificate or certificate request properties

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want Certificate or
   CertificateRequest instead.

   Some fields are only for certificates or only for certificate requests,
   and these fields are noted.

   \ingroup ProviderAPI
*/
class QCA_EXPORT CertContextProps
{
public:
	/**
	   The X.509 certificate version, usually 3

	   This field is for certificates only.
	*/
	int version;

	/**
	   The time the certificate becomes valid (often the time of create)

	   This field is for certificates only.
	*/
	QDateTime start;

	/**
	   The time the certificate expires

	   This field is for certificates only.
	*/
	QDateTime end;

	/**
	   The subject information
	*/
	CertificateInfoOrdered subject;

	/**
	   The issuer information

	   This field is for certificates only.
	*/
	CertificateInfoOrdered issuer;

	/**
	   The constraints
	*/
	Constraints constraints;

	/**
	   The policies
	*/
	QStringList policies;

	/**
	   A list of URIs for CRLs

	   This field is for certificates only.
	*/
	QStringList crlLocations;

	/**
	   A list of URIs for issuer certificates

	   This field is for certificates only.
	*/
	QStringList issuerLocations;

	/**
	   A list of URIs for OCSP services

	   This field is for certificates only.
	*/
	QStringList ocspLocations;

	/**
	   The certificate serial number

	   This field is for certificates only.
	*/
	BigInteger serial;

	/**
	   True if the certificate is a CA or the certificate request is
	   requesting to be a CA, otherwise false
	*/
	bool isCA;

	/**
	   True if the certificate is self-signed

	   This field is for certificates only.
	*/
	bool isSelfSigned;

	/**
	   The path limit
	*/
	int pathLimit;

	/**
	   The signature data
	*/
	QByteArray sig;

	/**
	   The signature algorithm used to create the signature
	*/
	SignatureAlgorithm sigalgo;

	/**
	   The subject id

	   This field is for certificates only.
	*/
	QByteArray subjectId;

	/**
	   The issuer id

	   This field is for certificates only.
	*/
	QByteArray issuerId;

	/**
	   The SPKAC challenge value

	   This field is for certificate requests only.
	*/
	QString challenge;

	/**
	   The format used for the certificate request

	   This field is for certificate requests only.
	*/
	CertificateRequestFormat format;
};

/**
   \class CRLContextProps qcaprovider.h QtCrypto

   X.509 certificate revocation list properties

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want CRL instead.

   For efficiency and simplicity, the members are directly accessed.

   \ingroup ProviderAPI
*/
class QCA_EXPORT CRLContextProps
{
public:
	/**
	   The issuer information of the CRL
	*/
	CertificateInfoOrdered issuer;

	/**
	   The CRL number, which increases at each update
	*/
	int number;

	/**
	   The time this CRL was created
	*/
	QDateTime thisUpdate;

	/**
	   The time this CRL expires, and the next CRL should be fetched
	*/
	QDateTime nextUpdate;

	/**
	   The revoked entries
	*/
	QList<CRLEntry> revoked;

	/**
	   The signature data of the CRL
	*/
	QByteArray sig;

	/**
	   The signature algorithm used by the issuer to sign the CRL
	*/
	SignatureAlgorithm sigalgo;

	/**
	   The issuer id
	*/
	QByteArray issuerId;
};

class CRLContext;

/**
   \class CertContext qcaprovider.h QtCrypto

   X.509 certificate provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want Certificate instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT CertContext : public CertBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	CertContext(Provider *p) : CertBase(p, QStringLiteral("cert")) {}

	/**
	   Create a self-signed certificate based on the given options and
	   private key.  Returns true if successful, otherwise false.

	   If successful, this object becomes the self-signed certificate.
	   If unsuccessful, this object is considered to be in an
	   uninitialized state.

	   \param opts the options to set on the certificate
	   \param priv the key to be used to sign the certificate 
	*/
	virtual bool createSelfSigned(const CertificateOptions &opts, const PKeyContext &priv) = 0;

	/**
	   Returns a pointer to the properties of this certificate
	*/
	virtual const CertContextProps *props() const = 0;

	/**
	   Returns true if this certificate is equal to another certificate,
	   otherwise false

	   \param other the certificate to compare with
	*/
	virtual bool compare(const CertContext *other) const = 0;

	/**
	   Returns a copy of this certificate's public key.  The caller is
	   responsible for deleting it.
	*/
	virtual PKeyContext *subjectPublicKey() const = 0;

	/**
	   Returns true if this certificate is an issuer of another
	   certificate, otherwise false

	   \param other the issued certificate to check
	*/
	virtual bool isIssuerOf(const CertContext *other) const = 0;

	/**
	   Validate this certificate

	   This function is blocking.

	   \param trusted list of trusted certificates
	   \param untrusted list of untrusted certificates (can be empty)
	   \param crls list of CRLs (can be empty)
	   \param u the desired usage for this certificate
	   \param vf validation options
	*/
	virtual Validity validate(const QList<CertContext*> &trusted, const QList<CertContext*> &untrusted, const QList<CRLContext*> &crls, UsageMode u, ValidateFlags vf) const = 0;

	/**
	   Validate a certificate chain.  This function makes no use of the
	   certificate represented by this object, and it can be used even
	   if this object is in an uninitialized state.

	   This function is blocking.

	   \param chain list of certificates in the chain, starting with the
	   user certificate.  It is not necessary for the chain to contain
	   the final root certificate.
	   \param trusted list of trusted certificates
	   \param crls list of CRLs (can be empty)
	   \param u the desired usage for the user certificate in the chain
	   \param vf validation options
	*/
	virtual Validity validate_chain(const QList<CertContext*> &chain, const QList<CertContext*> &trusted, const QList<CRLContext*> &crls, UsageMode u, ValidateFlags vf) const = 0;
};

/**
   \class CSRContext qcaprovider.h QtCrypto

   X.509 certificate request provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want CertificateRequest
   instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT CSRContext : public CertBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	CSRContext(Provider *p) : CertBase(p, QStringLiteral("csr")) {}

	/**
	   Returns true if the provider of this object supports the specified
	   format, otherwise false

	   \param f the format to test for support for.
	*/
	virtual bool canUseFormat(CertificateRequestFormat f) const = 0;

	/**
	   Create a certificate request based on the given options and
	   private key.  Returns true if successful, otherwise false.

	   If successful, this object becomes the certificate request.
	   If unsuccessful, this object is considered to be in an
	   uninitialized state.

	   \param opts the options to set on the certificate
	   \param priv the key to be used to sign the certificate 
	*/
	virtual bool createRequest(const CertificateOptions &opts, const PKeyContext &priv) = 0;

	/**
	   Returns a pointer to the properties of this certificate request
	*/
	virtual const CertContextProps *props() const = 0;

	/**
	   Returns true if this certificate request is equal to another
	   certificate request, otherwise false

	   \param other the certificate request to compare with
	*/
	virtual bool compare(const CSRContext *other) const = 0;

	/**
	   Returns a copy of this certificate request's public key.  The
	   caller is responsible for deleting it.
	*/
	virtual PKeyContext *subjectPublicKey() const = 0;

	/**
	   Convert this certificate request to Netscape SPKAC format, and
	   return the value

	   Returns an empty string on error.
	*/
	virtual QString toSPKAC() const = 0;

	/**
	   Read Netscape SPKAC input and convert it into a certificate
	   request

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	*/
	virtual ConvertResult fromSPKAC(const QString &s) = 0;
};

/**
   \class CRLContext qcaprovider.h QtCrypto

   X.509 certificate revocation list provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want CRL instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT CRLContext : public CertBase
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	CRLContext(Provider *p) : CertBase(p, QStringLiteral("crl")) {}

	/**
	   Returns a pointer to the properties of this CRL
	*/
	virtual const CRLContextProps *props() const = 0;

	/**
	   Returns true if this CRL is equal to another CRL, otherwise false

	   \param other the CRL to compare with
	*/
	virtual bool compare(const CRLContext *other) const = 0;
};

/**
   \class CertCollectionContext qcaprovider.h QtCrypto

   X.509 certificate collection provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want CertificateCollection
   instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT CertCollectionContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	*/
	CertCollectionContext(Provider *p) : BasicContext(p, QStringLiteral("certcollection")) {}

	/**
	   Create PKCS#7 DER output based on the input certificates and CRLs

	   Returns an empty array on error.

	   \param certs list of certificates to store in the output
	   \param crls list of CRLs to store in the output
	*/
	virtual QByteArray toPKCS7(const QList<CertContext*> &certs, const QList<CRLContext*> &crls) const = 0;

	/**
	   Read PKCS#7 DER input and convert it into a list of certificates
	   and CRLs

	   The caller is responsible for deleting the returned items.

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	   \param certs the destination list for the certificates
	   \param crls the destination list for the CRLs
	*/
	virtual ConvertResult fromPKCS7(const QByteArray &a, QList<CertContext*> *certs, QList<CRLContext*> *crls) const = 0;
};

/**
   \class CAContext qcaprovider.h QtCrypto

   X.509 certificate authority provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want CertificateAuthority
   instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT CAContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the Provider associated with this context
	*/
	CAContext(Provider *p) : BasicContext(p, QStringLiteral("ca")) {}

	/**
	   Prepare the object for usage

	   This must be called before any CA operations are performed.

	   \param cert the certificate of the CA
	   \param priv the private key of the CA
	*/
	virtual void setup(const CertContext &cert, const PKeyContext &priv) = 0;

	/**
	   Returns a copy of the CA's certificate.  The caller is responsible
	   for deleting it.
	*/
	virtual CertContext *certificate() const = 0;

	/**
	   Issue a certificate based on a certificate request, and return
	   the certificate.  The caller is responsible for deleting it.

	   \param req the certificate request
	   \param notValidAfter the expiration date
	*/
	virtual CertContext *signRequest(const CSRContext &req, const QDateTime &notValidAfter) const = 0;

	/**
	   Issue a certificate based on a public key and options, and return
	   the certificate.  The caller is responsible for deleting it.

	   \param pub the public key of the certificate
	   \param opts the options to use for generation
	*/
	virtual CertContext *createCertificate(const PKeyContext &pub, const CertificateOptions &opts) const = 0;

	/**
	   Create a new CRL and return it.  The caller is responsible for
	   deleting it.

	   The CRL has no entries in it.

	   \param nextUpdate the expiration date of the CRL
	*/
	virtual CRLContext *createCRL(const QDateTime &nextUpdate) const = 0;

	/**
	   Update an existing CRL, by examining an old one and creating a new
	   one based on it.  The new CRL is returned, and the caller is
	   responsible for deleting it.

	   \param crl an existing CRL issued by this CA
	   \param entries the list of revoked entries
	   \param nextUpdate the expiration date of the new CRL
	*/
	virtual CRLContext *updateCRL(const CRLContext &crl, const QList<CRLEntry> &entries, const QDateTime &nextUpdate) const = 0;
};

/**
   \class PKCS12Context qcaprovider.h QtCrypto

   PKCS#12 provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want KeyBundle instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT PKCS12Context : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the Provider associated with this context
	*/
	PKCS12Context(Provider *p) : BasicContext(p, QStringLiteral("pkcs12")) {}

	/**
	   Create PKCS#12 DER output based on a set of input items

	   Returns an empty array on error.

	   \param name the friendly name of the data
	   \param chain the certificate chain to store
	   \param priv the private key to store
	   \param passphrase the passphrase to encrypt the PKCS#12 data with
	*/
	virtual QByteArray toPKCS12(const QString &name, const QList<const CertContext*> &chain, const PKeyContext &priv, const SecureArray &passphrase) const = 0;

	/**
	   Read PKCS#12 DER input and convert it into a set of output items

	   The caller is responsible for deleting the returned items.

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param in the input data
	   \param passphrase the passphrase needed to decrypt the input data
	   \param name the destination string for the friendly name
	   \param chain the destination list for the certificate chain
	   \param priv address of a pointer to accept the private key
	*/
	virtual ConvertResult fromPKCS12(const QByteArray &in, const SecureArray &passphrase, QString *name, QList<CertContext*> *chain, PKeyContext **priv) const = 0;
};

/**
   \class PGPKeyContextProps qcaprovider.h QtCrypto

   OpenPGP key properties

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want PGPKey instead.

   For efficiency and simplicity, the members are directly accessed.

   \ingroup ProviderAPI
*/
class QCA_EXPORT PGPKeyContextProps
{
public:
	/**
	   The key id
	*/
	QString keyId;

	/**
	   List of user id strings for the key, the first one being the
	   primary user id
	*/
	QStringList userIds;

	/**
	   True if this key is a secret key, otherwise false
	*/
	bool isSecret;

	/**
	   The time the key was created
	*/
	QDateTime creationDate;

	/**
	   The time the key expires
	*/
	QDateTime expirationDate;

	/**
	   The hex fingerprint of the key

	   The format is all lowercase with no spaces.
	*/
	QString fingerprint;

	/**
	   True if this key is in a keyring (and thus usable), otherwise
	   false
	*/
	bool inKeyring;

	/**
	   True if this key is trusted (e.g. signed by the keyring owner or
	   via some web-of-trust), otherwise false
	*/
	bool isTrusted;
};

/**
   \class PGPKeyContext qcaprovider.h QtCrypto

   OpenPGP key provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want PGPKey instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT PGPKeyContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the Provider associated with this context
	*/
	PGPKeyContext(Provider *p) : BasicContext(p, QStringLiteral("pgpkey")) {}

	/**
	   Returns a pointer to the properties of this key
	*/
	virtual const PGPKeyContextProps *props() const = 0;

	/**
	   Convert the key to binary format, and return the value
	*/
	virtual QByteArray toBinary() const = 0;

	/**
	   Convert the key to ascii-armored format, and return the value
	*/
	virtual QString toAscii() const = 0;

	/**
	   Read binary input and convert it into a key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param a the input data
	*/
	virtual ConvertResult fromBinary(const QByteArray &a) = 0;

	/**
	   Read ascii-armored input and convert it into a key

	   Returns QCA::ConvertGood if successful, otherwise some error
	   value.

	   \param s the input data
	*/
	virtual ConvertResult fromAscii(const QString &s) = 0;
};

/**
   \class KeyStoreEntryContext qcaprovider.h QtCrypto

   KeyStoreEntry provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want KeyStoreEntry
   instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT KeyStoreEntryContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the Provider associated with this context
	*/
	KeyStoreEntryContext(Provider *p) : BasicContext(p, QStringLiteral("keystoreentry")) {}

	/**
	   Returns the entry type
	*/
	virtual KeyStoreEntry::Type type() const = 0;

	/**
	   Returns the entry id

	   This id must be unique among all other entries in the same store.
	*/
	virtual QString id() const = 0;

	/**
	   Returns the name of this entry
	*/
	virtual QString name() const = 0;

	/**
	   Returns the id of the store that contains this entry
	*/
	virtual QString storeId() const = 0;

	/**
	   Returns the name of the store that contains this entry
	*/
	virtual QString storeName() const = 0;

	/**
	   Returns true if the private key of this entry is present for use
	*/
	virtual bool isAvailable() const;

	/**
	   Serialize the information about this entry

	   This allows the entry object to be restored later, even if the
	   store that contains it is not present.

	   \sa KeyStoreListContext::entryPassive()
	*/
	virtual QString serialize() const = 0;

	/**
	   If this entry is of type KeyStoreEntry::TypeKeyBundle, this
	   function returns the KeyBundle of the entry
	*/
	virtual KeyBundle keyBundle() const;

	/**
	   If this entry is of type KeyStoreEntry::TypeCertificate, this
	   function returns the Certificate of the entry
	*/
	virtual Certificate certificate() const;

	/**
	   If this entry is of type KeyStoreEntry::TypeCRL, this function
	   returns the CRL of the entry
	*/
	virtual CRL crl() const;

	/**
	   If this entry is of type KeyStoreEntry::TypePGPSecretKey, this
	   function returns the secret PGPKey of the entry
	*/
	virtual PGPKey pgpSecretKey() const;

	/**
	   If this entry is of type KeyStoreEntry::TypePGPPublicKey or
	   KeyStoreEntry::TypePGPSecretKey, this function returns the public
	   PGPKey of the entry
	*/
	virtual PGPKey pgpPublicKey() const;

	/**
	   Attempt to ensure the private key of this entry is usable and
	   accessible, potentially prompting the user and/or performing a
	   login to a token device.  Returns true if the entry is now
	   accessible, or false if the entry cannot be made accessible.

	   This function is blocking.
	*/
	virtual bool ensureAccess();
};

/**
   \class KeyStoreListContext qcaprovider.h QtCrypto

   KeyStore provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want KeyStore instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT KeyStoreListContext : public Provider::Context
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the Provider associated with this context
	*/
	KeyStoreListContext(Provider *p) : Provider::Context(p, QStringLiteral("keystorelist")) {}

	/**
	   Starts the keystore provider
	*/
	virtual void start();

	/**
	   Enables or disables update events

	   The updated() and storeUpdated() signals might not be emitted if
	   updates are not enabled.

	   \param enabled whether update notifications are enabled (true) or disabled (false)
	*/
	virtual void setUpdatesEnabled(bool enabled);

	/**
	   Returns a list of integer context ids, each representing a
	   keystore instance

	   If a keystore becomes unavailable and then later becomes
	   available again (for example, if a smart card is removed and
	   then the same one is inserted again), the integer context id
	   must be different than last time.
	*/
	virtual QList<int> keyStores() = 0;

	/**
	   Returns the type of the specified store, or -1 if the integer
	   context id is invalid

	   \param id the id for the store context
	*/
	virtual KeyStore::Type type(int id) const = 0;

	/**
	   Returns the string id of the store, or an empty string if the
	   integer context id is invalid

	   The string id of the store should be unique to a single store, and
	   it should persist between availability/unavailability.  For
	   example, a smart card that is removed and inserted again should
	   have the same string id (despite having a new integer context id).

	   \param id the id for the store context
	*/
	virtual QString storeId(int id) const = 0;

	/**
	   Returns the friendly name of the store, or an empty string if the
	   integer context id is invalid

	   \param id the id for the store context
	*/
	virtual QString name(int id) const = 0;

	/**
	   Returns true if the store is read-only

	   If the integer context id is invalid, this function should return
	   true.

	   \param id the id for the store context
	*/
	virtual bool isReadOnly(int id) const;

	/**
	   Returns the types supported by the store, or an empty list if the
	   integer context id is invalid

	   This function should return all supported types, even if the store
	   doesn't actually contain entries for all of the types.

	   \param id the id for the store context
	*/
	virtual QList<KeyStoreEntry::Type> entryTypes(int id) const = 0;

	/**
	   Returns the entries of the store, or an empty list if the integer
	   context id is invalid

	   The caller is responsible for deleting the returned entry objects.

	   \param id the id for the store context
	*/
	virtual QList<KeyStoreEntryContext*> entryList(int id) = 0;

	/**
	   Returns a single entry in the store, if the entry id is already
	   known.  If the entry does not exist, the function returns 0.

	   The caller is responsible for deleting the returned entry object.

	   \param id the id for the store context
	   \param entryId the entry to retrieve
	*/
	virtual KeyStoreEntryContext *entry(int id, const QString &entryId);

	/**
	   Returns a single entry, created from the serialization string of
	   a previous entry (using KeyStoreEntryContext::serialize()).  If
	   the serialization string cannot be parsed by this provider, or the
	   entry cannot otherwise be created, the function returns 0.

	   The caller is responsible for deleting the returned entry object.

	   This function must be thread-safe.

	   \param serialized the serialized data to create the entry from
	*/
	virtual KeyStoreEntryContext *entryPassive(const QString &serialized);

	/**
	   Write a KeyBundle to the store

	   Returns the entry id of the new item, or an empty string if there
	   was an error writing the item.

	   \param id the id for the store context
	   \param kb the key bundle to add to the store
	*/
	virtual QString writeEntry(int id, const KeyBundle &kb);

	/**
	   Write a Certificate to the store

	   Returns the entry id of the new item, or an empty string if there
	   was an error writing the item.

	   \param id the id for the store context
	   \param cert the certificate to add to the store
	*/
	virtual QString writeEntry(int id, const Certificate &cert);

	/**
	   Write a CRL to the store

	   Returns the entry id of the new item, or an empty string if there
	   was an error writing the item.

	   \param id the id for the store context
	   \param crl the revocation list to add to the store
	*/
	virtual QString writeEntry(int id, const CRL &crl);

	/**
	   Write a PGPKey to the store

	   Returns the entry id of the new item, or an empty string if there
	   was an error writing the item.

	   \param id the id for the store context
	   \param key the PGP key to add to the store
	*/
	virtual QString writeEntry(int id, const PGPKey &key);

	/**
	   Remove an entry from the store

	   Returns true if the entry is successfully removed, otherwise
	   false.

	   \param id the id for the store context
	   \param entryId the entry to remove from the store
	*/
	virtual bool removeEntry(int id, const QString &entryId);

Q_SIGNALS:
	/**
	   Emit this when the provider is busy looking for keystores.  The
	   provider goes into a busy state when it has reason to believe
	   there are keystores present, but it still needs to check or query
	   some devices to see for sure.

	   For example, if a smart card is inserted, then the provider may
	   immediately go into a busy state upon detecting the insert.
	   However, it may take some seconds before the smart card
	   information can be queried and reported by the provider.  Once
	   the card is queried successfully, the provider would leave the
	   busy state and report the new keystore.

	   When this object is first started with start(), it is assumed to
	   be in the busy state, so there is no need to emit this signal at
	   the beginning.
	*/
	void busyStart();

	/**
	   Emit this to leave the busy state

	   When this object is first started with start(), it is assumed to
	   be in the busy state.  You must emit busyEnd() at some point, or
	   QCA will never ask you about keystores.
	*/
	void busyEnd();

	/**
	   Indicates the list of keystores has changed, and that QCA should
	   call keyStores() to obtain the latest list
	*/
	void updated();

	/**
	   Emitted when there is diagnostic text to report

	   \param str the diagnostic text
	*/
	void diagnosticText(const QString &str);

	/**
	   Indicates that the entry list of a keystore has changed (entries
	   added, removed, or modified)

	   \param id the id of the key store that has changed
	*/
	void storeUpdated(int id);
};

/**
   \class TLSSessionContext qcaprovider.h QtCrypto

   TLS "session" provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want TLSSession instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT TLSSessionContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the Provider associated with this context
	*/
	TLSSessionContext(Provider *p) : BasicContext(p, QStringLiteral("tlssession")) {}
};

/**
   \class TLSContext qcaprovider.h QtCrypto

   TLS provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want TLS instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT TLSContext : public Provider::Context
{
	Q_OBJECT
public:
	/**
	   \class QCA::TLSContext::SessionInfo qcaprovider.h QtCrypto

	   Information about an active TLS connection

	   For efficiency and simplicity, the members are directly accessed.

	   \ingroup ProviderAPI
	*/
	class SessionInfo
	{
	public:
		/**
		   True if the TLS connection is compressed, otherwise false
		*/
		bool isCompressed;

		/**
		   The TLS protocol version being used for this connection
		*/
		TLS::Version version;

		/**
		   The cipher suite being used for this connection

		   \sa TLSContext::supportedCipherSuites()
		*/
		QString cipherSuite;

		/**
		   The bit size of the cipher used for this connection
		*/
		int cipherBits;

		/**
		   The maximum bit size possible of the cipher used for this
		   connection
		*/
		int cipherMaxBits;

		/**
		   Pointer to the id of this TLS session, for use with
		   resuming
		*/
		TLSSessionContext *id;
	};

	/**
	   Result of a TLS operation
	*/
	enum Result
	{
		Success, ///< Operation completed
		Error,   ///< Operation failed
		Continue ///< More data needed to complete operation
	};

	/**
	   Standard constructor

	   \param p the Provider associated with this context
	   \param type the name of the type of feature that supported by this context
	*/
	TLSContext(Provider *p, const QString &type) : Provider::Context(p, type) {}

	/**
	   Reset the object to its initial state
	*/
	virtual void reset() = 0;

	/**
	   Returns a list of supported cipher suites for the specified
	   SSL/TLS version.  The cipher suites are specified as strings, for
	   example: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" (without quotes).

	   \param version the version of TLS to search for
	*/
	virtual QStringList supportedCipherSuites(const TLS::Version &version) const = 0;

	/**
	   Returns true if the provider supports compression
	*/
	virtual bool canCompress() const = 0;

	/**
	   Returns true if the provider supports server name indication
	*/
	virtual bool canSetHostName() const = 0;

	/**
	   Returns the maximum SSF supported by this provider
	*/
	virtual int maxSSF() const = 0;

	/**
	   Configure a new session

	   This function will be called before any other configuration
	   functions.

	   \param serverMode whether to operate as a server (true) or client (false)
	   \param hostName the hostname to use
	   \param compress whether to compress (true) or not (false)
	*/
	virtual void setup(bool serverMode, const QString &hostName, bool compress) = 0;

	/**
	   Set the constraints of the session using SSF values

	   This function will be called before start().

	   \param minSSF the minimum strength factor that is acceptable 
	   \param maxSSF the maximum strength factor that is acceptable
	*/
	virtual void setConstraints(int minSSF, int maxSSF) = 0;

	/**
	   \overload

	   Set the constraints of the session using a cipher suite list

	   This function will be called before start().

	   \param cipherSuiteList the list of cipher suites that may be used for
	   this session.

	   \sa supportedCipherSuites
	*/
	virtual void setConstraints(const QStringList &cipherSuiteList) = 0;

	/**
	   Set the list of trusted certificates

	   This function may be called at any time.

	   \param trusted the trusted certificates and CRLs to be used.
	*/
	virtual void setTrustedCertificates(const CertificateCollection &trusted) = 0;

	/**
	   Set the list of acceptable issuers

	   This function may be called at any time.

	   This function is for server mode only.

	   \param issuerList the list of issuers that may be used
	*/
	virtual void setIssuerList(const QList<CertificateInfoOrdered> &issuerList) = 0;

	/**
	   Set the local certificate

	   This function may be called at any time.

	   \param cert the certificate and associated trust chain
	   \param key the private key for the local certificate
	*/
	virtual void setCertificate(const CertificateChain &cert, const PrivateKey &key) = 0;

	/**
	   Set the TLS session id, for session resuming

	   This function will be called before start().

	   \param id the session identification
	*/
	virtual void setSessionId(const TLSSessionContext &id) = 0;

	/**
	   Sets the session to the shutdown state.

	   The actual shutdown operation will happen at a future call to
	   update().

	   This function is for normal TLS only (not DTLS).
	*/
	virtual void shutdown() = 0;

	/**
	   Set the maximum transmission unit size

	   This function is for DTLS only.

	   \param size the maximum number of bytes in a datagram
	*/
	virtual void setMTU(int size);

	/**
	   Begins the session, starting with the handshake

	   This function returns immediately, and completion is signaled with
	   the resultsReady() signal.

	   On completion, the result() function will return Success if the
	   TLS session is able to begin, or Error if there is a failure to
	   initialize the TLS subsystem.  If successful, the session is now
	   in the handshake state, and update() will be called repeatedly
	   until the session ends.
	*/
	virtual void start() = 0;

	/**
	   Performs one iteration of the TLS session processing

	   This function returns immediately, and completion is signaled with
	   the resultsReady() signal.

	   If the session is in a handshake state, result() and to_net() will
	   be valid.  If result() is Success, then the session is now in the
	   connected state.

	   If the session is in a shutdown state, result() and to_net() will
	   be valid.  If result() is Success, then the session has ended.

	   If the session is in a connected state, result(), to_net(),
	   encoded(), to_app(), and eof() are valid.  The result() function
	   will return Success or Error.  Note that eof() does not apply
	   to DTLS.

	   For DTLS, this function operates with single packets.  Many
	   update() operations must be performed repeatedly to exchange
	   multiple packets.

	   \param from_net the data from the "other side" of the connection
	   \param from_app the data from the application of the protocol
	*/
	virtual void update(const QByteArray &from_net, const QByteArray &from_app) = 0;

	/**
	   Waits for a start() or update() operation to complete.  In this
	   case, the resultsReady() signal is not emitted.  Returns true if
	   the operation completed or false if this function times out.

	   This function is blocking.

	   \param msecs number of milliseconds to wait (-1 to wait forever)
	*/
	virtual bool waitForResultsReady(int msecs) = 0;

	/**
	   Returns the result code of an operation
	*/
	virtual Result result() const = 0;

	/**
	   Returns data that should be sent across the network
	*/
	virtual QByteArray to_net() = 0;

	/**
	   Returns the number of bytes of plaintext data that is encoded
	   inside of to_net()
	*/
	virtual int encoded() const = 0;

	/**
	   Returns data that is decoded from the network and should be
	   processed by the application
	*/
	virtual QByteArray to_app() = 0;

	/**
	   Returns true if the peer has closed the stream
	*/
	virtual bool eof() const = 0;

	/**
	   Returns true if the TLS client hello has been received

	   This is only valid if a handshake is in progress or
	   completed.
	*/
	virtual bool clientHelloReceived() const = 0;

	/**
	   Returns true if the TLS server hello has been received

	   This is only valid if a handshake is in progress or completed.
	*/
	virtual bool serverHelloReceived() const = 0;

	/**
	   Returns the host name sent by the client using server name
	   indication (server mode only)

	   This is only valid if a handshake is in progress or completed.
	*/
	virtual QString hostName() const = 0;

	/**
	   Returns true if the peer is requesting a certificate

	   This is only valid if a handshake is in progress or completed.
	*/
	virtual bool certificateRequested() const = 0;

	/**
	   Returns the issuer list sent by the server (client mode only)

	   This is only valid if a handshake is in progress or completed.
	*/
	virtual QList<CertificateInfoOrdered> issuerList() const = 0;

	/**
	   Returns the QCA::Validity of the peer certificate

	   This is only valid if a handshake is completed.
	*/
	virtual Validity peerCertificateValidity() const = 0;

	/**
	   Returns the peer certificate chain

	   This is only valid if a handshake is completed.
	*/
	virtual CertificateChain peerCertificateChain() const = 0;

	/**
	   Returns information about the active TLS session

	   This is only valid if a handshake is completed.
	*/
	virtual SessionInfo sessionInfo() const = 0;

	/**
	   Returns any unprocessed network input data

	   This is only valid after a successful shutdown.
	*/
	virtual QByteArray unprocessed() = 0;

Q_SIGNALS:
	/**
	   Emit this when a start() or update() operation has completed.
	*/
	void resultsReady();

	/**
	   Emit this to force the application to call update(), even with
	   empty arguments.
	*/
	void dtlsTimeout();
};

/**
   \class SASLContext qcaprovider.h QtCrypto

   SASL provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want SASL instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT SASLContext : public Provider::Context
{
	Q_OBJECT
public:
	/**
	   \class QCA::SASLContext::HostPort qcaprovider.h QtCrypto

	   Convenience class to hold an IP address and an associated port

	   For efficiency and simplicity, the members are directly accessed.

	   \ingroup ProviderAPI
	*/
	class HostPort
	{
	public:
		/**
		   The IP address
		*/
		QString addr;

		/**
		   The port
		*/
		quint16 port;
	};

	/**
	   Result of a SASL operation
	*/
	enum Result
	{
		Success,   ///< Operation completed
		Error,     ///< Operation failed
		Params,    ///< Parameters are needed to complete authentication
		AuthCheck, ///< Client login can be inspected (server only)
		Continue   ///< More steps needed to complete authentication
	};

	/**
	   Standard constructor

	   \param p the Provider associated with this context
	*/
	SASLContext(Provider *p) : Provider::Context(p, QStringLiteral("sasl")) {}

	/**
	   Reset the object to its initial state
	*/
	virtual void reset() = 0;

	/**
	   Configure a new session

	   This function will be called before any other configuration
	   functions.

	   \param service the name of the network service being provided by
	   this application, which can be used by the SASL system for policy
	   control.  Examples: "imap", "xmpp"
	   \param host the hostname that the application is interacting with
	   or as
	   \param local pointer to a HostPort representing the local end of a
	   network socket, or 0 if this information is unknown or not
	   available
	   \param remote pointer to a HostPort representing the peer end of a
	   network socket, or 0 if this information is unknown or not
	   available
	   \param ext_id the id to be used for SASL EXTERNAL (client only)
	   \param ext_ssf the SSF of the external authentication channel
	   (client only)
	*/
	virtual void setup(const QString &service, const QString &host, const HostPort *local, const HostPort *remote, const QString &ext_id, int ext_ssf) = 0;

	/**
	   Set the constraints of the session using SSF values

	   This function will be called before startClient() or
	   startServer().

	   \param f the flags to use
	   \param minSSF the minimum strength factor that is acceptable 
	   \param maxSSF the maximum strength factor that is acceptable
	*/
	virtual void setConstraints(SASL::AuthFlags f, int minSSF, int maxSSF) = 0;

	/**
	   Begins the session in client mode, starting with the
	   authentication

	   This function returns immediately, and completion is signaled with
	   the resultsReady() signal.

	   On completion, result(), mech(), haveClientInit(), and stepData()
	   will be valid.  If result() is Success, then the session is now in
	   the connected state.

	   \param mechlist the list of mechanisms
	   \param allowClientSendFirst whether the client sends first (true) or the server
	   sends first (false)
	*/
	virtual void startClient(const QStringList &mechlist, bool allowClientSendFirst) = 0;

	/**
	   Begins the session in server mode, starting with the
	   authentication

	   This function returns immediately, and completion is signaled with
	   the resultsReady() signal.

	   On completion, result() and mechlist() will be valid.  The
	   result() function will return Success or Error.  If the result is
	   Success, then serverFirstStep() will be called next.

	   \param realm the realm to authenticate in
	   \param disableServerSendLast whether the client sends first (true)
	   or the server sends first (false)
	*/
	virtual void startServer(const QString &realm, bool disableServerSendLast) = 0;

	/**
	   Finishes server startup

	   This function returns immediately, and completion is signaled with
	   the resultsReady() signal.

	   On completion, result() and stepData() will be valid.  If result()
	   is Success, then the session is now in the connected state.

	   \param mech the mechanism to use
	   \param clientInit initial data from the client, or 0 if there is
	   no such data
	*/
	virtual void serverFirstStep(const QString &mech, const QByteArray *clientInit) = 0;

	/**
	   Perform another step of the SASL authentication

	   This function returns immediately, and completion is signaled with
	   the resultsReady() signal.

	   On completion, result() and stepData() will be valid.

	   \param from_net the data from the "other side" of the protocol
	   to be used for the next step.
	*/
	virtual void nextStep(const QByteArray &from_net) = 0;

	/**
	   Attempt the most recent operation again.  This is used if the
	   result() of an operation is Params or AuthCheck.

	   This function returns immediately, and completion is signaled with
	   the resultsReady() signal.

	   On completion, result() and stepData() will be valid.
	*/
	virtual void tryAgain() = 0;

	/**
	   Performs one iteration of the SASL security layer processing

	   This function returns immediately, and completion is signaled with
	   the resultsReady() signal.

	   On completion, result(), to_net(), encoded(), and to_app() will be
	   valid.  The result() function will return Success or Error.

	   \param from_net the data from the "other side" of the protocol
	   \param from_app the data from the application of the protocol
	*/
	virtual void update(const QByteArray &from_net, const QByteArray &from_app) = 0;

	/**
	   Waits for a startClient(), startServer(), serverFirstStep(),
	   nextStep(), tryAgain(), or update() operation to complete.  In
	   this case, the resultsReady() signal is not emitted.  Returns true
	   if the operation completed or false if this function times out.

	   This function is blocking.

	   \param msecs number of milliseconds to wait (-1 to wait forever)
	*/
	virtual bool waitForResultsReady(int msecs) = 0;

	/**
	   Returns the result code of an operation
	*/
	virtual Result result() const = 0;

	/**
	   Returns the mechanism list (server mode only)
	*/
	virtual QStringList mechlist() const = 0;

	/**
	   Returns the mechanism selected
	*/
	virtual QString mech() const = 0;

	/**
	   Returns true if the client has initialization data
	*/
	virtual bool haveClientInit() const = 0;

	/**
	   Returns an authentication payload for to be transmitted over the
	   network
	*/
	virtual QByteArray stepData() const = 0;

	/**
	   Returns data that should be sent across the network (for the
	   security layer)
	*/
	virtual QByteArray to_net() = 0;

	/**
	   Returns the number of bytes of plaintext data that is encoded
	   inside of to_net()
	*/
	virtual int encoded() const = 0;

	/**
	   Returns data that is decoded from the network and should be
	   processed by the application
	*/
	virtual QByteArray to_app() = 0;

	/**
	   Returns the SSF of the active SASL session

	   This is only valid after authentication success.
	*/
	virtual int ssf() const = 0;

	/**
	   Returns the reason for failure, if the authentication was not
	   successful.

	   This is only valid after authentication failure.
	*/
	virtual SASL::AuthCondition authCondition() const = 0;

	/**
	   Returns the needed/optional client parameters

	   This is only valid after receiving the Params result code.
	*/
	virtual SASL::Params clientParams() const = 0;

	/**
	   Set some of the client parameters (pass 0 to not set a field)

	   \param user the user name
	   \param authzid the authorization name / role
	   \param pass the password
	   \param realm the realm to authenticate in
	*/
	virtual void setClientParams(const QString *user, const QString *authzid, const SecureArray *pass, const QString *realm) = 0;

	/**
	   Returns the realm list (client mode only)

	   This is only valid after receiving the Params result code and
	   SASL::Params::canSendRealm is set to true.
	*/
	virtual QStringList realmlist() const = 0;

	/**
	   Returns the username attempting to authenticate (server mode only)

	   This is only valid after receiving the AuthCheck result code.
	*/
	virtual QString username() const = 0;

	/**
	   Returns the authzid attempting to authorize (server mode only)

	   This is only valid after receiving the AuthCheck result code.
	*/
	virtual QString authzid() const = 0;

Q_SIGNALS:
	/**
	   Emit this when a startClient(), startServer(), serverFirstStep(),
	   nextStep(), tryAgain(), or update() operation has completed.
	*/
	void resultsReady();
};

/**
   \class MessageContext qcaprovider.h QtCrypto

   SecureMessage provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want SecureMessage
   instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT MessageContext : public Provider::Context
{
	Q_OBJECT
public:
	/**
	   The type of operation being performed
	*/
	enum Operation
	{
		Encrypt,       ///< Encrypt operation
		Decrypt,       ///< Decrypt (or Decrypt and Verify) operation
		Sign,          ///< Sign operation
		Verify,        ///< Verify operation
		SignAndEncrypt ///< Sign and Encrypt operation
	};

	/**
	   Standard constructor

	   \param p the Provider associated with this context
	   \param type the name of the type of secure message to be created
	*/
	MessageContext(Provider *p, const QString &type) : Provider::Context(p, type) {}

	/**
	   Returns true if the provider supports multiple signers for
	   signature creation or signature verification
	*/
	virtual bool canSignMultiple() const = 0;

	/**
	   The type of secure message (e.g. PGP or CMS)
	*/
	virtual SecureMessage::Type type() const = 0;

	/**
	   Reset the object to its initial state
	*/
	virtual void reset() = 0;

	/**
	   Configure a new encrypting operation

	   \param keys the keys to be used for encryption.
	*/
	virtual void setupEncrypt(const SecureMessageKeyList &keys) = 0;

	/**
	   Configure a new signing operation

	   \param keys the keys to use for signing
	   \param m the mode to sign in
	   \param bundleSigner whether to bundle the signing keys (true) or not (false)
	   \param smime whether to use smime format (true) or not (false)
	*/
	virtual void setupSign(const SecureMessageKeyList &keys, SecureMessage::SignMode m, bool bundleSigner, bool smime) = 0;

	/**
	   Configure a new verify operation

	   \param detachedSig the detached signature to use (if applicable) for verification
	*/
	virtual void setupVerify(const QByteArray &detachedSig) = 0;

	/**
	   Begins the secure message operation

	   This function returns immediately.

	   If there is input data, update() will be called (potentially
	   repeatedly) afterwards.  Emit updated() if there is data to
	   read, if input data has been accepted, or if the operation has
	   finished.

	   \param f the format of the message to be produced
	   \param op the operation to be performed
	*/
	virtual void start(SecureMessage::Format f, Operation op) = 0;

	/**
	   Provide input to the message operation

	   \param in the data to use for the message operation
	*/
	virtual void update(const QByteArray &in) = 0;

	/**
	   Extract output from the message operation
	*/
	virtual QByteArray read() = 0;

	/**
	   Returns the number of input bytes accepted since the last call to
	   update()
	*/
	virtual int written() = 0;

	/**
	   Indicates the end of input
	*/
	virtual void end() = 0;

	/**
	   Returns true if the operation has finished, otherwise false
	*/
	virtual bool finished() const = 0;

	/**
	   Waits for the secure message operation to complete.  In this case,
	   the updated() signal is not emitted.  Returns true if the
	   operation completed or false if this function times out.

	   This function is blocking.

	   \param msecs number of milliseconds to wait (-1 to wait forever)
	*/
	virtual bool waitForFinished(int msecs) = 0;

	/**
	   Returns true if the operation was successful

	   This is only valid if the operation has finished.
	*/
	virtual bool success() const = 0;

	/**
	   Returns the reason for failure, if the operation was not
	   successful

	   This is only valid if the operation has finished.
	*/
	virtual SecureMessage::Error errorCode() const = 0;

	/**
	   Returns the signature, in the case of a detached signature
	   operation

	   This is only valid if the operation has finished.
	*/
	virtual QByteArray signature() const = 0;

	/**
	   Returns the name of the hash used to generate the signature, in
	   the case of a signature operation

	   This is only valid if the operation has finished.
	*/
	virtual QString hashName() const = 0;

	/**
	   Returns a list of signatures, in the case of a verify or decrypt
	   and verify operation

	   This is only valid if the operation has finished.
	*/
	virtual SecureMessageSignatureList signers() const = 0;

	/**
	   Returns any diagnostic text for the operation, potentially useful
	   to show the user in the event the operation is unsuccessful.  For
	   example, this could be the stderr output of gpg.

	   This is only valid if the operation has finished.
	*/
	virtual QString diagnosticText() const;

Q_SIGNALS:
	/**
	   Emitted when there is data to read, if input data has been
	   accepted, or if the operation has finished
	*/
	void updated();
};

/**
   \class SMSContext qcaprovider.h QtCrypto

   SecureMessageSystem provider

   \note This class is part of the provider plugin interface and should not
   be used directly by applications.  You probably want SecureMessageSystem
   instead.

   \ingroup ProviderAPI
*/
class QCA_EXPORT SMSContext : public BasicContext
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param p the provider associated with this context
	   \param type the name of the type of secure message system
	*/
	SMSContext(Provider *p, const QString &type) : BasicContext(p, type) {}

	/**
	   Set the trusted certificates and for this secure message system,
	   to be used for validation

	   The collection may also contain CRLs.

	   This function is only valid for CMS.

	   \param trusted a set of trusted certificates and CRLs.
	*/
	virtual void setTrustedCertificates(const CertificateCollection &trusted);

	/**
	   Set the untrusted certificates and CRLs for this secure message
	   system, to be used for validation

	   This function is only valid for CMS.

	   \param untrusted a set of untrusted certificates and CRLs.
	*/
	virtual void setUntrustedCertificates(const CertificateCollection &untrusted);

	/**
	   Set the private keys for this secure message system, to be used
	   for decryption

	   This function is only valid for CMS.

	   \param keys the keys to be used for decryption
	*/
	virtual void setPrivateKeys(const QList<SecureMessageKey> &keys);

	/**
	   Create a new message object for this system.  The caller is
	   responsible for deleting it.
	*/
	virtual MessageContext *createMessage() = 0;
};

}
#endif

#endif
