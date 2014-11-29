/*
 * qca_securelayer.h - Qt Cryptographic Architecture
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
   \file qca_securelayer.h

   Header file for SecureLayer and its subclasses

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/
#ifndef QCA_SECURELAYER_H
#define QCA_SECURELAYER_H

#include <QObject>
#include "qca_core.h"
#include "qca_publickey.h"
#include "qca_cert.h"

namespace QCA {

/**
   Specify the lower-bound for acceptable TLS/SASL security layers

   For TLS, the interpretation of these levels is:
   - Any cipher suite that provides non-authenticated communications
   (usually anonymous Diffie-Hellman) is SL_Integrity. 
   - Any cipher suite that is limited to 40 bits (export-version
   crippled forms of RC2, RC4 or DES) is SL_Export. Standard
   DES (56 bits) and some forms of RC4 (64 bits) are also SL_Export.
   - Any normal cipher (AES, Camellia, RC4 or similar) with 128 bits, or
   Elliptic Curve Ciphers with 283 bits, is SL_Baseline
   - AES or Camellia at least 192 bits, triple-DES and similar
   ciphers are SL_High.  ECC with 409 or more bits is also SL_High. 
   - Highest does not have an equivalent strength. It
   indicates that the provider should use the strongest
   ciphers available (but not less than SL_High). 
 */
enum SecurityLevel
{
	SL_None,      ///< indicates that no security is ok
	SL_Integrity, ///< must at least get integrity protection
	SL_Export,    ///< must be export level bits or more
	SL_Baseline,  ///< must be 128 bit or more
	SL_High,      ///< must be more than 128 bit
	SL_Highest    ///< SL_High or max possible, whichever is greater
};

/**
   \class SecureLayer qca_securelayer.h QtCrypto

   Abstract interface to a security layer

   SecureLayer is normally used between an application and a
   potentially insecure network. It provides secure
   communications over that network.

   The concept is that (after some initial setup), the
   application can write() some data to the SecureLayer
   implementation, and that data is encrypted (or otherwise
   protected, depending on the setup). The SecureLayer
   implementation then emits the readyReadOutgoing() signal,
   and the application uses readOutgoing() to retrieve the the
   encrypted data from the SecureLayer implementation.  The
   encrypted data is then sent out on the network.

   When some encrypted data comes back from the network, the
   application does a writeIncoming() to the SecureLayer
   implementation. Some time later, the SecureLayer
   implementation may emit readyRead() to the application,
   which then read()s the decrypted data from the SecureLayer
   implementation.

   Note that sometimes data is sent or received between the
   SecureLayer implementation and the network without any data
   being sent between the application and the SecureLayer
   implementation. This is a result of the initial negotiation
   activities (which require network traffic to agree a
   configuration to use) and other overheads associated with
   the secure link.

   \ingroup UserAPI
*/
class QCA_EXPORT SecureLayer : public QObject
{
	Q_OBJECT
public:
	/**
	   Constructor for an abstract secure communications
	   layer

	   \param parent the parent object for this object
	*/
	SecureLayer(QObject *parent = 0);

	/**
	   Returns true if the layer has a meaningful "close".
	*/
	virtual bool isClosable() const;

	/**
	   Returns the number of bytes available to be read()
	   on the application side.
	*/
	virtual int bytesAvailable() const = 0;

	/**
	   Returns the number of bytes available to be
	   readOutgoing() on the network side.
	*/
	virtual int bytesOutgoingAvailable() const = 0;

	/**
	   Close the link. Note that this may not be
	   meaningful / possible for all implementations. 

	   \sa isClosable() for a test that verifies if the
	   link can be %closed.
	*/
	virtual void close();

	/**
	   This method writes unencrypted (plain) data to
	   the SecureLayer implementation. You normally
	   call this function on the application side.

	   \param a the source of the application-side data
	*/
	virtual void write(const QByteArray &a) = 0;

	/**
	   This method reads decrypted (plain) data from
	   the SecureLayer implementation. You normally call
	   this function on the application side after receiving
	   the readyRead() signal.
	*/
	virtual QByteArray read() = 0;

	/**
	   This method accepts encoded (typically encrypted) data
	   for processing. You normally call this function using
	   data read from the network socket (e.g. using 
	   QTcpSocket::readAll()) after receiving a signal that
	   indicates that the socket has data to read.

	   \param a the ByteArray to take network-side data from
	*/
	virtual void writeIncoming(const QByteArray &a) = 0;

	/**
	   This method provides encoded (typically encrypted)
	   data. You normally call this function to get data
	   to write out to the network socket (e.g. using
	   QTcpSocket::write()) after receiving the
	   readyReadOutgoing() signal.

	   \param plainBytes the number of bytes that were read.
	*/
	virtual QByteArray readOutgoing(int *plainBytes = 0) = 0;

	/**
	   This allows you to read data without having it
	   decrypted first. This is intended to be used for
	   protocols that close off the connection and return
	   to plain text transfer. You do not normally need to
	   use this function.
	*/
	virtual QByteArray readUnprocessed();

	/**
	   Convert encrypted bytes written to plain text bytes written

	   \param encryptedBytes the number of bytes to convert
	*/
	virtual int convertBytesWritten(qint64 encryptedBytes) = 0;

Q_SIGNALS:
	/**
	   This signal is emitted when SecureLayer has
	   decrypted (application side) data ready to be
	   read. Typically you will connect this signal to a
	   slot that reads the data (using read()).
	*/
	void readyRead();

	/**
	   This signal is emitted when SecureLayer has encrypted
	   (network side) data ready to be read. Typically you
	   will connect this signal to a slot that reads the data
	   (using readOutgoing()) and writes it to a network socket.
	*/
	void readyReadOutgoing();

	/**
	   This signal is emitted when the SecureLayer connection
	   is %closed.
	*/
	void closed();

	/**
	   This signal is emitted when an error is detected. You
	   can determine the error type using errorCode().
	*/
	void error();

private:
	Q_DISABLE_COPY(SecureLayer)
};

/**
   \class TLSSession qca_securelayer.h QtCrypto

   Session token, used for TLS resuming

   \ingroup UserAPI

*/
class QCA_EXPORT TLSSession : public Algorithm
{
public:
	TLSSession();

	/**
	   Copy constructor

	   \param from the session token to copy from
	*/
	TLSSession(const TLSSession &from);

	~TLSSession();

	/**
	   Assignment operator

	   \param from the session token to assign from
	*/
	TLSSession & operator=(const TLSSession &from);

	/**
	   Test if the session token is valid
	*/
	bool isNull() const;
};

/**
   \class TLS qca_securelayer.h QtCrypto

   Transport Layer Security / Secure Socket Layer 

   Transport Layer Security (%TLS) is the current
   state-of-the-art in secure transport mechanisms over the
   internet. It can be used in a way where only one side of
   the link needs to authenticate to the other. This makes it
   very useful for servers to provide their identity to
   clients. Note that is is possible to use %TLS to
   authenticate both client and server.

   %TLS is a IETF standard (<a
   href="http://www.ietf.org/rfc/rfc2712.txt">RFC2712</a> for
   TLS version 1.0, and <a
   href="http://www.ietf.org/rfc/rfc4346.txt">RFC4346</a> for
   TLS version 1.1) based on earlier Netscape work on Secure
   Socket Layer (SSL version 2 and SSL version 3). New
   applications should use at least TLS 1.0, and SSL version 2
   should be avoided due to known security problems.

   \ingroup UserAPI
*/
class QCA_EXPORT TLS : public SecureLayer, public Algorithm
{
	Q_OBJECT
public:
	/**
	   Operating mode
	*/
	enum Mode
	{
		Stream,  ///< stream mode
		Datagram ///< datagram mode
	};

	/**
	   Version of %TLS or SSL
	*/
	enum Version
	{
		TLS_v1, ///< Transport Layer Security, version 1
		SSL_v3, ///< Secure Socket Layer, version 3
		SSL_v2, ///< Secure Socket Layer, version 2
		DTLS_v1 ///< Datagram Transport Layer Security, version 1
	};

	/**
	   Type of error
	*/
	enum Error
	{
		ErrorSignerExpired,   ///< local certificate is expired
		ErrorSignerInvalid,   ///< local certificate is invalid in some way
		ErrorCertKeyMismatch, ///< certificate and private key don't match
		ErrorInit,            ///< problem starting up %TLS
		ErrorHandshake,       ///< problem during the negotiation
		ErrorCrypt            ///< problem at anytime after
	};

	/**
	   Type of identity
	*/
	enum IdentityResult
	{
		Valid,              ///< identity is verified
		HostMismatch,       ///< valid cert provided, but wrong owner
		InvalidCertificate, ///< invalid cert
		NoCertificate       ///< identity unknown
	};

	/** 
	    Constructor for Transport Layer Security connection

	    This produces a Stream (normal %TLS) rather than Datagram (DTLS)
	    object.
	    If you want to do DTLS, see below.

	    \param parent the parent object for this object
	    \param provider the name of the provider, if a specific provider
	    is required
	*/
	explicit TLS(QObject *parent = 0, const QString &provider = QString());

	/**
	   Constructor for Transport Layer Security connection.

	   This constructor can be used for both normal %TLS (set mode to TLS::Stream)
	   or DTLS (set mode to TLS::Datagram).

	   \param mode the connection Mode
	   \param parent the parent object for this object
	   \param provider the name of the provider, if a specific provider is
	   required
	*/
	explicit TLS(Mode mode, QObject *parent = 0, const QString &provider = QString());

	/**
	   Destructor
	*/
	~TLS();

	/**
	   Reset the connection
	*/
	void reset();

	/**
	   Get the list of cipher suites that are available for use.

	   A cipher suite is a combination of key exchange,
	   encryption and hashing algorithms that are agreed
	   during the initial handshake between client and
	   server.

	   \param version the protocol Version that the cipher
	   suites are required for

	   \return list of the the names of the cipher suites
	   supported.
	*/
	QStringList supportedCipherSuites(const Version &version = TLS_v1) const;

	/**
	   The local certificate to use. This is the
	   certificate that will be provided to the peer. This
	   is almost always required on the server side
	   (because the server has to provide a certificate to
	   the client), and may be used on the client side.

	   \param cert a chain of certificates that
	   link the host certificate to a trusted root
	   certificate.
	   \param key the private key for the certificate
	   chain
	*/
	void setCertificate(const CertificateChain &cert, const PrivateKey &key);

	/**
	   \overload

	   Allows setting a certificate from a KeyBundle.

	   \param kb key bundle containing the local certificate
	   and associated private key.
	*/
	void setCertificate(const KeyBundle &kb);

	/**
	   Return the trusted certificates set for this object
	*/
	CertificateCollection trustedCertificates() const;

	/**
	   Set up the set of trusted certificates that will be used to verify
	   that the certificate provided is valid.

	   Typically, this will be the collection of root certificates from
	   the system, which you can get using QCA::systemStore(), however you
	   may choose to pass whatever certificates match your assurance
	   needs.

	   \param trusted a bundle of trusted certificates.
	*/
	void setTrustedCertificates(const CertificateCollection &trusted);

	/**
	   The security level required for this link

	   \param s the level required for this link.
	*/
	void setConstraints(SecurityLevel s);

	/**
	   \overload

	   \param minSSF the minimum Security Strength Factor
	   required for this link.
	   \param maxSSF the maximum Security Strength Factor
	   required for this link.
	*/
	void setConstraints(int minSSF, int maxSSF);

	/**
	   \overload

	   \param cipherSuiteList a list of the names of
	   cipher suites that can be used for this link.

	   \note the names are the same as the names in the
	   applicable IETF RFCs (or Internet Drafts if there
	   is no applicable RFC).
	*/
	void setConstraints(const QStringList &cipherSuiteList);

	/**
	   Retrieve the list of allowed issuers by the server,
	   if the server has provided them.  Only DN types will
	   be present.

	   \code
Certificate someCert = ...
PrivateKey someKey = ...

// see if the server will take our cert
CertificateInfoOrdered issuerInfo = someCert.issuerInfoOrdered().dnOnly();
foreach(const CertificateInfoOrdered &info, tls->issuerList())
{
	if(info == issuerInfo)
	{
		// server will accept someCert, let's present it
		tls->setCertificate(someCert, someKey);
		break;
	}
}
	   \endcode
	*/
	QList<CertificateInfoOrdered> issuerList() const;

	/**
	   Sets the issuer list to present to the client.  For
	   use with servers only.  Only DN types are allowed.

	   \param issuers the list of valid issuers to be used.
	*/
	void setIssuerList(const QList<CertificateInfoOrdered> &issuers);

	/**
	   Resume a %TLS session using the given session object

	   \param session the session state to use for resumption.
	*/
	void setSession(const TLSSession &session);

	/**
	   Test if the link can use compression

	   \return true if the link can use compression
	*/
	bool canCompress() const;

	/**
	   Test if the link can specify a hostname (Server Name
	   Indication)

	   \return true if the link can specify a hostname
	*/
	bool canSetHostName() const;

	/**
	   Returns true if compression is enabled

	   This only indicates whether or not the object is configured to use
	   compression, not whether or not the link is actually compressed.
	   Use isCompressed() for that.
	*/
	bool compressionEnabled() const;

	/**
	   Set the link to use compression

	   \param b true if the link should use compression, or false to
	   disable compression
	*/
	void setCompressionEnabled(bool b);

	/**
	   Returns the host name specified or an empty string if no host
	   name is specified.
	*/
	QString hostName() const;

	/**
	   Start the %TLS/SSL connection as a client

	   Typically, you'll want to perform RFC 2818 validation on the
	   server's certificate, based on the hostname you're intending
	   to connect to.  Pass a value for \a host in order to have the
	   validation for you.  If you want to bypass this behavior and
	   do the validation yourself, pass an empty string for \a host.

	   If the host is an internationalized domain name, then it must be
	   provided in unicode format, not in IDNA ACE/punycode format.

	   \param host the hostname that you want to connect to

	   \note The hostname will be used for Server Name Indication
	   extension (see
	   <a href="http://www.ietf.org/rfc/rfc3546.txt">RFC 3546</a> Section
	   3.1) if supported by the backend provider.
	*/
	void startClient(const QString &host = QString());

	/**
	   Start the %TLS/SSL connection as a server.
	*/
	void startServer();

	/**
	   Resumes %TLS processing.

	   Call this function after hostNameReceived(), certificateRequested()
	   peerCertificateAvailable() or handshaken() is emitted.  By
	   requiring this function to be called in order to proceed,
	   applications are given a chance to perform user interaction between
	   steps in the %TLS process.
	*/
	void continueAfterStep();

	/**
	   test if the handshake is complete

	   \return true if the handshake is complete

	   \sa handshaken
	*/
	bool isHandshaken() const;

	/**
	   test if the link is compressed

	   \return true if the link is compressed
	*/
	bool isCompressed() const;

	/**
	   The protocol version that is in use for this connection.
	*/
	Version version() const;

	/**
	   The cipher suite that has been negotiated for this connection.

	   The name returned here is the name used in the applicable RFC
	   (or Internet Draft, where there is no RFC).
	*/
	QString cipherSuite() const;

	/**
	   The number of effective bits of security being used for this
	   connection. 

	   This can differ from the actual number of bits in
	   the cipher for certain
	   older "export ciphers" that are deliberately crippled. If you
	   want that information, use cipherMaxBits().
	*/
	int cipherBits() const;

	/**
	   The number of bits of security that the cipher could use.

	   This is normally the same as cipherBits(), but can be greater
	   for older "export ciphers".
	*/
	int cipherMaxBits() const;

	/**
	   The session object of the %TLS connection, which can be used
	   for resuming.
	*/
	TLSSession session() const;

	/**
	   This method returns the type of error that has
	   occurred. You should only need to check this if the
	   error() signal is emitted.
	*/
	Error errorCode() const;

	/**
	   After the SSL/%TLS handshake is complete, this
	   method allows you to determine if the other end
	   of the connection (if the application is a client,
	   this is the server; if the application is a server,
	   this is the client) has a valid identity.

	   Note that the security of %TLS/SSL depends on
	   checking this. It is not enough to check that the
	   certificate is valid - you must check that the
	   certificate is valid for the entity that you are
	   trying to communicate with.

	   \note If this returns QCA::TLS::InvalidCertificate,
	   you may wish to use peerCertificateValidity() to
	   determine whether to proceed or not.
	*/
	IdentityResult peerIdentityResult() const;

	/**
	   After the SSL/%TLS handshake is valid, this method
	   allows you to check if the received certificate
	   from the other end is valid. As noted in
	   peerIdentityResult(), you also need to check that
	   the certificate matches the entity you are trying
	   to communicate with.
	*/
	Validity peerCertificateValidity() const;

	/**
	   The CertificateChain for the local host
	   certificate.
	*/
	CertificateChain localCertificateChain() const;

	/**
	   The PrivateKey for the local host
	   certificate.
	*/
	PrivateKey localPrivateKey() const;

	/**
	   The CertificateChain from the peer (other end of
	   the connection to the trusted root certificate).
	*/
	CertificateChain peerCertificateChain() const;

	// reimplemented
	virtual bool isClosable() const;
	virtual int bytesAvailable() const;
	virtual int bytesOutgoingAvailable() const;
	virtual void close();
	virtual void write(const QByteArray &a);
	virtual QByteArray read();
	virtual void writeIncoming(const QByteArray &a);
	virtual QByteArray readOutgoing(int *plainBytes = 0);
	virtual QByteArray readUnprocessed();
	virtual int convertBytesWritten(qint64 encryptedBytes);

	/**
	   Determine the number of packets available to be
	   read on the application side.

	   \note this is only used with DTLS.
	*/
	int packetsAvailable() const;

	/**
	   Determine the number of packets available to be
	   read on the network side.

	   \note this is only used with DTLS.
	*/
	int packetsOutgoingAvailable() const;

	/**
	   Return the currently configured maximum packet size

	   \note this is only used with DTLS
	*/
	int packetMTU() const;

	/**
	   Set the maximum packet size to use.

	   \param size the number of bytes to set as the MTU.

	   \note this is only used with DTLS.
	*/
	void setPacketMTU(int size) const;

Q_SIGNALS:
	/**
	   Emitted if a host name is set by the client.  At
	   this time, the server can inspect the hostName().

	   You must call continueAfterStep() in order for %TLS
	   processing to resume after this signal is emitted.

	   This signal is only emitted in server mode.

	   \sa continueAfterStep
	*/
	void hostNameReceived();

	/**
	   Emitted when the server requests a certificate.  At
	   this time, the client can inspect the issuerList().

	   You must call continueAfterStep() in order for %TLS
	   processing to resume after this signal is emitted.

	   This signal is only emitted in client mode.

	   \sa continueAfterStep
	*/
	void certificateRequested();

	/**
	   Emitted when a certificate is received from the peer.
	   At this time, you may inspect peerIdentityResult(),
	   peerCertificateValidity(), and peerCertificateChain().

	   You must call continueAfterStep() in order for %TLS
	   processing to resume after this signal is emitted.

	   \sa continueAfterStep
	*/
	void peerCertificateAvailable();

	/**
	   Emitted when the protocol handshake is complete.  At
	   this time, all available information about the %TLS
	   session can be inspected.

	   You must call continueAfterStep() in order for %TLS
	   processing to resume after this signal is emitted.

	   \sa continueAfterStep
	   \sa isHandshaken
	*/
	void handshaken();

protected:
	/**
	   Called when a connection is made to a particular signal

	   \param signal the name of the signal that has been
	   connected to.
	*/
#if QT_VERSION >= 0x050000
	void connectNotify(const QMetaMethod &signal);
#else
	void connectNotify(const char *signal);
#endif

	/**
	   Called when a connection is removed from a particular signal

	   \param signal the name of the signal that has been
	   disconnected from.
	*/
#if QT_VERSION >= 0x050000
	void disconnectNotify(const QMetaMethod &signal);
#else
	void disconnectNotify(const char *signal);
#endif

private:
	Q_DISABLE_COPY(TLS)

	class Private;
	friend class Private;
	Private *d;
};

/**
   \class SASL qca_securelayer.h QtCrypto

   Simple Authentication and Security Layer protocol implementation

   This class implements the Simple Authenication and Security Layer protocol,
   which is described in RFC2222 - see
   <a href="http://www.ietf.org/rfc/rfc2222.txt">http://www.ietf.org/rfc/rfc2222.txt</a>.

   As the name suggests, %SASL provides authentication (eg, a "login" of some
   form), for a connection oriented protocol, and can also provide protection
   for the subsequent connection.

   The %SASL protocol is designed to be extensible, through a range of
   "mechanisms", where a mechanism is the actual authentication method.
   Example mechanisms include Anonymous, LOGIN, Kerberos V4, and GSSAPI.
   Mechanisms can be added (potentially without restarting the server
   application) by the system administrator.

   It is important to understand that %SASL is neither "network aware" nor
   "protocol aware".  That means that %SASL does not understand how the client
   connects to the server, and %SASL does not understand the actual
   application protocol.

   \ingroup UserAPI

*/
class QCA_EXPORT SASL : public SecureLayer, public Algorithm
{
	Q_OBJECT
public:
	/**
	   Possible errors that may occur when using %SASL
	*/
	enum Error
	{
		ErrorInit,      ///< problem starting up %SASL
		ErrorHandshake, ///< problem during the authentication process
		ErrorCrypt      ///< problem at anytime after
	};

	/**
	   Possible authentication error states
	*/
	enum AuthCondition
	{
		AuthFail,          ///< Generic authentication failure
		NoMechanism,       ///< No compatible/appropriate authentication mechanism
		BadProtocol,       ///< Bad protocol or cancelled
		BadServer,         ///< Server failed mutual authentication (client side only)
		BadAuth,           ///< Authentication failure (server side only)
		NoAuthzid,         ///< Authorization failure (server side only)
		TooWeak,           ///< Mechanism too weak for this user (server side only)
		NeedEncrypt,       ///< Encryption is needed in order to use mechanism (server side only)
		Expired,           ///< Passphrase expired, has to be reset (server side only)
		Disabled,          ///< Account is disabled (server side only)
		NoUser,            ///< User not found (server side only)
		RemoteUnavailable  ///< Remote service needed for auth is gone (server side only)
	};

	/**
	   Authentication requirement flag values
	*/
	enum AuthFlags
	{
		AuthFlagsNone          = 0x00,
		AllowPlain             = 0x01,
		AllowAnonymous         = 0x02,
		RequireForwardSecrecy  = 0x04,
		RequirePassCredentials = 0x08,
		RequireMutualAuth      = 0x10,
		RequireAuthzidSupport  = 0x20  // server-only
	};

	/**
	   Mode options for client side sending
	*/
	enum ClientSendMode
	{
		AllowClientSendFirst,
		DisableClientSendFirst
	};

	/**
	   Mode options for server side sending
	*/
	enum ServerSendMode
	{
		AllowServerSendLast,
		DisableServerSendLast
	};

	/**
	   \class Params qca_securelayer.h QtCrypto

	   Parameter flags for the %SASL authentication

	   This is used to indicate which parameters are needed by %SASL
	   in order to complete the authentication process.

	   \ingroup UserAPI
	*/
	class QCA_EXPORT Params
	{
	public:
		Params();

		/**
		   Standard constructor. 
		   
		   The concept behind this is that you set each of the 
		   flags depending on which parameters are needed.

		   \param user the username is required
		   \param authzid the authorization identity is required
		   \param pass the password is required
		   \param realm the realm is required
		*/
		Params(bool user, bool authzid, bool pass, bool realm);

		/**
		   Standard copy constructor

		   \param from the Params object to copy
		*/
		Params(const Params &from);
		~Params();

		/**
		   Standard assignment operator

		   \param from the Params object to assign from
		*/
		Params & operator=(const Params &from);

		/**
		   User is needed
		*/
		bool needUsername() const;

		/**
		   An Authorization ID can be sent if desired
		*/
		bool canSendAuthzid() const;

		/**
		   Password is needed
		*/
		bool needPassword() const;

		/**
		   A Realm can be sent if desired
		*/
		bool canSendRealm() const;

	private:
		class Private;
		Private *d;
	};

	/**
	   Standard constructor

	   \param parent the parent object for this %SASL connection
	   \param provider if specified, the provider to use. If not 
	   specified, or specified as empty, then any provider is 
	   acceptable.
	*/
	explicit SASL(QObject *parent = 0, const QString &provider = QString());

	~SASL();

	/**
	   Reset the %SASL mechanism
	*/
	void reset();

	/**
	   Specify connection constraints

	   %SASL supports a range of authentication requirements, and
	   a range of security levels. This method allows you to
	   specify the requirements for your connection.

	   \param f the authentication requirements, which you typically
	   build using a binary OR function (eg AllowPlain | AllowAnonymous)
	   \param s the security level of the encryption, if used. See
	   SecurityLevel for details of what each level provides.
	*/
	void setConstraints(AuthFlags f, SecurityLevel s = SL_None);

	/**
	   \overload

	   Unless you have a specific reason for directly specifying a
	   strength factor, you probably should use the method above.

	   \param f the authentication requirements, which you typically
	   build using a binary OR function (eg AllowPlain | AllowAnonymous)
	   \param minSSF the minimum security strength factor that is required
	   \param maxSSF the maximum security strength factor that is required

	   \note Security strength factors are a rough approximation to key
	   length in the encryption function (eg if you are securing with
	   plain DES, the security strength factor would be 56).
	*/
	void setConstraints(AuthFlags f, int minSSF, int maxSSF);

	/**
	   Specify the local address.

	   \param addr the address of the local part of the connection
	   \param port the port number of the local part of the connection
	*/
	void setLocalAddress(const QString &addr, quint16 port);

	/**
	   Specify the peer address.

	   \param addr the address of the peer side of the connection
	   \param port the port number of the peer side of the connection
	*/
	void setRemoteAddress(const QString &addr, quint16 port);

	/**
	   Specify the id of the externally secured connection

	   \param authid the id of the connection
	*/
	void setExternalAuthId(const QString &authid);

	/**
	   Specify a security strength factor for an externally secured
	   connection

	   \param strength the security strength factor of the connection
	*/
	void setExternalSSF(int strength);

	/**
	   Initialise the client side of the connection

	   startClient must be called on the client side of the connection.
	   clientStarted will be emitted when the operation is completed.

	   \param service the name of the service
	   \param host the client side host name
	   \param mechlist the list of mechanisms which can be used
	   \param mode the mode to use on the client side
	*/
	void startClient(const QString &service, const QString &host, const QStringList &mechlist, ClientSendMode mode = AllowClientSendFirst);

	/**
	   Initialise the server side of the connection

	   startServer must be called on the server side of the connection.
	   serverStarted will be emitted when the operation is completed.

	   \param service the name of the service
	   \param host the server side host name
	   \param realm the realm to use
	   \param mode which mode to use on the server side
	*/
	void startServer(const QString &service, const QString &host, const QString &realm, ServerSendMode mode = DisableServerSendLast);

	/**
	   Process the first step in server mode (server)

	   Call this with the mechanism selected by the client.  If there
	   is initial client data, call the other version of this function
	   instead.

	   \param mech the mechanism to be used.
	*/
	void putServerFirstStep(const QString &mech);

	/**
	   Process the first step in server mode (server)

	   Call this with the mechanism selected by the client, and initial
	   client data.  If there is no initial client data, call the other
	   version of this function instead.

	   \param mech the mechanism to be used
	   \param clientInit the initial data provided by the client side
	*/
	void putServerFirstStep(const QString &mech, const QByteArray &clientInit);

	/**
	   Process an authentication step

	   Call this with authentication data received from the network.
	   The only exception is the first step in server mode, in which
	   case putServerFirstStep must be called.

	   \param stepData the authentication data from the network
	*/
	void putStep(const QByteArray &stepData);

	/**
	   Return the mechanism selected (client)
	*/
	QString mechanism() const;

	/**
	   Return the mechanism list (server)
	*/
	QStringList mechanismList() const;

	/**
	   Return the realm list, if available (client)
	*/
	QStringList realmList() const;

	/**
	   Return the security strength factor of the connection
	*/
	int ssf() const;

	/**
	   Return the error code
	*/
	Error errorCode() const;

	/**
	   Return the reason for authentication failure
	*/
	AuthCondition authCondition() const;

	/**
	   Specify the username to use in authentication

	   \param user the username to use
	*/
	void setUsername(const QString &user);

	/**
	   Specify the authorization identity to use in authentication

	   \param auth the authorization identity to use
	*/
	void setAuthzid(const QString &auth);

	/**
	   Specify the password to use in authentication

	   \param pass the password to use
	*/
	void setPassword(const SecureArray &pass);

	/**
	   Specify the realm to use in authentication

	   \param realm the realm to use
	*/
	void setRealm(const QString &realm);

	/**
	   Continue negotiation after parameters have been set (client)
	*/
	void continueAfterParams();

	/**
	   Continue negotiation after auth ids have been checked (server)
	*/
	void continueAfterAuthCheck();

	// reimplemented
	virtual int bytesAvailable() const;
	virtual int bytesOutgoingAvailable() const;
	virtual void write(const QByteArray &a);
	virtual QByteArray read();
	virtual void writeIncoming(const QByteArray &a);
	virtual QByteArray readOutgoing(int *plainBytes = 0);
	virtual int convertBytesWritten(qint64 encryptedBytes);

Q_SIGNALS:
	/**
	   This signal is emitted when the client has been successfully
	   started

	   \param clientInit true if the client should send an initial
	   response to the server
	   \param clientInitData the initial response to send to the server.
	   Do note that there is a difference in SASL between an empty initial
	   response and no initial response, and so even if clientInitData is
	   an empty array, you still need to send an initial response if
	   clientInit is true.
	*/
	void clientStarted(bool clientInit, const QByteArray &clientInitData);

	/**
	   This signal is emitted after the server has been
	   successfully started
	*/
	void serverStarted();

	/**
	   This signal is emitted when there is data required
	   to be sent over the network to complete the next
	   step in the authentication process.

	   \param stepData the data to send over the network
	*/
	void nextStep(const QByteArray &stepData);

	/**
	   This signal is emitted when the client needs
	   additional parameters

	   After receiving this signal, the application should set 
	   the required parameter values appropriately and then call
	   continueAfterParams().

	   \param params the parameters that are required by the client
	*/
	void needParams(const QCA::SASL::Params &params);

	/**
	   This signal is emitted when the server needs to
	   perform the authentication check

	   If the user and authzid are valid, call continueAfterAuthCheck().

	   \param user the user identification name
	   \param authzid the user authorization name
	*/
	void authCheck(const QString &user, const QString &authzid);

	/**
	   This signal is emitted when authentication is complete.
	*/
	void authenticated();

private:
	Q_DISABLE_COPY(SASL)

	class Private;
	friend class Private;
	Private *d;
};

}

#endif
