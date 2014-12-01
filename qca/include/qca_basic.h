/*
 * qca_basic.h - Qt Cryptographic Architecture
 * Copyright (C) 2003-2007  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004-2007  Brad Hards <bradh@frogmouth.net>
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
   \file qca_basic.h

   Header file for classes for cryptographic primitives (basic operations).

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_BASIC_H
#define QCA_BASIC_H

#include "qca_core.h"

// Qt5 comes with QStringLiteral for wrapping string literals, which Qt4 does
// not have. It is needed if the headers are built with QT_NO_CAST_FROM_ASCII.
// Defining it here as QString::fromUtf8 for convenience.
#ifndef QStringLiteral
#define QStringLiteral(str) QString::fromUtf8(str)
#endif

namespace QCA {

/**
   \defgroup UserAPI QCA user API

   This is the main set of QCA classes, intended for use
   in standard applications.
*/

/**
   \class Random qca_basic.h QtCrypto

   Source of random numbers.

   QCA provides a built in source of random numbers, which
   can be accessed through this class. You can also use
   an alternative random number source, by implementing
   another provider.

   The normal use of this class is expected to be through the
   static members - randomChar(), randomInt() and randomArray().

   \ingroup UserAPI
 */
class QCA_EXPORT Random : public Algorithm
{
public:
	/**
	   Standard Constructor

	   \param provider the name of the provider library for the random
           number generation
	*/
	Random(const QString &provider = QString());

	/**
	   Copy constructor

	   \param from the %Random object to copy from
        */
	Random(const Random &from);

	~Random();

        /**
	   Assignment operator

	   \param from the %Random object to copy state from
        */
	Random & operator=(const Random &from);

	/**
	   Provide a random byte.

	   This method isn't normally required - you should use
	   the static randomChar() method instead.

	   \sa randomChar
	*/
	uchar nextByte();

	/**
	   Provide a specified number of random bytes.

	   This method isn't normally required - you should use
	   the static randomArray() method instead.

	   \param size the number of bytes to provide

	   \sa randomArray
	*/
	SecureArray nextBytes(int size);

	/**
	   Provide a random character (byte)

	   This is the normal way of obtaining a single random char
	   (ie. 8 bit byte), as shown below:
	   \code
myRandomChar = QCA::Random::randomChar();
	   \endcode

	   If you need a number of bytes, perhaps randomArray() may be of use.
	*/
	static uchar randomChar();

	/**
	   Provide a random integer.

	   This is the normal way of obtaining a single random integer,
	   as shown below:
	   \code
myRandomInt = QCA::Random::randomInt();
	   \endcode
	*/
	static int randomInt();

	/**
	   Provide a specified number of random bytes.

	   \code
// build a 30 byte secure array.
SecureArray arry = QCA::Random::randomArray(30);
	   \endcode

	   \param size the number of bytes to provide
	*/
	static SecureArray randomArray(int size);

private:
	class Private;
	Private *d;
};

/**
   \class Hash qca_basic.h QtCrypto

   General class for hashing algorithms.

   Hash is the class for the various hashing algorithms
   within %QCA. SHA256, SHA1 or RIPEMD160 are recommended for
   new applications, although MD2, MD4, MD5 or SHA0 may be
   applicable (for interoperability reasons) for some
   applications.

   To perform a hash, you create a Hash object, call update()
   with the data that needs to be hashed, and then call
   final(), which returns a QByteArray of the hash result. An
   example (using the SHA1 hash, with 1000 updates of a 1000
   byte string) is shown below:

   \code
if(!QCA::isSupported("sha1"))
	printf("SHA1 not supported!\n");
else
{
	QByteArray fillerString;
	fillerString.fill('a', 1000);

	QCA::Hash shaHash("sha1");
	for (int i=0; i<1000; i++)
		shaHash.update(fillerString);
	QByteArray hashResult = shaHash.final();
	if ( "34aa973cd4c4daa4f61eeb2bdbad27316534016f" == QCA::arrayToHex(hashResult) )
	{
		printf("big SHA1 is OK\n");
	}
	else
	{
		printf("big SHA1 failed\n");
	}
}
   \endcode

   If you only have a simple hash requirement - a single
   string that is fully available in memory at one time - then
   you may be better off with one of the convenience
   methods. So, for example, instead of creating a QCA::Hash
   object, then doing a single update() and the final() call;
   you could simply call QCA::Hash("algoName").hash() with the
   data that you would otherwise have provided to the update()
   call.

   For more information on hashing algorithms, see \ref hashing.

   \ingroup UserAPI
*/
class QCA_EXPORT Hash : public Algorithm, public BufferedComputation
{
public:
	/**
	   Constructor

	   \param type label for the type of hash to be
	   created (for example, "sha1" or "md2")
	   \param provider the name of the provider plugin
	   for the subclass (eg "qca-ossl")
	*/
	explicit Hash(const QString &type, const QString &provider = QString());

	/**
	   Copy constructor

	   \param from the Hash object to copy from
        */
	Hash(const Hash &from);

	~Hash();

	/**
	   Assignment operator

	   \param from the Hash object to copy state from
        */
	Hash & operator=(const Hash &from);

	/**
	   Returns a list of all of the hash types available

	   \param provider the name of the provider to get a list from, if one
	   provider is required. If not specified, available hash types from all
	   providers will be returned.
	*/
	static QStringList supportedTypes(const QString &provider = QString());

	/**
	   Return the hash type
	*/
	QString type() const;

	/**
	   Reset a hash, dumping all previous parts of the
	   message.

	   This method clears (or resets) the hash algorithm,
	   effectively undoing any previous update()
	   calls. You should use this call if you are re-using
	   a Hash sub-class object to calculate additional
	   hashes.
	*/
	virtual void clear();

	/**
	   Update a hash, adding more of the message contents
	   to the digest. The whole message needs to be added
	   using this method before you call final().

	   If you find yourself only calling update() once,
	   you may be better off using a convenience method
	   such as hash() or hashToString() instead.

	   \param a the byte array to add to the hash
	*/
	virtual void update(const MemoryRegion &a);

	/**
	   \overload

	   \param a the QByteArray to add to the hash
	*/
	void update(const QByteArray &a);

	/**
	   \overload

	   This method is provided to assist with code that
	   already exists, and is being ported to %QCA. You are
	   better off passing a SecureArray (as shown above)
	   if you are writing new code.

	   \param data pointer to a char array
	   \param len the length of the array. If not specified
	   (or specified as a negative number), the length will be
	   determined with strlen(), which may not be what you want
	   if the array contains a null (0x00) character.
	*/
	void update(const char *data, int len = -1);

	/**
	   \overload

	   This allows you to read from a file or other
	   I/O device. Note that the device must be already
	   open for reading

	   \param file an I/O device

	   If you are trying to calculate the hash of
	   a whole file (and it isn't already open), you
	   might want to use code like this:
	   \code
QFile f( "file.dat" );
if ( f.open( QIODevice::ReadOnly ) )
{
	QCA::Hash hashObj("sha1");
	hashObj.update( &f );
	QByteArray output = hashObj.final().toByteArray();
}
	   \endcode
	*/
	void update(QIODevice *file);

	/**
	   Finalises input and returns the hash result

	   After calling update() with the required data, the
	   hash results are finalised and produced.

	   Note that it is not possible to add further data (with
	   update()) after calling final(), because of the way
	   the hashing works - null bytes are inserted to pad
	   the results up to a fixed size. If you want to
	   reuse the Hash object, you should call clear() and
	   start to update() again.
	*/
	virtual MemoryRegion final();

	/**
	   %Hash a byte array, returning it as another
	   byte array

	   This is a convenience method that returns the
	   hash of a SecureArray.

	   \code
SecureArray sampleArray(3);
sampleArray.fill('a');
SecureArray outputArray = QCA::Hash("md2")::hash(sampleArray);
	   \endcode

	   \param array the QByteArray to hash

	   If you need more flexibility (e.g. you are constructing
	   a large byte array object just to pass it to hash(), then
	   consider creating an Hash object, and then calling
	   update() and final().
	*/
	MemoryRegion hash(const MemoryRegion &array);

	/**
	   %Hash a byte array, returning it as a printable
	   string

	   This is a convenience method that returns the
	   hash of a SecureArray as a hexadecimal
	   representation encoded in a QString.

	   \param array the QByteArray to hash

	   If you need more flexibility, you can create a Hash
	   object, call Hash::update() as required, then call 
	   Hash::final(), before using the static arrayToHex() method.
	*/
	QString hashToString(const MemoryRegion &array);

private:
	class Private;
	Private *d;
};

/**
   \page hashing Hashing Algorithms

   There are a range of hashing algorithms available in
   %QCA. Hashing algorithms are used with the Hash and
   MessageAuthenticationCode classes.

   The MD2 algorithm takes an arbitrary data stream, known as the
   message and outputs a condensed 128 bit (16 byte)
   representation of that data stream, known as the message
   digest. This algorithm is considered slightly more secure than MD5,
   but is more expensive to compute. Unless backward
   compatibility or interoperability are considerations, you
   are better off using the SHA1 or RIPEMD160 hashing algorithms.
   For more information on %MD2, see B. Kalinski RFC1319 "The %MD2
   Message-Digest Algorithm". The label for MD2 is "md2".

   The MD4 algorithm takes an arbitrary data stream, known as the
   message and outputs a condensed 128 bit (16 byte)
   representation of that data stream, known as the message
   digest. MD4 is not considered to be secure, based on
   known attacks. It should only be used for applications where
   collision attacks are not a consideration (for example, as
   used in the rsync algorithm for fingerprinting blocks of
   data). If a secure hash is required, you are better off using
   the SHA1 or RIPEMD160 hashing algorithms. MD2 and MD5 are both
   stronger 128 bit hashes.  For more information on MD4, see
   R. Rivest RFC1320 "The %MD4 Message-Digest Algorithm". The
   label for MD4 is "md4".

   The MD5 takes an arbitrary data stream, known as the message
   and outputs a condensed 128 bit (16 byte) representation of
   that data stream, known as the message digest. MD5 is not
   considered to be secure, based on known attacks. It should
   only be used for applications where collision attacks are not
   a consideration. If a secure hash is required, you are better
   off using the SHA1 or RIPEMD160 hashing algorithms.  For more
   information on MD5, see R. Rivest RFC1321 "The %MD5
   Message-Digest Algorithm". The label for MD5 is "md5".

   The RIPEMD160 algorithm takes an arbitrary data stream, known
   as the message (up to \f$2^{64}\f$ bits in length) and outputs
   a condensed 160 bit (20 byte) representation of that data
   stream, known as the message digest. The RIPEMD160 algorithm
   is considered secure in that it is considered computationally
   infeasible to find the message that produced the message
   digest. The label for RIPEMD160 is "ripemd160".

   The SHA-0 algorithm is a 160 bit hashing function, no longer
   recommended for new applications because of known (partial)
   attacks against it. The label for SHA-0 is "sha0".

   The SHA-1 algorithm takes an arbitrary data stream, known as
   the message (up to \f$2^{64}\f$ bits in length) and outputs a
   condensed 160 bit (20 byte) representation of that data
   stream, known as the message digest. SHA-1 is considered
   secure in that it is considered computationally infeasible to
   find the message that produced the message digest. For more
   information on the SHA-1 algorithm,, see Federal Information
   Processing Standard Publication 180-2 "Specifications for the
   Secure %Hash Standard", available from
   http://csrc.nist.gov/publications/. The label for SHA-1 is
   "sha1".

   The SHA-224 algorithm takes an arbitrary data stream, known as
   the message (up to \f$2^{64}\f$ bits in length) and outputs a
   condensed 224 bit (28 byte) representation of that data
   stream, known as the message digest. SHA-224 is a "cut down"
   version of SHA-256, and you may be better off using SHA-256 in
   new designs. The SHA-224 algorithm is considered secure in
   that it is considered computationally infeasible to find the
   message that produced the message digest. For more information
   on SHA-224, see Federal Information Processing Standard
   Publication 180-2 "Specifications for the Secure %Hash
   Standard", with change notice 1, available from
   http://csrc.nist.gov/publications/. The label for SHA-224 is
   "sha224".

   The SHA-256 algorithm takes an arbitrary data stream, known as
   the message (up to \f$2^{64}\f$ bits in length) and outputs a
   condensed 256 bit (32 byte) representation of that data
   stream, known as the message digest. The SHA-256 algorithm is
   considered secure in that it is considered computationally
   infeasible to find the message that produced the message
   digest. For more information on SHA-256, see Federal
   Information Processing Standard Publication 180-2
   "Specifications for the Secure %Hash Standard", available from
   http://csrc.nist.gov/publications/. The label for SHA-256 is
   "sha256".

   The SHA-384 algorithm takes an arbitrary data stream, known as
   the message (up to \f$2^{128}\f$ bits in length) and outputs a
   condensed 384 bit (48 byte) representation of that data
   stream, known as the message digest. The SHA-384 algorithm is
   a "cut down" version of SHA-512, and you may be better off
   using SHA-512 in new designs. The SHA-384 algorithm is
   considered secure in that it is considered computationally
   infeasible to find the message that produced the message
   digest. For more information on SHA-384, see Federal
   Information Processing Standard Publication 180-2
   "Specifications for the Secure %Hash Standard", available from
   http://csrc.nist.gov/publications/. The label for SHA-384 is
   "sha384".

   The SHA-512 algorithm takes an arbitrary data stream, known as
   the message (up to \f$2^{128}\f$ bits in length) and outputs a
   condensed 512 bit (64 byte) representation of that data
   stream, known as the message digest. The SHA-512 algorithm is
   considered secure in that it is considered computationally
   infeasible to find the message that produced the message
   digest. For more information on SHA-512, see Federal
   Information Processing Standard Publication 180-2
   "Specifications for the Secure %Hash Standard", available from
   http://csrc.nist.gov/publications/. The label for SHA-512 is
   "sha512".

   The Whirlpool algorithm takes an arbitrary data stream, known as
   the message (up to \f$2^{256}\f$ bits in length) and outputs a
   condensed 512 bit (64 byte) representation of that data
   stream, known as the message digest. The Whirlpool algorithm is
   considered secure in that it is considered computationally
   infeasible to find the message that produced the message
   digest. For more information on Whirlpool, see 
   http://paginas.terra.com.br/informatica/paulobarreto/WhirlpoolPage.html
   or ISO/IEC 10118-3:2004. The label for Whirlpool is
   "whirlpool".
*/

/**
   \page paddingDescription Padding

   For those Cipher sub-classes that are block based, there are modes
   that require a full block on encryption and decryption - %Cipher Block
   Chaining mode and Electronic Code Book modes are good examples.

   Since real world messages are not always a convenient multiple of a
   block size, we have to adding <i>padding</i>. There are a number of
   padding modes that %QCA supports, including not doing any padding
   at all.

   If you are not going to use padding, then you can pass 
   QCA::Cipher::NoPadding as the pad argument to the Cipher sub-class,
   however it is then your responsibility to pass in appropriate data for
   the mode that you are using.

   The most common padding scheme is known as PKCS#7 (also PKCS#1), and
   it specifies that the pad bytes are all equal to the length of the 
   padding ( for example, if you need three pad bytes to complete the block,
   then the padding is 0x03 0x03 0x03 ).

   On encryption, for algorithm / mode combinations that require
   padding, you will get a block of ciphertext when the input plain
   text block is complete. When you call final(), you will get out the
   ciphertext that corresponds to the last part of the plain text,
   plus any padding. If you had provided plaintext that matched up
   with a block size, then the cipher text block is generated from
   pure padding - you always get at least some padding, to ensure that
   the padding can be safely removed on decryption.

   On decryption, for algorithm / mode combinations that use padding,
   you will get back a block of plaintext when the input ciphertext block
   is complete. When you call final(), you will get a block that has been
   stripped of ciphertext.
*/

/**
   \class Cipher qca_basic.h QtCrypto

   General class for cipher (encryption / decryption) algorithms.

   Cipher is the class for the various algorithms that perform
   low level encryption and decryption within %QCA.

   AES128, AES192 and AES256 are recommended for new applications.

   Standard names for ciphers are:
   - Blowfish - "blowfish"
   - TripleDES - "tripledes"
   - DES - "des"
   - AES128 - "aes128"
   - AES192 - "aes192"
   - AES256 - "aes256"
   - CAST5 (CAST-128) - "cast5"

   When checking for the availability of a particular kind
   of cipher operation (e.g. AES128 in CBC mode with PKCS7
   padding), you append the mode and padding type (in that
   example "aes128-cbc-pkcs7"). CFB and OFB modes don't use
   padding, so they are always just the cipher name followed
   by the mode (e.g. "blowfish-cfb" or "aes192-ofb"). If
   you are not using padding with CBC mode (i.e. you are
   ensuring block size operations yourself), just use 
   the cipher name followed by "-cbc" (e.g. "blowfish-cbc"
   or "aes256-cbc"). 

   \ingroup UserAPI
*/
class QCA_EXPORT Cipher : public Algorithm, public Filter
{
public:
	/**
	   Mode settings for cipher algorithms.

	   \note ECB is almost never what you want, unless you
	   are trying to implement a %Cipher variation that is not
	   supported by %QCA.
	*/
	enum Mode
	{
		CBC, ///< operate in %Cipher Block Chaining mode
		CFB, ///< operate in %Cipher FeedBack mode
		ECB, ///< operate in Electronic Code Book mode
		OFB, ///< operate in Output FeedBack Mode
		CTR, ///< operate in CounTer Mode
	};

	/**
	   Padding variations for cipher algorithms.

	   See the \ref paddingDescription description for more details on
	   padding schemes.
	*/
	enum Padding
	{
		DefaultPadding, ///< Default for cipher-mode
		NoPadding,      ///< Do not use padding
		PKCS7           ///< Pad using the scheme in PKCS#7
	};

	/**
	   Standard constructor

	   \param type the name of the cipher specialisation to use (e.g.
	   "aes128")
	   \param mode the operating Mode to use (e.g. QCA::Cipher::CBC)
	   \param pad the type of Padding to use
	   \param dir the Direction that this Cipher should use (Encode for
	   encryption, Decode for decryption)
	   \param key the SymmetricKey array that is the key
	   \param iv the InitializationVector to use (not used for ECB mode)
	   \param provider the name of the Provider to use

	   \note Padding only applies to CBC and ECB modes.  CFB and OFB
	   ciphertext is always the length of the plaintext.
	*/
	Cipher(const QString &type, Mode mode, Padding pad = DefaultPadding,
		Direction dir = Encode, const SymmetricKey &key = SymmetricKey(), 
		const InitializationVector &iv = InitializationVector(),
		const QString &provider = QString());

	/**
	   Standard copy constructor

	   \param from the Cipher to copy state from
	*/
	Cipher(const Cipher &from);

	~Cipher();

	/**
	   Assignment operator

	   \param from the Cipher to copy state from
	*/
	Cipher & operator=(const Cipher &from);

	/**
	   Returns a list of all of the cipher types available

	   \param provider the name of the provider to get a list from, if one
	   provider is required. If not specified, available cipher types from all
	   providers will be returned.
	*/
	static QStringList supportedTypes(const QString &provider = QString());

	/**
	   Return the cipher type
	*/
	QString type() const;

	/**
	   Return the cipher mode
	*/
	Mode mode() const;

	/**
	   Return the cipher padding type
	*/
	Padding padding() const;

	/**
	   Return the cipher direction
	*/
	Direction direction() const;

	/**
	   Return acceptable key lengths
	*/
	KeyLength keyLength() const;

	/**
	   Test if a key length is valid for the cipher algorithm

	   \param n the key length in bytes
	   \return true if the key would be valid for the current algorithm
	*/
	bool validKeyLength(int n) const;

	/**
	   return the block size for the cipher object
	*/
	int blockSize() const;

	/**
	   reset the cipher object, to allow re-use
	*/
	virtual void clear();

	/**
	   pass in a byte array of data, which will be encrypted or decrypted
	   (according to the Direction that was set in the constructor or in
	   setup() ) and returned.

	   \param a the array of data to encrypt / decrypt
	*/
	virtual MemoryRegion update(const MemoryRegion &a);

	/**
	   complete the block of data, padding as required, and returning
	   the completed block
	*/
	virtual MemoryRegion final();

	/**
	   Test if an update() or final() call succeeded.

	   \return true if the previous call succeeded
	*/
	virtual bool ok() const;

	/**
	   Reset / reconfigure the Cipher

	   You can use this to re-use an existing Cipher, rather than creating
	   a new object with a slightly different configuration.

	   \param dir the Direction that this Cipher should use (Encode for
	   encryption, Decode for decryption)
	   \param key the SymmetricKey array that is the key
	   \param iv the InitializationVector to use (not used for ECB Mode)

	   \note You should not leave iv empty for any Mode except ECB.
	*/
	void setup(Direction dir, const SymmetricKey &key, const InitializationVector &iv = InitializationVector());

	/**
	   Construct a Cipher type string

	   \param cipherType the name of the algorithm (eg AES128, DES)
	   \param modeType the mode to operate the cipher in (eg QCA::CBC,
	   QCA::CFB)
	   \param paddingType the padding required (eg QCA::NoPadding,
	   QCA::PCKS7)
	*/
	static QString withAlgorithms(const QString &cipherType, Mode modeType, Padding paddingType);

private:
	class Private;
	Private *d;
};

/**
   \class MessageAuthenticationCode  qca_basic.h QtCrypto

   General class for message authentication code (MAC) algorithms.

   MessageAuthenticationCode is a class for accessing the various 
   message authentication code algorithms within %QCA.
   HMAC using SHA1 ("hmac(sha1)") or HMAC using SHA256 ("hmac(sha256)")
   is recommended for new applications.

   Note that if your application is potentially susceptable to "replay
   attacks" where the message is sent more than once, you should include a
   counter in the message that is covered by the MAC, and check that the
   counter is always incremented every time you receive a message and MAC.

   For more information on HMAC, see H. Krawczyk et al. RFC2104 
   "HMAC: Keyed-Hashing for Message Authentication"

   \ingroup UserAPI
*/
class QCA_EXPORT MessageAuthenticationCode : public Algorithm, public BufferedComputation
{
public:
	/**
	   Standard constructor

	   \param type the name of the MAC (and algorithm, if applicable) to
	   use
	   \param key the shared key
	   \param provider the provider to use, if a particular provider is
	   required
	*/
	MessageAuthenticationCode(const QString &type, const SymmetricKey &key, const QString &provider = QString());

	/**
	   Standard copy constructor

	   Copies the state (including key) from one MessageAuthenticationCode
	   to another

	   \param from the MessageAuthenticationCode to copy state from
	*/
	MessageAuthenticationCode(const MessageAuthenticationCode &from);

	~MessageAuthenticationCode();

	/**
	   Assignment operator.

	   Copies the state (including key) from one MessageAuthenticationCode
	   to another

	   \param from the MessageAuthenticationCode to assign from.
	*/
	MessageAuthenticationCode & operator=(const MessageAuthenticationCode &from);

	/**
	   Returns a list of all of the message authentication code types
	   available

	   \param provider the name of the provider to get a list from, if one
	   provider is required. If not specified, available message authentication
	   codes types from all providers will be returned.
	*/
	static QStringList supportedTypes(const QString &provider = QString());

	/**
	   Return the MAC type
	*/
	QString type() const;

	/**
	   Return acceptable key lengths
	*/
	KeyLength keyLength() const;

	/**
	   Test if a key length is valid for the MAC algorithm

	   \param n the key length in bytes
	   \return true if the key would be valid for the current algorithm
	*/
	bool validKeyLength(int n) const;

	/**
	   Reset a MessageAuthenticationCode, dumping all
	   previous parts of the message.

	   This method clears (or resets) the algorithm,
	   effectively undoing any previous update()
	   calls. You should use this call if you are re-using
	   a %MessageAuthenticationCode sub-class object
	   to calculate additional MACs. Note that if the key
	   doesn't need to be changed, you don't need to call
	   setup() again, since the key can just be reused.
	*/
	virtual void clear();

	/**
	   Update the MAC, adding more of the message contents
	   to the digest. The whole message needs to be added
	   using this method before you call final().

	   \param array the message contents
	*/
	virtual void update(const MemoryRegion &array);

	/**
	   Finalises input and returns the MAC result

	   After calling update() with the required data, the
	   hash results are finalised and produced.

	   Note that it is not possible to add further data (with
	   update()) after calling final(). If you want to
	   reuse the %MessageAuthenticationCode object, you
	   should call clear() and start to update() again.
	*/
	virtual MemoryRegion final();

	/**
	   Initialise the MAC algorithm

	   \param key the key to use for the algorithm
	*/
	void setup(const SymmetricKey &key);

private:
	class Private;
	Private *d;
};

/**
   \class KeyDerivationFunction  qca_basic.h QtCrypto

   General superclass for key derivation algorithms.

   %KeyDerivationFunction is a superclass for the various 
   key derivation function algorithms within %QCA. You should
   not need to use it directly unless you are
   adding another key derivation capability to %QCA - you should be
   using a sub-class. PBKDF2 using SHA1 is recommended for new applications.

   \ingroup UserAPI

*/
class QCA_EXPORT KeyDerivationFunction : public Algorithm
{
public:
	/**
	   Standard copy constructor

	   \param from the KeyDerivationFunction to copy from
	*/
	KeyDerivationFunction(const KeyDerivationFunction &from);

	~KeyDerivationFunction();

	/**
	   Assignment operator

	   Copies the state (including key) from one KeyDerivationFunction
	   to another

	   \param from the KeyDerivationFunction to assign from
	*/
	KeyDerivationFunction & operator=(const KeyDerivationFunction &from);

	/**
	   Generate the key from a specified secret and salt value

	   \note key length is ignored for some functions

	   \param secret the secret (password or passphrase)
	   \param salt the salt to use
	   \param keyLength the length of key to return
	   \param iterationCount the number of iterations to perform

	   \return the derived key
	*/
	SymmetricKey makeKey(const SecureArray &secret, const InitializationVector &salt, unsigned int keyLength, unsigned int iterationCount);

	/**
	   Generate the key from a specified secret and salt value

	   \note key length is ignored for some functions

	   \param secret the secret (password or passphrase)
	   \param salt the salt to use
	   \param keyLength the length of key to return
	   \param msecInterval the maximum time to compute the key, in milliseconds
	   \param iterationCount a pointer to store the number of iteration done for the specified time

	   \return the derived key
	*/
	SymmetricKey makeKey(const SecureArray &secret,
						 const InitializationVector &salt,
						 unsigned int keyLength,
						 int msecInterval,
						 unsigned int *iterationCount);

	/**
	   Construct the name of the algorithm

	   You can use this to build a standard name string.
	   You probably only need this method if you are 
	   creating a new subclass.

	   \param kdfType the type of key derivation function
	   \param algType the name of the algorithm to use with the key derivation function

	   \return the name of the KDF/algorithm pair
	*/
	static QString withAlgorithm(const QString &kdfType, const QString &algType);

protected:
	/**
	   Special constructor for subclass initialisation

	   \param type the algorithm to create
	   \param provider the name of the provider to create the key derivation function in.
	*/
	KeyDerivationFunction(const QString &type, const QString &provider);

private:
	class Private;
	Private *d;
};

/**
   \class PBKDF1 qca_basic.h QtCrypto

   Password based key derivation function version 1

   This class implements Password Based Key Derivation Function version 1,
   as specified in RFC2898, and also in PKCS#5.

   \ingroup UserAPI
*/
class QCA_EXPORT PBKDF1 : public KeyDerivationFunction
{
public:
	/**
	   Standard constructor

	   \param algorithm the name of the hashing algorithm to use
	   \param provider the name of the provider to use, if available
	*/
	explicit PBKDF1(const QString &algorithm = QStringLiteral("sha1"), const QString &provider = QString())
		: KeyDerivationFunction(withAlgorithm(QStringLiteral("pbkdf1"), algorithm), provider) {}
};

/**
   \class PBKDF2 qca_basic.h QtCrypto

   Password based key derivation function version 2

   This class implements Password Based Key Derivation Function version 2,
   as specified in RFC2898, and also in PKCS#5.

   \ingroup UserAPI
*/
class QCA_EXPORT PBKDF2 : public KeyDerivationFunction
{
public:
	/**
	   Standard constructor

	   \param algorithm the name of the hashing algorithm to use
	   \param provider the name of the provider to use, if available
	*/
	explicit PBKDF2(const QString &algorithm = QStringLiteral("sha1"), const QString &provider = QString())
		: KeyDerivationFunction(withAlgorithm(QStringLiteral("pbkdf2"), algorithm), provider) {}
};

}

#endif
