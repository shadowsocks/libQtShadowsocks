/*
 * qca_keystore.h - Qt Cryptographic Architecture
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
   \file qca_keystore.h

   Header file for classes that provide and manage keys

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_KEYSTORE_H
#define QCA_KEYSTORE_H

#include "qca_core.h"
#include "qca_cert.h"

namespace QCA {

class KeyStoreTracker;
class KeyStoreManagerPrivate;
class KeyStorePrivate;

/**
   \class KeyStoreEntry qca_keystore.h QtCrypto

   Single entry in a KeyStore

   This is a container for any kind of object in a KeyStore
   (such as PGP keys, or X.509 certificates / private keys).

   KeyStoreEntry objects are obtained through KeyStore or loaded from a
   serialized string format.  The latter method requires a KeyStoreEntry
   obtained through KeyStore to be serialized for future loading.  For
   example:

   \code
QString str = someKeyStoreEntry.toString();
[ app saves str to disk ]
[ app quits ]
...
[ app launches ]
[ app reads str from disk ]
KeyStoreEntry entry(str);
printf("Entry name: [%s]\n", qPrintable(entry.name()));
   \endcode

   KeyStoreEntry objects may or may not be available.  An entry is
   unavailable if it has a private content that is not present.  The
   private content might exist on external hardware.  To determine if an
   entry is available, call isAvailable().  To ensure an entry is available
   before performing a private key operation, call ensureAvailable.  For
   example:

   \code
if(entry.ensureAvailable())
{
   entry.keyBundle().privateKey().signMessage(...);
   ...
}
   \endcode

   ensureAvailable() blocks and may cause hardware access, but
   if it completes successfully then you may use the entry's private
   content.  It also means, in the case of a Smart Card token, that
   it is probably inserted.

   To watch this entry asynchronously, you would do:

   \code
KeyStoreEntryWatcher *watcher = new KeyStoreEntryWatcher(entry);
connect(watcher, SIGNAL(available()), SLOT(entry_available()));
...
void entry_available()
{
   // entry now available
   watcher->entry().keyBundle().privateKey().signMessage(...);
}
   \endcode

   Unlike private content, public content is always usable even if the
   entry is not available.  Serialized entry data contains all of the
   metadata necessary to reconstruct the public content.

   Now, even though an entry may be available, it does not
   mean you have access to use it for operations.  For
   example, even though a KeyBundle entry offered by a Smart Card
   may be available, as soon as you try to use the PrivateKey object
   for a signing operation, a PIN might be asked for.  You can call
   ensureAccess() if you want to synchronously provide the PIN
   early on:

   \code
if(entry.ensureAccess())
{
   // do private key stuff
   ...
}
   \endcode

   Note that you don't have to call ensureAvailable() before
   ensureAccess().  Calling the latter is enough to imply
   both.

   After an application is configured to use a particular key,
   it is expected that its usual running procedure will be:

   1) Construct KeyStoreEntry from the serialized data.
   2) If the content object is not available, wait for it
   (with either ensureAvailable() or KeyStoreEntryWatcher).
   3) Pass the content object(s) to a high level operation like TLS.

   In this case, any PIN prompting and private key operations
   would be caused/handled from the TLS object.  Omit step 2 and
   the private key operations might cause token prompting.

   \ingroup UserAPI
*/
class QCA_EXPORT KeyStoreEntry : public Algorithm
{
public:
	/**
	   The type of entry in the KeyStore
	*/
	enum Type
	{
		TypeKeyBundle,
		TypeCertificate,
		TypeCRL,
		TypePGPSecretKey,
		TypePGPPublicKey
	};

	/**
	   Create an empty KeyStoreEntry
	*/
	KeyStoreEntry();

	/**
	   Create a passive KeyStoreEntry based on a serialized
	   string

	   \param serialized the string containing the keystore entry information

	   \sa fromString
	*/
	KeyStoreEntry(const QString &serialized);

	/**
	   Standard copy constructor

	   \param from the source entry
	*/
	KeyStoreEntry(const KeyStoreEntry &from);

	~KeyStoreEntry();

	/**
	   Standard assignment operator

	   \param from the source entry
	*/
	KeyStoreEntry & operator=(const KeyStoreEntry &from);

	/**
	   Test if this key is empty (null)
	*/
	bool isNull() const;

	/**
	   Test if the key is available for use.

	   A key is considered available if the key's private
	   content is present.

	   \sa ensureAvailable
	   \sa isAccessible
	*/
	bool isAvailable() const;

	/**
	   Test if the key is currently accessible.

	   This means that the private key part can be used
	   at this time. For a smartcard, this means that all
	   required operations (e.g. login / PIN entry) are
	   completed.

	   If isAccessible() is true, then the key
	   is necessarily available (i.e. isAvailable() is
	   also true).

	   \sa ensureAccessible
	   \sa isAvailable
	*/
	bool isAccessible() const;

	/**
	   Determine the type of key stored in this object 
	*/
	Type type() const;

	/**
	   The name associated with the key stored in this object
	*/
	QString name() const;

	/**
	   The ID associated with the key stored in this object.
	*/
	QString id() const;

	/**
	   The name of the KeyStore for this key object
	*/
	QString storeName() const;

	/**
	   The id of the KeyStore for this key object

	   \sa KeyStore::id()
	*/
	QString storeId() const;

	/**
	   Serialize into a string for use as a passive entry
	*/
	QString toString() const;

	/**
	   Load a passive entry by using a serialized string
	   as input

	   \param serialized the string containing the keystore entry information

	   \return the newly created KeyStoreEntry
	*/
	static KeyStoreEntry fromString(const QString &serialized);

	/**
	   If a KeyBundle is stored in this object, return that
	   bundle.
	*/
	KeyBundle keyBundle() const;

	/**
	   If a Certificate is stored in this object, return that
	   certificate.
	*/
	Certificate certificate() const;

	/**
	   If a CRL is stored in this object, return the value
	   of the CRL
	*/
	CRL crl() const;

	/**
	   If the key stored in this object is a private
	   PGP key, return the contents of that key.
	*/
	PGPKey pgpSecretKey() const;

	/**
	   If the key stored in this object is either an 
	   public or private PGP key, extract the public key
	   part of that PGP key.
	*/
	PGPKey pgpPublicKey() const;

	/**
	   Returns true if the entry is available, otherwise false.

	   Available means that any private content for this entry is
	   present and ready for use.  In the case of a smart card, this
	   will ensure the card is inserted, and may invoke a token
	   prompt.

	   Calling this function on an already available entry may cause
	   the entry to be refreshed.

	   \sa isAvailable
	   \sa ensureAccess

	   \note This function is blocking.
	   \note This synchronous operation may require event handling, and so
	   it must not be called from the same thread as an EventHandler.
	*/
	bool ensureAvailable();

	/**
	   Like ensureAvailable, but will also ensure
	   that the PIN is provided if needed.

	   \sa isAccessible
	   \sa ensureAvailable

	   \note This synchronous operation may require event handling, and so
	   it must not be called from the same thread as an EventHandler.
	*/
	bool ensureAccess();

private:
	class Private;
	Private *d;

	friend class KeyStoreTracker;
};

/**
   \class KeyStoreEntryWatcher qca_keystore.h QtCrypto

   Class to monitor the availability of a KeyStoreEntry

   Some KeyStore types have the concept of an entry that can be
   available only part of the time (for example, a smart card that
   can be removed). This class allows you to identify when a 
   KeyStoreEntry becomes available / unavailable.

   \note You can also monitor availability of a whole KeyStore,
   using KeyStoreManager::keyStoreAvailable() signal, and
   the KeyStore::unavailable() signal. 

   \sa KeyStore for more discussion on availability of 
   keys and related objects.

   \ingroup UserAPI
*/
class QCA_EXPORT KeyStoreEntryWatcher : public QObject
{
	Q_OBJECT
public:
	/**
	   Standard constructor.

	   This creates an object that monitors the specified KeyStore entry,
	   emitting available() and unavailable() as the entry becomes available
	   and unavailable respectively.

	   \param e the KeyStoreEntry to monitor
	   \param parent the parent object for this object
	*/
	explicit KeyStoreEntryWatcher(const KeyStoreEntry &e, QObject *parent = 0);

	~KeyStoreEntryWatcher();

	/**
	   The KeyStoreEntry that is being monitored
	*/
	KeyStoreEntry entry() const;

Q_SIGNALS:
	/**
	   This signal is emitted when the entry that is being monitored
	   becomes available.
	*/
	void available();

	/**
	   This signal is emitted when the entry that is being monitored
	   becomes unavailble.
	*/
	void unavailable();

private:
	Q_DISABLE_COPY(KeyStoreEntryWatcher)

	class Private;
	friend class Private;
	Private *d;
};

/**
   \class KeyStore qca_keystore.h QtCrypto

   General purpose key storage object

   Examples of use of this are:
    -  systemstore:          System TrustedCertificates
    -  accepted self-signed: Application TrustedCertificates
    -  apple keychain:       User Identities
    -  smartcard:            SmartCard Identities
    -  gnupg:                PGPKeyring Identities,PGPPublicKeys

    \note
    - there can be multiple KeyStore objects referring to the same id
    - when a KeyStore is constructed, it refers to a given id (deviceId)
    and internal contextId.  if the context goes away, the KeyStore
    becomes invalid (isValid() == false), and unavailable() is emitted.
    even if the device later reappears, the KeyStore remains invalid.
    a new KeyStore will have to be created to use the device again.

   \ingroup UserAPI
*/
class QCA_EXPORT KeyStore : public QObject, public Algorithm
{
	Q_OBJECT
public:
	/**
	   The type of keystore
	*/
	enum Type
	{
		System,      ///< objects such as root certificates
		User,        ///< objects such as Apple Keychain, KDE Wallet
		Application, ///< for caching accepted self-signed certificates
		SmartCard,   ///< for smartcards
		PGPKeyring   ///< for a PGP keyring
	};

	/**
	   Obtain a specific KeyStore

	   \param id the identification for the key store
	   \param keyStoreManager the parent manager for this keystore
	*/
	KeyStore(const QString &id, KeyStoreManager *keyStoreManager);

	~KeyStore();

	/**
	   Check if this KeyStore is valid

	   \return true if the KeyStore is valid
	*/
	bool isValid() const;

	/**
	   The KeyStore Type
	*/
	Type type() const;

	/**
	   The name associated with the KeyStore
	*/
	QString name() const;

	/**
	   The ID associated with the KeyStore
	*/
	QString id() const;

	/**
	   Test if the KeyStore is writeable or not

	   \return true if the KeyStore is read-only
	*/
	bool isReadOnly() const;

	/**
	   Turns on asynchronous mode for this KeyStore instance.

	   Normally, entryList() and writeEntry() are blocking
	   calls.  However, if startAsynchronousMode() is called,
	   then these functions will return immediately.  entryList()
	   will return with the latest known entries, or an empty
	   list if none are known yet (in this mode, updated() will
	   be emitted once the initial entries are known, even if the
	   store has not actually been altered).  writeEntry() will
	   always return an empty string, and the entryWritten()
	   signal indicates the result of a write.
	*/
	void startAsynchronousMode();

	/**
	   A list of the KeyStoreEntry objects in this store

	   \note This synchronous operation may require event handling, and so
	   it must not be called from the same thread as an EventHandler
	   (this is not a concern if asynchronous mode is enabled).

	   \sa startAsynchronousMode
	*/
	QList<KeyStoreEntry> entryList() const;

	/**
	   test if the KeyStore holds trusted certificates (and CRLs)
	*/
	bool holdsTrustedCertificates() const;

	/**
	   test if the KeyStore holds identities (eg KeyBundle or PGPSecretKey)
	*/
	bool holdsIdentities() const;

	/**
	   test if the KeyStore holds PGPPublicKey objects
	*/
	bool holdsPGPPublicKeys() const;

	/**
	   Add a entry to the KeyStore

	   Returns the entryId of the written entry or an empty
	   string on failure.

	   \param kb the KeyBundle to add to the KeyStore

	   \note This synchronous operation may require event handling, and so
	   it must not be called from the same thread as an EventHandler
	   (this is not a concern if asynchronous mode is enabled).

	   \sa startAsynchronousMode
	*/
	QString writeEntry(const KeyBundle &kb);

	/**
	   \overload

	   \param cert the Certificate to add to the KeyStore
	*/
	QString writeEntry(const Certificate &cert);

	/**
	   \overload

	   \param crl the CRL to add to the KeyStore
	*/
	QString writeEntry(const CRL &crl);

	/**
	   \overload

	   \param key the PGPKey to add to the KeyStore

	   \return a ref to the key in the keyring
	*/
	QString writeEntry(const PGPKey &key);

	/**
	   Delete the a specified KeyStoreEntry from this KeyStore

	   \param id the ID for the entry to be deleted

	   \note This synchronous operation may require event handling, and so
	   it must not be called from the same thread as an EventHandler
	   (this is not a concern if asynchronous mode is enabled).

	   \sa startAsynchronousMode
	*/
	bool removeEntry(const QString &id);

Q_SIGNALS:
	/**
	   Emitted when the KeyStore is changed

	   This occurs if entries are added, removed, or changed in this
	   KeyStore, including changes in entry availability.
	*/
	void updated();

	/**
	   Emitted when the KeyStore becomes unavailable
	*/
	void unavailable();

	/**
	   Emitted when an entry has been written, in asynchronous
	   mode.  

	   \param entryId is the newly written entry id on success,
	   or an empty string if the write failed.
	*/
	void entryWritten(const QString &entryId);

	/**
	   Emitted when an entry has been removed, in asynchronous
	   mode.  

	   \param success indicates if the removal succeeded (true) or not (false).
	*/
	void entryRemoved(bool success);

private:
	Q_DISABLE_COPY(KeyStore)

	friend class KeyStorePrivate;
	KeyStorePrivate *d;

	friend class KeyStoreManagerPrivate;
};

/**
   \class KeyStoreInfo qca_keystore.h QtCrypto

   Key store information, outside of a KeyStore object

   This class is used in conjunction with the Event class,
   and related classes such as PasswordAsker and TokenAsker,
   to describe the key store source of the Event.

   Each KeyStoreInfo represents a single KeyStore, and describes
   the type of store (e.g. smartcard or PGP keyring - see 
   KeyStore::Type), and a couple of names. The id() of a KeyStore
   is used to reference it, and is typically of the form 
   "qca-mystorename". The name() of a KeyStore is used to describe
   it (i.e. this is the "pretty" name to show the user), and is
   typically of the form "My Store Name".

   \ingroup UserAPI
*/
class QCA_EXPORT KeyStoreInfo
{
public:
	/**
	   Constructor.

	   \note This form of constructor for KeyStoreInfo
	   produces an object that does not describe any 
	   KeyStore, and isNull() will return true.
	*/
	KeyStoreInfo();

	/**
	   Standard constructor.

	   This builds a KeyStoreInfo object that descibes a
	   KeyStore.

	   \param type the type of KeyStore
	   \param id the identification of the KeyStore
	   \param name the descriptive name of the KeyStore
	*/
	KeyStoreInfo(KeyStore::Type type, const QString &id, const QString &name);

	/**
	   Copy constructor.

	   \param from the KeyStoreInfo to copy from
	*/
	KeyStoreInfo(const KeyStoreInfo &from);

	~KeyStoreInfo();

	/**
	   Assignment operator.

	   \param from the KeyStoreInfo to copy from
	*/
	KeyStoreInfo & operator=(const KeyStoreInfo &from);

	/**
	   Test if this object is valid

	   \return true if the object is not valid
	*/
	bool isNull() const;

	/**
	   The Type of KeyStore that this KeyStoreInfo object
	   describes.
	*/
	KeyStore::Type type() const;

	/**
	   The unique identification of the KeyStore that
	   this KeyStoreInfo object describes.
	*/
	QString id() const;

	/**
	   The descriptive name of the KeyStore that this
	   KeyStoreInfo object describes.
	*/
	QString name() const;

private:
	class Private;
	QSharedDataPointer<Private> d;
};

/**
   \class KeyStoreManager qca_keystore.h QtCrypto

   Access keystores, and monitor keystores for changes.

   Before you can access a KeyStore, you must create a
   KeyStoreManager. You then need to start()
   the KeyStoreManager, and either wait for the busyFinished()
   signal, or block using waitForBusyFinished().

   If you know the KeyStoreEntry that you need, you can
   use KeyStore passively, as described in the KeyStoreEntry
   documentation.

   \ingroup UserAPI
*/
class QCA_EXPORT KeyStoreManager : public QObject
{
	Q_OBJECT
public:
        /**
	   Create a new KeyStoreManager

	   \param parent the parent for this object
	*/
	KeyStoreManager(QObject *parent = 0);
	~KeyStoreManager();

	/**
	   Initialize all key store providers
	*/
	static void start();

	/**
	   Initialize a specific key store provider

	   \param provider the name of the provider to start
	*/
	static void start(const QString &provider);

	/**
	   Indicates if the manager is busy looking for key stores
	*/
	bool isBusy() const;

	/**
	   Blocks until the manager is done looking for key stores
	*/
	void waitForBusyFinished();

	/**
	   A list of all the key stores
	*/
	QStringList keyStores() const;

	/**
	   The diagnostic result of key store operations, such as
	   warnings and errors
	*/
	static QString diagnosticText();

	/**
	   Clears the diagnostic result log
	*/
	static void clearDiagnosticText();

	/**
	   If you are not using the eventloop, call this to update
	   the object state to the present
	*/
	void sync();

Q_SIGNALS:
	/**
	   emitted when the manager has started looking for key stores
	*/
	void busyStarted();

	/**
	   emitted when the manager has finished looking for key stores
	*/
	void busyFinished();

	/**
	   emitted when a new key store becomes available

	   \param id the name of the key store that has become available
	*/
	void keyStoreAvailable(const QString &id);

private:
	Q_DISABLE_COPY(KeyStoreManager)

	friend class KeyStoreManagerPrivate;
	KeyStoreManagerPrivate *d;

	friend class Global;
	friend class KeyStorePrivate;

	static void scan();
	static void shutdown();
};

}

#endif
