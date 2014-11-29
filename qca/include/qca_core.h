/*
 * qca_core.h - Qt Cryptographic Architecture
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
   \file qca_core.h

   Header file for core %QCA infrastructure

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_CORE_H
#define QCA_CORE_H

#include <QString>
#include <QStringList>
#include <QList>
#include <QSharedData>
#include <QSharedDataPointer>
#include "qca_export.h"
#include "qca_support.h"
#include "qca_tools.h"
#include "qca_version.h"

/**
   The current version of %QCA.

   This is equivalent to ::QCA_VERSION, except it provides
   a runtime check of the version of %QCA that is being used.
*/
QCA_EXPORT int qcaVersion();

/**
   The current version of %QCA.

   This is equivalent to ::QCA_VERSION_STR, except it provides
   a runtime check of the version of %QCA that is being used.
*/
QCA_EXPORT const char *qcaVersionStr();

/**
   The current version of %QCA.

   This is equivalent to ::QCA_MAJOR_VERSION, except it provides
   a runtime check of the version of %QCA that is being used.
*/
QCA_EXPORT int qcaMajorVersion();

/**
   The current version of %QCA.

   This is equivalent to ::QCA_MINOR_VERSION, except it provides
   a runtime check of the version of %QCA that is being used.
*/
QCA_EXPORT int qcaMinorVersion();

/**
   The current version of %QCA.

   This is equivalent to ::QCA_PATCH_VERSION, except it provides
   a runtime check of the version of %QCA that is being used.
*/
QCA_EXPORT int qcaPatchVersion();

/**
   QCA - the Qt Cryptographic Architecture
*/
namespace QCA {

class Provider;
class Random;
class CertificateCollection;
class Global;
class KeyStore;
class KeyStoreEntry;
class KeyStoreInfo;
class KeyStoreManager;
class Logger;

/**
   Convenience representation for the plugin providers

   You can get a list of providers using the providers()
   function

   \sa ProviderListIterator
   \sa providers()
*/
typedef QList<Provider*> ProviderList;

/**
   Mode settings for memory allocation

   QCA can use secure memory, however most operating systems
   restrict the amount of memory that can be pinned by user
   applications, to prevent a denial-of-service attack. 

   QCA supports two approaches to getting memory - the mlock
   method, which generally requires root (administrator) level
   privileges, and the mmap method which is not as secure, but
   which should be able to be used by any process.

   \sa Initializer
*/
enum MemoryMode
{
	Practical, ///< mlock and drop root if available, else mmap
	Locking, ///< mlock and drop root
	LockingKeepPrivileges ///< mlock, retaining root privileges
};

/**
   Direction settings for symmetric algorithms

   For some algorithms, it makes sense to have a "direction", such
   as Cipher algorithms which can be used to encrypt or decrypt.
*/
enum Direction
{
	Encode, ///< Operate in the "forward" direction; for example, encrypting
	Decode  ///< Operate in the "reverse" direction; for example, decrypting
};

/**
   Initialise %QCA.
   This call is not normally required, because it is cleaner
   to use an Initializer.
*/
QCA_EXPORT void init();

/**
   \overload

   \param m the MemoryMode to use
   \param prealloc the amount of memory in kilobytes to allocate
   for secure storage
*/
QCA_EXPORT void init(MemoryMode m, int prealloc);

/**
   Clean up routine

   This routine cleans up %QCA, including memory allocations
   This call is not normally required, because it is cleaner
   to use an Initializer
*/
QCA_EXPORT void deinit();

/**
   Test if secure storage memory is available

  \return true if secure storage memory is available
*/
QCA_EXPORT bool haveSecureMemory();

/**
   Test if secure random is available

   Secure random is considered available if the global random
   provider is not the default provider.

  \return true if secure random is available
*/
QCA_EXPORT bool haveSecureRandom();

/**
   Test if a capability (algorithm) is available.

   Since capabilities are made available at runtime, you
   should always check before using a capability the first
   time, as shown below.
   \code
QCA::init();
if(!QCA::isSupported("sha1"))
	printf("SHA1 not supported!\n");
else
{
	QString result = QCA::SHA1::hashToString(myString);
	printf("sha1(\"%s\") = [%s]\n", myString.data(), qPrintable(result));
}
   \endcode

   \param features the name of the capability to test for
   \param provider if specified, only check for the capability in that
   specific provider. If not provided, or provided as an empty
   string, then check for capabilities in all available providers
   \return true if the capability is available, otherwise false

   Note that you can test for a combination of capabilities,
   using a comma delimited list:
   \code
QCA::isSupported("sha1,md5"):
   \endcode
   which will return true if all of the capabilities listed
   are present.
*/
QCA_EXPORT bool isSupported(const char *features, const QString &provider = QString());

/**
   \overload

   \param features a list of features to test for
   \param provider if specified, only check for the capability in that
   specific provider. If not provided, or provided as an empty
   string, then check for capabilities in all available providers
*/
QCA_EXPORT bool isSupported(const QStringList &features, const QString &provider = QString());

/**
   Generate a list of all the supported features in plugins,
   and in built in capabilities

   \return a list containing the names of the features

   The following code writes a list of features to standard out
   \code
QStringList capabilities;
capabilities = QCA::supportedFeatures();
std::cout << "Supported:" << capabilities.join(",") << std::endl;
   \endcode
   \sa isSupported(const char *features)
   \sa isSupported(const QStringList &features)
   \sa defaultFeatures()
*/
QCA_EXPORT QStringList supportedFeatures();

/**
   Generate a list of the built in features. This differs from
   supportedFeatures() in that it does not include features provided
   by plugins.

   \return a list containing the names of the features

   The following code writes a list of features to standard out
   \code
QStringList capabilities;
capabilities = QCA::defaultFeatures();
std::cout << "Default:" << capabilities.join(",") << std::endl;
   \endcode

   \sa isSupported
   \sa supportedFeatures()
*/
QCA_EXPORT QStringList defaultFeatures();

/**
   Add a provider to the current list of providers

   This function allows you to add a provider to the 
   current plugin providers at a specified priority. If
   a provider with the name already exists, this call fails.

   QCA takes ownership of the provider.

   \param p a pointer to a Provider object, which must be
   set up.
   \param priority the priority level to set the provider to
   \return true if the provider is added, and false if the
   provider is not added (failure)

   \sa unloadProvider for unloading specified providers
   \sa setProviderPriority for a description of the provider priority system
*/
QCA_EXPORT bool insertProvider(Provider *p, int priority = 0);

/**
   Unload specified provider

   The specified provider is removed from the list of providers
   and deleted. If no provider with the name is found, this call fails.

   \param name the name of the provider
   \return true if the provider is unloaded, and false if the provider
   cannot be found

   \sa insertProvider for adding providers
*/
QCA_EXPORT bool unloadProvider(const QString &name);

/**
   Change the priority of a specified provider

   QCA supports a number of providers, and if a number of providers
   support the same algorithm, it needs to choose between them. You
   can do this at object instantiation time (by specifying the name
   of the provider that should be used). Alternatively, you can provide a
   relative priority level at an application level, using this call.

   Priority is used at object instantiation time. The provider is selected
   according to the following logic:
   - if a particular provider is nominated, and that provider supports
   the required algorithm, then the nominated provider is used
   - if no provider is nominated, or it doesn't support the required
   algorithm, then the provider with the lowest priority number will be used,
   if that provider supports the algorithm.
   - if the provider with the lowest priority number doesn't support 
   the required algorithm, the provider with the next lowest priority number
   will be tried, and so on through to the provider with the largest priority
   number
   - if none of the plugin providers support the required algorithm, then
   the default (built-in) provider will be tried.

   \param name the name of the provider
   \param priority the new priority of the provider. As a special case, if
   you pass in -1, then this provider gets the same priority as the
   the last provider that was added or had its priority set using this
   call.

   \sa providerPriority
*/
QCA_EXPORT void setProviderPriority(const QString &name, int priority);

/**
   Return the priority of a specified provider

   The name of the provider (eg "qca-ossl") is used to look up the 
   current priority associated with that provider. If the provider
   is not found (or something else went wrong), -1 is returned.

   \param name the name of the provider

   \return the current priority level

   \sa setProviderPriority for a description of the provider priority system
*/
QCA_EXPORT int providerPriority(const QString &name);

/**
   Return a list of the current providers

   The current plugin providers are provided as a list, which you
   can iterate over using ProviderListIterator.

   \sa ProviderList
   \sa ProviderListIterator
*/
QCA_EXPORT ProviderList providers();

/**
   Return the named provider, or 0 if not found

   \param name the name of the provider to search for.
*/
QCA_EXPORT Provider *findProvider(const QString &name);

/**
   Return the default provider
*/
QCA_EXPORT Provider *defaultProvider();

/**
   Retrieve plugin paths. It consists of:
   1. QCA_PLUGIN_PATH environment if set.
   2. \c %QCoreApplication::libraryPaths() .
   3. Directory where plugins were installed.

   QCA_PLUGIN_PATH is paths list like PATH or QT_PLUGIN_PATH.
   It uses system path separator. \";\" on Windows and \":\" on Unix.

   This function was introduced in %QCA 2.1.
*/
QCA_EXPORT QStringList pluginPaths();

/**
   Scan for new plugins
*/
QCA_EXPORT void scanForPlugins();

/**
   Unload the current plugins
*/
QCA_EXPORT void unloadAllPlugins();

/**
   Retrieve plugin diagnostic text
*/
QCA_EXPORT QString pluginDiagnosticText();

/**
   Clear plugin diagnostic text
*/
QCA_EXPORT void clearPluginDiagnosticText();

/**
   Add plugin diagnostic text

   This function should only be called by providers.

   \param text the diagnostic message to append
*/
QCA_EXPORT void appendPluginDiagnosticText(const QString &text);

/**
   Set a global property

   \param name the name of the property
   \param value the value to set the property to

   \sa getProperty
*/
QCA_EXPORT void setProperty(const QString &name, const QVariant &value);

/**
   Retrieve a global property

   \param name the name of the property to look up

   \sa setProperty
*/
QCA_EXPORT QVariant getProperty(const QString &name);

/**
   Set provider configuration

   Allowed value types: QString, int, bool

   \param name the name of the provider to set the configuration to
   \param config the configuration
*/
QCA_EXPORT void setProviderConfig(const QString &name, const QVariantMap &config);

/**
   Retrieve provider configuration

   \param name the name of the provider to retrieve the configuration of
*/
QCA_EXPORT QVariantMap getProviderConfig(const QString &name);

/**
   Save provider configuration to persistent storage

   \param name the name of the provider to have its configuration saved
*/
QCA_EXPORT void saveProviderConfig(const QString &name);

/**
   Return the name of the global random number provider
*/
QCA_EXPORT QString globalRandomProvider();

/**
   Change the global random number provider

   The Random capabilities of %QCA are provided as part of the
   built in capabilities, however the generator can be changed
   if required.

   \param provider the name of the provider to use as the global random
   provider.
*/
QCA_EXPORT void setGlobalRandomProvider(const QString &provider);

/**
   Return a reference to the %QCA Logger, which is used for diagnostics
   and error recording.

   The system Logger is automatically created for you on start. 
*/
QCA_EXPORT Logger *logger();

/**
   Log a text message. This is an efficient function
   to avoid overhead of argument executions when log level
   blocks the message.

   \param message the text to log
   \param severity the type of information to log

   \note This is a macro, so arguments may or may not be evaluated.
*/
#define QCA_logTextMessage(message, severity) \
	do { \
		register QCA::Logger::Severity s = severity; \
		register QCA::Logger *l = QCA::logger (); \
		if (s <= l->level ()) { \
			l->logTextMessage (message, s); \
		} \
	} while (false)

/**
   Log a binary message. This is an efficient function
   to avoid overhead of argument executions when log level
   blocks the message.

   \param blob the blob to log
   \param severity the type of information to log

   \note This is a macro, so arguments may or may not be evaluated.
*/
#define QCA_logBinaryMessage(blob, severity) \
	do { \
		register QCA::Logger::Severity s = severity; \
		register QCA::Logger *l = QCA::logger (); \
		if (s <= l->level ()) { \
			l->logBinaryMessage (blob, s); \
		} \
	} while (false)

/**
   Test if QCA can access the root CA certificates

   If root certificates are available, this function returns true,
   otherwise it returns false.

   \sa systemStore
*/
QCA_EXPORT bool haveSystemStore();

/**
   Get system-wide root Certificate Authority (CA) certificates

   Many operating systems (or distributions, on Linux-type systems)
   come with some trusted certificates. Typically, these include
   the root certificates for major Certificate Authorities (for
   example, Verisign, Comodo) and some additional certificates that
   are used for system updates. They are provided in different ways
   for different systems.

   This function provides an common way to access the system 
   certificates. There are other ways to access certificates - see
   the various I/O methods (such as fromDER() and fromPEM()) 
   in the Certificate and CertificateCollection classes.

   \note Availability of the system certificates depends on how
   %QCA was built. You can test whether the system certificates
   are available using the haveSystemStore() function.

*/
QCA_EXPORT CertificateCollection systemStore();

/**
   Get the application name that will be used by SASL server mode

   The application name is used by SASL in server mode, as some systems might
   have different security policies depending on the app.
   The default application name  is 'qca'
*/
QCA_EXPORT QString appName();

/**
   Set the application name that will be used by SASL server mode

   The application name is used by SASL in server mode, as some systems might
   have different security policies depending on the app. This should be set 
   before using SASL objects, and it cannot be changed later.

   \param name the name string to use for SASL server mode
*/
QCA_EXPORT void setAppName(const QString &name);

/**
   Convert a byte array to printable hexadecimal
   representation.

   This is a convenience function to convert an arbitrary
   QByteArray to a printable representation.

   \code
QByteArray test(10);
test.fill('a');
// 0x61 is 'a' in ASCII
if (QString("61616161616161616161") == QCA::arrayToHex(test) )
{
	printf ("arrayToHex passed\n");
}
   \endcode

   \param array the array to be converted
   \return a printable representation
*/
QCA_EXPORT QString arrayToHex(const QByteArray &array);

/**
   Convert a QString containing a hexadecimal representation
   of a byte array into a QByteArray

   This is a convenience function to convert a printable
   representation into a QByteArray - effectively the inverse
   of QCA::arrayToHex.

   \code
QCA::init();
QByteArray test(10);

test.fill('b'); // 0x62 in hexadecimal
test[7] = 0x00; // can handle strings with nulls

if (QCA::hexToArray(QString("62626262626262006262") ) == test )
{
	printf ("hexToArray passed\n");
}
   \endcode

   \param hexString the string containing a printable
   representation to be converted
   \return the equivalent QByteArray
*/
QCA_EXPORT QByteArray hexToArray(const QString &hexString);

/**
   \class Initializer qca_core.h QtCrypto

   Convenience method for initialising and cleaning up %QCA

   To ensure that QCA is properly initialised and cleaned up,
   it is convenient to create an Initializer object, and let it
   go out of scope at the end of %QCA usage.

   \ingroup UserAPI
*/
class QCA_EXPORT Initializer
{
public:
	/**
	   Standard constructor

	   \param m the MemoryMode to use for secure memory
	   \param prealloc the amount of secure memory to pre-allocate,
	   in units of 1024 bytes (1K).
	*/
	explicit Initializer(MemoryMode m = Practical, int prealloc = 64);
	~Initializer();
};

/**
   \class KeyLength qca_core.h QtCrypto

   Simple container for acceptable key lengths

   The KeyLength specifies the minimum and maximum byte sizes
   allowed for a key, as well as a "multiple" which the key
   size must evenly divide into.

   As an example, if the key can be 4, 8 or 12 bytes, you can
   express this as
   \code
KeyLength keyLen( 4, 12, 4 );
   \endcode

   If you want to express a KeyLength that takes any number
   of bytes (including zero), you may want to use
   \code
#include<limits>
KeyLength( 0, std::numeric_limits<int>::max(), 1 );
   \endcode

   \ingroup UserAPI
*/
class QCA_EXPORT KeyLength
{
public:
	/**
	   Construct a %KeyLength object

	   \param min the minimum length of the key, in bytes
	   \param max the maximum length of the key, in bytes
	   \param multiple the number of bytes that the key must be a 
	   multiple of.
	*/
	KeyLength(int min, int max, int multiple)
		: _min( min ), _max(max), _multiple( multiple )
	{ }

	/**
	   Obtain the minimum length for the key, in bytes
	*/
	int minimum() const { return _min; }

	/**
	   Obtain the maximum length for the key, in bytes
	*/
	int maximum() const { return _max; }

	/**
	   Return the number of bytes that the key must be a multiple of

	   If this is one, then anything between minimum and maximum (inclusive)
	   is acceptable.
	*/
	int multiple() const { return _multiple; }

private:
	const int _min, _max, _multiple;
};

/**
   \class Provider qca_core.h QtCrypto

   Algorithm provider

   Provider represents a plugin provider (or as a special case, the
   built-in provider). This is the class you need to inherit
   from to create your own plugin. You don't normally need to 
   worry about this class if you are just using existing 
   QCA capabilities and plugins, however there is nothing stopping
   you from using it to obtain information about specific plugins,
   as shown in the example below.

   \ingroup ProviderAPI
*/
class QCA_EXPORT Provider
{
public:
	virtual ~Provider();

	class Context;

	/**
	   Initialisation routine

	   This routine will be called when your plugin
	   is loaded, so this is a good place to do any
	   one-off initialisation tasks. If you don't need
	   any initialisation, just implement it as an empty
	   routine.
	*/
	virtual void init();

	/**
	   Deinitialisation routine

	   This routine will be called just before provider destruction.
	   Notably, during QCA shutdown, deinit() will be called on all
	   providers before any of the providers are destructed.  Use this
	   opportunity to free any resources that may be used by other
	   providers.
	*/
	virtual void deinit();

	/**
	   Version number of the plugin

	   The format is the same as QCA itself.  Version 1.2.3 would be
	   represented as 0x010203.

	   The default returns 0 (version 0.0.0).
	*/
	virtual int version() const;

	/**
	   Target QCA version for the provider.

	   This is used to verify compatibility between the
	   provider and QCA.  For a provider to be used, it
	   must supply major and minor version numbers here that are
	   less-than or equal to the actual QCA version (the patch
	   version number is ignored).  This means an older
	   provider may be used with a newer QCA, but a newer
	   provider cannot be used with an older QCA.
	*/
	virtual int qcaVersion() const = 0;

	/**
	   The name of the provider.

	   Typically you just return a string containing a 
	   convenient name.

	   \code
QString name() const
{
	return "qca-myplugin";
}
	   \endcode

	   \note  The name is used to tell if a provider is
	   already loaded, so you need to make sure it is
	   unique amongst the various plugins.
	*/
	virtual QString name() const = 0;

	/**
	   The capabilities (algorithms) of the provider.

	   Typically you just return a fixed QStringList:
	   \code
QStringList features() const
{
	QStringList list;
	list += "sha1";
	list += "sha256";
	list += "hmac(sha1)";
	return list;
}
	   \endcode
	*/
	virtual QStringList features() const = 0;

	/**
	   Optional credit text for the provider.

	   You might display this information in a credits or
	   "About" dialog.  Returns an empty string if the
	   provider has no credit text.  Only report credit text
	   when absolutely required (for example, an "advertisement
	   clause" related to licensing).  Do not use it for
	   reporting general author information.
	*/
	virtual QString credit() const;

	/**
	   Routine to create a plugin context

	   You need to return a pointer to an algorithm
	   Context that corresponds with the algorithm
	   name specified. 

	   \param type the name of the algorithm required

	   \code
Context *createContext(const QString &type)
{
	if ( type == "sha1" )
		return new SHA1Context( this );
	else if ( type == "sha256" )
		return new SHA0256Context( this );
	else if ( type == "hmac(sha1)" )
		return new HMACSHA1Context( this );
	else
		return 0;
}
	   \endcode

	   Naturally you also need to implement
	   the specified Context subclasses as well.
	*/
	virtual Context *createContext(const QString &type) = 0;

	/**
	   Method to set up the default configuration options.

	   If your provider needs some configuration options,
	   this method allows you to establish default options.
	   The user can then change the configuration options 
	   as required, and set them using configChanged().

	   You need to return a QVariantMap that has configuration
	   options as the keys, and the default configuration 
	   as the values, as shown below:
	   \code
QVariantMap defaultConfig() const
{
	QVariantMap myConfig;
	myConfig[ "firstOption" ] = QString("firstOptionValue");
	myConfig[ "secondOption" ] = true;
	myConfig[ "thirdOpt" ] = 1243;
	return myConfig;
}
	   \endcode

	   \sa configChanged for how to set the configuration;
	*/
	virtual QVariantMap defaultConfig() const;

	/**
	   Method to set the configuration options.

	   If your provider supports configuration options, you
	   will be advised of user changes to the configuration 
	   when this method is called.

	   \param config the new configuration to be used by the provider
	*/
	virtual void configChanged(const QVariantMap &config);
};

/**
   \class QCA::Provider::Context qca_core.h QtCrypto

   Internal context class used for the plugin

   \internal

   \ingroup ProviderAPI
*/
class QCA_EXPORT Provider::Context : public QObject
{
	Q_OBJECT
public:
	virtual ~Context();

	/**
	   The Provider associated with this Context
	*/
	Provider *provider() const;

	/**
	   The type of context, as passed to the constructor
	*/
	QString type() const;

	/**
	   Create a duplicate of this Context
	*/
	virtual Context *clone() const = 0;

	/**
	   Test if two Contexts have the same Provider

	   \param c pointer to the Context to compare to

	   \return true if the argument and this Context
	   have the same provider.
	*/
	bool sameProvider(const Context *c) const;

protected:
	/**
	   Standard constructor

	   \param parent the parent provider for this 
	   context
	   \param type the name of the provider context type
	*/
	Context(Provider *parent, const QString &type);

	/**
	   Copy constructor

	   \param from the Context to copy from
	*/
	Context(const Context &from);

private:
	// disable assignment
	Context & operator=(const Context &from);

	Provider *_provider;
	QString _type;
};

/**
   \class BasicContext qca_core.h QtCrypto

   Base class to use for primitive provider contexts

   \internal

   This class inherits Provider::Context and calls moveToThread(0) on
   itself, thereby disabling the event properties of the underlying
   QObject.  Context types that need to be a QObject should inherit from
   Provider::Context, those that don't should inherit from BasicContext.

   \ingroup ProviderAPI
*/
class QCA_EXPORT BasicContext : public Provider::Context
{
	Q_OBJECT
public:
	~BasicContext();

protected:
	/**
	   Standard constructor

	   \param parent the parent provider for this 
	   context
	   \param type the name of the provider context type
	*/
	BasicContext(Provider *parent, const QString &type);

	/**
	   Copy constructor

	   \param from the Context to copy from
	*/
	BasicContext(const BasicContext &from);

private:
	// disable assignment
	BasicContext & operator=(const BasicContext &from);
};

/**
   \class BufferedComputation qca_core.h QtCrypto

   General superclass for buffered computation algorithms

   A buffered computation is characterised by having the
   algorithm take data in an incremental way, then having
   the results delivered at the end. Conceptually, the
   algorithm has some internal state that is modified
   when you call update() and returned when you call
   final().

   \ingroup UserAPI
*/
class QCA_EXPORT BufferedComputation
{
public:
	virtual ~BufferedComputation();

	/**
	   Reset the internal state
	*/
	virtual void clear() = 0;

	/**
	   Update the internal state with a byte array

	   \param a the byte array of data that is to 
	   be used to update the internal state.
	*/
	virtual void update(const MemoryRegion &a) = 0;

	/**
	   Complete the algorithm and return the internal state
	*/
	virtual MemoryRegion final() = 0;

	/**
	   Perform an "all in one" update, returning
	   the result. This is appropriate if you
	   have all the data in one array - just
	   call process on that array, and you will
	   get back the results of the computation.

	   \note This will invalidate any previous
	   computation using this object.

	   \param a the data to process.
	*/
	MemoryRegion process(const MemoryRegion &a);
};

/**
   \class Filter qca_core.h QtCrypto

   General superclass for filtering transformation algorithms

   A filtering computation is characterised by having the
   algorithm take input data in an incremental way, with results
   delivered for each input, or block of input. Some internal
   state may be managed, with the transformation completed
   when final() is called.

   If this seems a big vague, then you might try deriving
   your class from a subclass with stronger semantics, or if your
   update() function is always returning null results, and
   everything comes out at final(), try BufferedComputation.

   \ingroup UserAPI
*/
class QCA_EXPORT Filter
{
public:
	virtual ~Filter();

	/**
	   Reset the internal state
	*/
	virtual void clear() = 0;

	/**
	   Process more data, returning the corresponding
	   filtered version of the data.

	   \param a the array containing data to process
	*/
	virtual MemoryRegion update(const MemoryRegion &a) = 0;

	/**
	   Complete the algorithm, returning any 
	   additional results.
	*/
	virtual MemoryRegion final() = 0;

	/**
	   Test if an update() or final() call succeeded.

	   \return true if the previous call succeeded
	*/
	virtual bool ok() const = 0;

	/**
	   Perform an "all in one" update, returning
	   the result. This is appropriate if you
	   have all the data in one array - just
	   call process on that array, and you will
	   get back the results of the computation.

	   \note This will invalidate any previous
	   computation using this object.

	   \param a the data to process in this step
	*/
	MemoryRegion process(const MemoryRegion &a);
};

/**
   \class Algorithm qca_core.h QtCrypto

   General superclass for an algorithm. 

   This is a fairly abstract class, mainly used for
   implementing the backend "provider" interface.

   \ingroup UserAPI
*/
class QCA_EXPORT Algorithm
{
public:
	/**
	   Standard copy constructor

	   \param from the Algorithm to copy from
	*/
	Algorithm(const Algorithm &from);

	virtual ~Algorithm();

	/**
	   Assignment operator

	   \param from the Algorithm to copy state from
	*/
	Algorithm & operator=(const Algorithm &from);

	/**
	   The name of the algorithm type.
	*/
	QString type() const;

	/**
	   The name of the provider

	   Each algorithm is implemented by a provider. This
	   allows you to figure out which provider is associated
	*/
	Provider *provider() const;

	// Note: The next five functions are not public!

	/**
	   \internal

	   The context associated with this algorithm
	*/
	Provider::Context *context();

	/**
	   \internal

	   The context associated with this algorithm
	*/
	const Provider::Context *context() const;

	/**
	   \internal

	   Set the Provider for this algorithm

	   \param c the context for the Provider to use
	*/
	void change(Provider::Context *c);

	/**
	   \internal

	   \overload

	   \param type the name of the algorithm to use
	   \param provider the name of the preferred provider
	*/
	void change(const QString &type, const QString &provider);

	/**
	   \internal

	   Take the Provider from this algorithm
	*/
	Provider::Context *takeContext();

protected:
	/**
	   Constructor for empty algorithm
	*/
	Algorithm();

	/**
	   Constructor of a particular algorithm.

	   \param type the algorithm to construct
	   \param provider the name of a particular Provider
	*/
	Algorithm(const QString &type, const QString &provider);

private:
	class Private;
	QSharedDataPointer<Private> d;
};

/**
   \class SymmetricKey qca_core.h QtCrypto

   Container for keys for symmetric encryption algorithms.

   \ingroup UserAPI
*/
class QCA_EXPORT SymmetricKey : public SecureArray
{
public:
	/**
	   Construct an empty (zero length) key
	*/
	SymmetricKey();

	/**
	   Construct an key of specified size, with random contents

	   This is intended to be used as a random session key.

	   \param size the number of bytes for the key
	*/
	SymmetricKey(int size);

	/**
	   Construct a key from a provided byte array

	   \param a the byte array to copy
	*/
	SymmetricKey(const SecureArray &a);

	/**
	   Construct a key from a provided byte array

	   \param a the byte array to copy
	*/
	SymmetricKey(const QByteArray &a);

	/**
	   Test for weak DES keys

	  \return true if the key is a weak key for DES
	*/
	bool isWeakDESKey();
};

/**
   \class InitializationVector qca_core.h QtCrypto

   Container for initialisation vectors and nonces

   \ingroup UserAPI
*/
class QCA_EXPORT InitializationVector : public SecureArray
{
public:
	/**
	   Construct an empty (zero length) initisation vector
	*/
	InitializationVector();

	/**
	   Construct an initialisation vector of the specified size

	   \param size the length of the initialisation vector, in bytes
	*/
	InitializationVector(int size);

	/**
	   Construct an initialisation vector from a provided byte array

	   \param a the byte array to copy
	*/
	InitializationVector(const SecureArray &a);

	/**
	   Construct an initialisation vector from a provided byte array

	   \param a the byte array to copy
	*/
	InitializationVector(const QByteArray &a);
};

/**
   \class Event qca_core.h QtCrypto

   An asynchronous event

   Events are produced in response to the library's need for some user
   intervention, such as entering a pin or password, or inserting a
   cryptographic token.

   Event is an abstraction, so you can handle this need in a way that makes
   sense for your application.

   \ingroup UserAPI
*/
class QCA_EXPORT Event
{
public:
	/**
	   %Type of event

	   \sa type()
	*/
	enum Type
	{
		Password,   ///< Asking for a password, PIN or passphrase.
		Token       ///< Asking for a token
	};

	/**
	   %Source of the event

	   Events are associated with access to a KeyStore, or access to 
	   a file (or bytearray/stream or equivalent). This tells you the
	   type of source that caused the Event.

	   \sa source()
	   \sa fileName() for the name, if source is Event::Data
	   \sa keyStoreInfo() and keyStoreEntry() for the keystore and entry,
	   if the source is Event::KeyStore
	*/
	enum Source
	{
		KeyStore,   ///< KeyStore generated the event
		Data        ///< File or bytearray generated the event
	};

	/**
	   password variation

	   If the Type of Event is Password, PasswordStyle tells you whether 
	   it is a PIN, passphrase or password.

	   \sa passwordStyle()
	*/
	enum PasswordStyle
	{
		StylePassword,   ///< User should be prompted for a "Password"
		StylePassphrase, ///< User should be prompted for a "Passphrase"
		StylePIN         ///< User should be prompted for a "PIN"
	};

	/**
	   Constructor
	*/
	Event();

	/**
	   Copy constructor

	   \param from the Event to copy from
	*/
	Event(const Event &from);

	/**
	   Destructor
	*/
	~Event();

	/**
	   Assignment operator

	   \param from the Event to copy from
	*/
	Event & operator=(const Event &from);

	/**
	   test if this event has been setup correctly
	*/
	bool isNull() const;

	/**
	   the Type of this event
	*/
	Type type() const;

	/**
	   the Source of this event
	*/
	Source source() const;

	/**
	   the style of password required.

	   This is not meaningful unless the Type is Event::Password.

	   \sa PasswordStyle
	*/
	PasswordStyle passwordStyle() const;

	/**
	   The info of the KeyStore associated with this event

	   This is not meaningful unless the Source is KeyStore.
	*/
	KeyStoreInfo keyStoreInfo() const;

	/**
	   The KeyStoreEntry associated with this event

	   This is not meaningful unless the Source is KeyStore.
	*/
	KeyStoreEntry keyStoreEntry() const;

	/**
	   Name or other identifier for the file or byte array
	   associated with this event.

	   This is not meaningful unless the Source is Data.
	*/
	QString fileName() const;

	/**
	   opaque data
	*/
	void *ptr() const;

	/**
	   Set the values for this Event

	   This creates a Password type event, for a keystore.

	   \param pstyle the style of information required (e.g. PIN,
	   password or passphrase)
	   \param keyStoreInfo info about the keystore that the information
	   is required for
	   \param keyStoreEntry the entry in the keystore that the
	   information is required for
	   \param ptr opaque data
	*/
	void setPasswordKeyStore(PasswordStyle pstyle, const KeyStoreInfo &keyStoreInfo, const KeyStoreEntry &keyStoreEntry, void *ptr);

	/**
	   Set the values for this Event

	   This creates a Password type event, for a file.

	   \param pstyle the style of information required (e.g. PIN,
	   password or passphrase)
	   \param fileName the name of the file (or other identifier) that
	   the information is required for
	   \param ptr opaque data
	*/
	void setPasswordData(PasswordStyle pstyle, const QString &fileName, void *ptr);

	/**
	   Set the values for this Event

	   This creates a Token type event.

	   \param keyStoreInfo info about the keystore that the token is
	   required for
	   \param keyStoreEntry the entry in the keystore that the token is
	   required for
	   \param ptr opaque data
	*/
	void setToken(const KeyStoreInfo &keyStoreInfo, const KeyStoreEntry &keyStoreEntry, void *ptr);

private:
	class Private;
	QSharedDataPointer<Private> d;
};

/**
   \class EventHandler qca_core.h QtCrypto

   Interface class for password / passphrase / PIN and token handlers

   This class is used on client side applications to handle
   the provision of passwords, passphrases and PINs by users, and
   to indicate that tokens have been correctly inserted.

   The concept behind this class is that the library can raise
   events (typically using PasswordAsker or TokenAsker), which
   may (or may not) be handled by the application using a
   handler object (that has-a EventHandler, or possibly is-a
   EventHandler) that is connected to the eventReady() signal.

   \ingroup UserAPI
*/
class QCA_EXPORT EventHandler : public QObject
{
	Q_OBJECT
public:
	/**
	   Constructor

	   \param parent the parent object for this object
	*/
	EventHandler(QObject *parent = 0);
	~EventHandler();

	/**
	   mandatory function to call after connecting the
	   signal to a slot in your application specific password
	   / passphrase / PIN or token handler
	*/
	void start();

	/**
	   function to call to return the user provided
	   password, passphrase or PIN.

	   \param id the id corresponding to the password request
	   \param password the user-provided password, passphrase or PIN.

	   \note the id parameter is the same as that provided in the
	   eventReady() signal.
	*/
	void submitPassword(int id, const SecureArray &password);

	/**
	   function to call to indicate that the token has been inserted
	   by the user.

	   \param id the id corresponding to the password request

	   \note the id parameter is the same as that provided in the
	   eventReady() signal.
	*/
	void tokenOkay(int id);

	/**
	   function to call to indicate that the user declined to 
	   provide a password, passphrase, PIN or token.

	   \param id the id corresponding to the password request

	   \note the id parameter is the same as that provided in the
	   eventReady() signal.
	*/
	void reject(int id);

Q_SIGNALS:
	/**
	   signal emitted when an Event requires attention.

	   You typically need to connect this signal to
	   a compatible slot in your callback handler

	   \param id the identification number for the event 
	   \param context information about the type of response required
	*/
	void eventReady(int id, const QCA::Event &context);

private:
	Q_DISABLE_COPY(EventHandler)

	class Private;
	friend class Private;
	Private *d;
};

/**
   \class PasswordAsker qca_core.h QtCrypto

   User password / passphrase / PIN handler

   This class is used to obtain a password from a user.

   \ingroup UserAPI
*/
class QCA_EXPORT PasswordAsker : public QObject
{
	Q_OBJECT
public:
	/**
	   Construct a new asker

	   \param parent the parent object for this QObject
	*/
	PasswordAsker(QObject *parent = 0);
	~PasswordAsker();

	/**
	   queue a password / passphrase request associated with a key store

	   \param pstyle the type of information required (e.g. PIN,
	   passphrase or password)
	   \param keyStoreInfo info of the key store that the information is
	   required for
	   \param keyStoreEntry the item in the key store that the
	   information is required for (if applicable)
	   \param ptr opaque data
	*/
	void ask(Event::PasswordStyle pstyle, const KeyStoreInfo &keyStoreInfo, const KeyStoreEntry &keyStoreEntry, void *ptr);

	/**
	   queue a password / passphrase request associated with a file

	   \param pstyle the type of information required (e.g. PIN,
	   passphrase or password)
	   \param fileName the name of the file that the information is
	   required for
	   \param ptr opaque data
	*/
	void ask(Event::PasswordStyle pstyle, const QString &fileName, void *ptr);

	/**
	   Cancel the pending password / passphrase request
	*/
	void cancel();

	/**
	   Block until the password / passphrase request is
	   completed

	   You can use the responseReady signal instead of
	   blocking, if appropriate.
	*/
	void waitForResponse();

	/**
	   Determine whether the password / passphrase was accepted or not

	   In this context, returning true is indicative of the user clicking
	   "Ok" or equivalent; and returning false indicates that either the
	   user clicked "Cancel" or equivalent, or that the cancel() function
	   was called, or that the request is still pending.
	*/
	bool accepted() const;

	/**
	   The password / passphrase / PIN provided by the user in response
	   to the asker request. This may be empty.
	*/
	SecureArray password() const;

Q_SIGNALS:
	/**
	   Emitted when the asker process has been completed. 

	   You should check whether the user accepted() the response
	   prior to relying on the password().
	*/
	void responseReady();

private:
	Q_DISABLE_COPY(PasswordAsker)

	class Private;
	friend class Private;
	Private *d;
};

/**
   \class TokenAsker qca_core.h QtCrypto

   User token handler

   This class is used to request the user to insert a token.

   \ingroup UserAPI
*/
class QCA_EXPORT TokenAsker : public QObject
{
	Q_OBJECT
public:
	/**
	   Construct a new asker

	   \param parent the parent object for this QObject
	*/
	TokenAsker(QObject *parent = 0);
	~TokenAsker();

	/**
	   queue a token request associated with a key store
	
	   \param keyStoreInfo info of the key store that the information is
	   required for
	   \param keyStoreEntry the item in the key store that the
	   information is required for (if applicable)
	   \param ptr opaque data
	*/
	void ask(const KeyStoreInfo &keyStoreInfo, const KeyStoreEntry &keyStoreEntry, void *ptr);

	/**
	   Cancel the pending password / passphrase request
	*/
	void cancel();

	/**
	   Block until the token request is completed

	   You can use the responseReady signal instead of
	   blocking, if appropriate.
	*/
	void waitForResponse();

	/**
	   Test if the token request was accepted or not.

	   \return true if the token request was accepted
	*/
	bool accepted() const;

Q_SIGNALS:
	/**
	   Emitted when the asker process has been completed. 

	   You should check whether the user accepted() the response
	   prior to relying on token being present.
	*/
	void responseReady();

private:
	Q_DISABLE_COPY(TokenAsker)

	class Private;
	friend class Private;
	Private *d;
};

}

#endif
