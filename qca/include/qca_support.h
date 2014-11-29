/*
 * qca_support.h - Qt Cryptographic Architecture
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
 * Copyright (C) 2004,2005, 2007  Brad Hards <bradh@frogmouth.net>
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
   \file qca_support.h

   Header file for "support" classes used in %QCA

   The classes in this header do not have any cryptographic
   content - they are used in %QCA, and are included for convenience.

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_SUPPORT_H
#define QCA_SUPPORT_H

#include <QByteArray>
#include <QString>
#include <QObject>
#include <QVariant>
#include <QVariantList>
#include <QStringList>
#include <QList>
#include <QMetaObject>
#include <QThread>
#include "qca_export.h"
#include "qca_tools.h"

namespace QCA {

/**
   Convenience method to determine the return type of a method

   This function identifies the return type of a specified
   method. This function can be used as shown:
   \code
class TestClass : public QObject
{
    Q_OBJECT
    // ...
public slots:
    QString qstringMethod()  { return QString(); };
    bool boolMethod( const QString & )  { return true; };
};

QByteArray myTypeName;

TestClass testClass;
QList<QByteArray> argsList; // empty list, since no args

myTypeName = QCA::methodReturnType( testClass.metaObject(), QByteArray( "qstringMethod" ), argsList );
// myTypeName is "QString"

myTypeName = QCA::methodReturnType( testClass.metaObject(), QByteArray( "boolMethod" ), argsList );
// myTypeName is "", because there is no method called "boolMethod" that has no arguments

argsList << "QString"; // now we have one argument
myTypeName = QCA::methodReturnType( testClass.metaObject(), QByteArray( "boolMethod" ), argsList );
// myTypeName is "bool"
   \endcode

   The return type name of a method returning void is an empty string, not "void"

   \note This function is not normally required for use with
   %QCA. It is provided for use in your code, if required.

   \param obj the QMetaObject for the object
   \param method the name of the method (without the arguments or brackets)
   \param argTypes the list of argument types of the method 

   \return the name of the type that this method will return with the specified
   argument types.

   \sa QMetaType for more information on the Qt meta type system.

   \relates SyncThread
*/

QCA_EXPORT QByteArray methodReturnType(const QMetaObject *obj, const QByteArray &method, const QList<QByteArray> argTypes);

/**
   Convenience method to invoke a method by name, using a variant
   list of arguments.

   This function can be used as shown:
   \code
class TestClass : public QObject
{
    Q_OBJECT
    // ...
public slots:
    QString qstringMethod()  { return QString( "the result" ); };
    bool boolMethod( const QString & )  { return true; };
};

TestClass *testClass = new TestClass;
QVariantList args;

QVariant stringRes;
// calls testClass->qstringMethod() with no arguments ( since args is an empty list)
bool ret = QCA::invokeMethodWithVariants( testClass, QByteArray( "qstringMethod" ), args, &stringRes );
// ret is true (since call succeeded), stringRes.toString() is a string - "the result"

QVariant boolResult;
QString someString( "not important" );
args << someString;
// calls testClass->boolMethod( someString ), returning result in boolResult
ret = QCA::invokeMethodWithVariants( testClass1, QByteArray( "boolMethod" ), args, &boolResult );
// ret is true (since call succeeded), boolResult.toBool() is true.
   \endcode

   \param obj the object to call the method on
   \param method the name of the method (without the arguments or brackets)
   \param args the list of arguments to use in the method call
   \param ret the return value of the method (unchanged if the call fails)
   \param type the type of connection to use

   \return true if the call succeeded, otherwise false

   \relates SyncThread
*/
QCA_EXPORT bool invokeMethodWithVariants(QObject *obj, const QByteArray &method, const QVariantList &args, QVariant *ret, Qt::ConnectionType type = Qt::AutoConnection);

/**
   \class SyncThread qca_support.h QtCrypto

   Convenience class to run a thread and interact with it synchronously

   SyncThread makes it easy to perform the common practice of starting a
   thread, running some objects in that thread, and then interacting with
   those objects safely.  Often, there is no need to directly use threading
   primitives (e.g. QMutex), resulting in very clean multi-threaded code.

   \note The following is an excerpt from
   http://delta.affinix.com/2006/11/13/synchronized-threads-part-3/

   ---<br>
   With SyncThread, you can start, stop, and call a method in another thread
   while the main thread sleeps. The only requirement is that the methods be
   declared as slots.

   Below is a contrived example, where we have an object in another thread
   that increments a counter over a some interval, using the Qt event loop,
   and provides a method to inspect the value.

   First, the Counter object:

\code
class Counter : public QObject
{
	Q_OBJECT
private:
	int x;
	QTimer timer;

public:
	Counter() : timer(this)
	{
		x = 0;
		connect(&timer, SIGNAL(timeout()), SLOT(t_timeout()));
	}

public slots:
	void start(int seconds)
	{
		timer.setInterval(seconds * 1000);
		timer.start();
	}

	int value() const
	{
		return x;
	}

private slots:
	void t_timeout()
	{
		++x;
	}
};
\endcode

   Looks like a typical object, no surprises.

   Now to wrap Counter with SyncThread. We went over how to do this in the
   first article, and it is very straightforward:

\code
class CounterThread : public SyncThread
{
	Q_OBJECT
public:
	Counter *counter;

	CounterThread(QObject *parent) : SyncThread(parent)
	{
		counter = 0;
	}

	~CounterThread()
	{
		// SyncThread will stop the thread on destruct, but since our
		//   atStop() function makes references to CounterThread's
		//   members, we need to shutdown here, before CounterThread
		//   destructs.
		stop();
	}

protected:
	virtual void atStart()
	{
		counter = new Counter;
	}

	virtual void atStop()
	{
		delete counter;
	}
};
\endcode

   We can then use it like this:

\code
CounterThread *thread = new CounterThread;

// after this call, the thread is started and the Counter is ready
thread->start();

// let's start the counter with a 1 second interval
thread->call(thread->counter, "start", QVariantList() << 1);
...

// after some time passes, let's check on the value
int x = thread->call(thread->counter, "value").toInt();

// we're done with this thing
delete thread;
\endcode

   Do you see a mutex anywhere?  I didn't think so.<br>
   ---

   Even without the call() function, SyncThread is still very useful
   for preparing objects in another thread, which you can then
   QObject::connect() to and use signals and slots like normal.

   \ingroup UserAPI
*/
class QCA_EXPORT SyncThread : public QThread
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param parent the parent object for this parent.
	*/
	SyncThread(QObject *parent = 0);

	/**
	   Calls stop() and then destructs

	   \note Subclasses should call stop() in their own destructor
	*/
	~SyncThread();

	/**
	   Starts the thread, begins the event loop the thread, and then
	   calls atStart() in the thread.  This function will block until
	   atStart() has returned.
	*/
	void start();

	/**
	   Stops the event loop of the thread, calls atStop() in the thread,
	   and instructs the thread to finish.  This function will block
	   until the thread has finished.
	*/
	void stop();

	/**
	   Calls a slot of an object in the thread.  This function will block
	   until the slot has returned.

	   It is possible for the call to fail, for example if the method
	   does not exist.

	   The arguments and return value of the call use QVariant.  If the
	   method has no return value (returns void), then the returned
	   QVariant will be null.

	   \param obj the object to call the method on
	   \param method the name of the method (without the arguments or
	   brackets)
	   \param args the list of arguments to use in the method call
	   \param ok if not 0, true is stored here if the call succeeds,
	   otherwise false is stored here.
	*/
	QVariant call(QObject *obj, const QByteArray &method, const QVariantList &args = QVariantList(), bool *ok = 0);

protected:
	/**
	   Reimplement this to perform your initialization
	*/
	virtual void atStart() = 0;

	/**
	   Reimplement this to perform your deinitialization
	*/
	virtual void atEnd() = 0;

	/**
	   Starts the event loop and calls atStart and atStop as necessary
	*/
	virtual void run();

private:
	Q_DISABLE_COPY(SyncThread)

	class Private;
	friend class Private;
	Private *d;
};

/**
  \class Synchronizer qca_support.h QtCrypto

  Enable synchronization between two threads.
*/
class QCA_EXPORT Synchronizer : public QObject
{
	Q_OBJECT
public:
	/**
	  Standard constructor

	  \param parent the parent object to this object
	*/
	Synchronizer(QObject *parent);
	~Synchronizer();

	/**
	   Call to pause execution in this thread. This function
	   will block until conditionMet() is called.

	   \param msecs the time to wait before proceeding. The default
	   timeout value (-1) indicates to wait indefinitely.
	*/
	bool waitForCondition(int msecs = -1);

	/**
	   Call to continue execution in the paused thread.
	*/
	void conditionMet();

private:
	Q_DISABLE_COPY(Synchronizer)

	class Private;
	Private *d;
};

/**
   \class DirWatch qca_support.h QtCrypto

   Support class to monitor a directory for activity.

   %DirWatch monitors a specified file for any changes. When
   the directory changes, the changed() signal is emitted.

   \note QFileSystemWatcher has very similar functionality
   to this class. You should evaluate this class and 
   QFileSystemWatcher to determine which better suits your
   application needs.

   \ingroup UserAPI
*/
class QCA_EXPORT DirWatch : public QObject
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param dir the name of the directory to watch. If not
	   set in the constructor, you can set it using setDirName()
	   \param parent the parent object for this object
	*/
	explicit DirWatch(const QString &dir = QString(), QObject *parent = 0);
	~DirWatch();

	/**
	   The name of the directory that is being monitored
	*/
	QString dirName() const;

	/**
	   Change the directory being monitored

	   \param dir the name of the directory to monitor
	*/
	void setDirName(const QString &dir);

Q_SIGNALS:
	/**
	   The changed signal is emitted when the directory is
	   changed (e.g. modified by addition or deletion of a
	   file within the directory, or the deletion of the
	   directory)
	*/
	void changed();

private:
	Q_DISABLE_COPY(DirWatch)

	class Private;
	friend class Private;
	Private *d;
};

/**
   \class FileWatch qca_support.h QtCrypto

   Support class to monitor a file for activity

   %FileWatch monitors a specified file for any changes. When
   the file changes, the changed() signal is emitted.

   \note QFileSystemWatcher has very similar functionality
   to this class. You should evaluate this class and 
   QFileSystemWatcher to determine which better suits your
   application needs.

   \ingroup UserAPI
*/
class QCA_EXPORT FileWatch : public QObject
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param file the name of the file to watch. If not
	   in this object, you can set it using setFileName()
	   \param parent the parent object for this object
	*/
	explicit FileWatch(const QString &file = QString(), QObject *parent = 0);
	~FileWatch();

	/**
	   The name of the file that is being monitored
	*/
	QString fileName() const;

	/**
	   Change the file being monitored

	   \param file the name of the file to monitor
	*/
	void setFileName(const QString &file);

Q_SIGNALS:
	/**
	   The changed signal is emitted when the file is
	   changed (e.g. modified, deleted)
	*/
	void changed();

private:
	Q_DISABLE_COPY(FileWatch)

	class Private;
	friend class Private;
	Private *d;
};

class ConsolePrivate;
class ConsoleReferencePrivate;
class ConsoleReference;

/**
   \class Console qca_support.h QtCrypto

   %QCA %Console system

   %QCA provides an API for asynchronous, event-based access to
   the console and stdin/stdout, as these facilities are
   otherwise not portable.  The primary use of this system within
   %QCA is for passphrase prompting in command-line applications,
   using the tty console type.

   How it works: Create a %Console object for the type of console
   desired, and then use ConsoleReference to act on the console.
   Only one ConsoleReference may operate on a %Console at a time.

   A %Console object takes over either the physical console (Console::Tty
   type) or stdin/stdout (Console::Stdio type).  Only one of each type
   may be created at a time.

   Whenever code is written that needs a tty or stdio object, the
   code should first call one of the static methods (ttyInstance()
   or stdioInstance()) to see if a console object for the desired
   type exists already.  If the object exists, use it.  If it does
   not exist, the rule is that the relevant code should create the
   object, use the object, and then destroy the object when the
   operation is completed.

   By following the above rule, you can write code that utilizes
   a console without the application having to create some master
   console object for you.  Of course, if the application has
   created a console then it will be used.

   The reason why there is a master console object is that it
   is not guaranteed that all I/O will survive creation and
   destruction of a console object.  If you are using the Stdio
   Type, then you probably want a long-lived console object.  It
   is possible to capture unprocessed I/O by calling
   bytesLeftToRead or bytesLeftToWrite.  However, it is not
   expected that general console-needing code will call these
   functions when utilizing a temporary console.  Thus, an
   application developer would need to create his own console
   object, invoke the console-needing code, and then do his own
   extraction of the unprocessed I/O if necessary.  Another reason
   to extract unprocessed I/O is if you need to switch from
   %Console back to standard functions (e.g. fgets() ).

   \ingroup UserAPI
*/
class QCA_EXPORT Console : public QObject
{
	Q_OBJECT
public:
	/**
	   The type of console object
	*/
	enum Type
	{
		Tty,         ///< physical console
		Stdio        ///< stdin/stdout
	};
	/**
	   The type of I/O to use with the console object.
	*/
	enum ChannelMode
	{
		Read,        ///< Read only (equivalent to stdin)
		ReadWrite    ///< Read/write (equivalent to stdin and stdout)
	};

	/**
	   The nature of the console operation
	*/
	enum TerminalMode
	{
		Default,     ///< use default terminal settings
		Interactive  ///< char-by-char input, no echo
	};

	/**
	   Standard constructor

	   Note that library code should not create a new Console object
	   without checking whether there is already a Console object of
	   the required Type. See the main documentation for Console for the 
	   rationale for this.

	   \param type the Type of Console object to create
	   \param cmode the ChannelMode (I/O type) to use
	   \param tmode the TerminalMode to use
	   \param parent the parent object for this object

	   \sa ttyInstance() and stdioInstance for static methods that allow
	   you to test whether there is already a Console object of the 
	   required Type, and if there is, obtain a reference to that object.
	*/
	Console(Type type, ChannelMode cmode, TerminalMode tmode, QObject *parent = 0);
	~Console();

	/**
	   The Type of this Console object
	*/
	Type type() const;

	/**
	   The ChannelMode of this Console object
	*/
	ChannelMode channelMode() const;

	/**
	   The TerminalMode of this Console object
	*/
	TerminalMode terminalMode() const;

	/**
	   Test whether standard input is redirected.

	   \sa type() and channelMode()
	*/
	static bool isStdinRedirected();

	/**
	   Test whether standard output is redirected.

	   \sa type() and channelMode()
	*/
	static bool isStdoutRedirected();

	/**
	   The current terminal-type console object

	   \return null if there is no current Console
	   of this type, otherwise the Console to use
	*/
	static Console *ttyInstance();

	/**
	   The current stdio-type console object

	   \return null if there is no current Console
	   of this type, otherwise the Console to use
	*/
	static Console *stdioInstance();

	/**
	  Release the Console

	  This allows access to buffers containing any remaining data
	*/
	void release();

	/**
	   Obtain remaining data from the Console, awaiting
	   a read operation
	*/
	QByteArray bytesLeftToRead();

	/**
	   Obtain remaining data from the Console, awaiting
	   a write operation
	*/
	QByteArray bytesLeftToWrite();

private:
	Q_DISABLE_COPY(Console)

	friend class ConsolePrivate;
	ConsolePrivate *d;

	friend class ConsoleReference;
};

/**
   \class ConsoleReference qca_support.h QtCrypto

   Manager for a Console

   \note Only one %ConsoleReference object can be active at a time

   \ingroup UserAPI
*/
class QCA_EXPORT ConsoleReference : public QObject
{
	Q_OBJECT
public:
	/**
	   The security setting to use for the Console being managed.
	*/
	enum SecurityMode
	{
		SecurityDisabled,
		SecurityEnabled
	};

	/**
	   Standard constructor

	   \param parent the parent object for this object
	*/
	ConsoleReference(QObject *parent = 0);
	~ConsoleReference();

	/**
	   Set the Console object to be managed, and start processing.

	   You typically want to use Console::ttyInstance() or
	   Console::stdioInstance() to obtain the required Console
	   reference.

	   \param console reference to the Console to be managed
	   \param mode the SecurityMode to use for this Console.

	   \sa QCA::Console for more information on how to handle the
	   console aspects of your application or library code.
	*/
	bool start(Console *console, SecurityMode mode = SecurityDisabled);

	/**
	   Stop processing, and release the Console
	*/
	void stop();

	/**
	   The Console object managed by this object

	   \sa start() to set the Console to be managed
	*/
	Console *console() const;

	/**
	   The security mode setting for the Console object
	   managed by this object.

	   \sa start() to set the SecurityMode
	*/
	SecurityMode securityMode() const;

	/**
	   Read data from the Console.

	   \param bytes the number of bytes to read. The default 
	   is to read all available bytes

	   \sa readSecure() for a method suitable for reading 
	   sensitive data.
	*/
	QByteArray read(int bytes = -1);

	/**
	   Write data to the Console.

	   \param a the array of data to write to the Console

	   \sa writeSecure() for a method suitable for writing
	   sensitive data.
	*/
	void write(const QByteArray &a);

	/**
	   Read secure data from the Console

	   \param bytes the number of bytes to read. The default 
	   is to read all available bytes

	   \sa read() which is suitable for non-sensitive data
	*/
	SecureArray readSecure(int bytes = -1);

	/**
	   Write secure data to the Console

	   \param a the array of data to write to the Console

	   \sa write() which is suitable for non-sensitive data
	*/
	void writeSecure(const SecureArray &a);

	/**
	   Close the write channel

	   You only need to call this if writing is enabled
	   on the Console being managed.
	*/
	void closeOutput();

	/**
	   The number of bytes available to read from the 
	   Console being managed.
	*/
	int bytesAvailable() const;

	/**
	   The number of bytes remaining to be written
	   to the Console being managed
	*/
	int bytesToWrite() const;

Q_SIGNALS:
	/**
	   Emitted when there are bytes available to read from
	   the Console being managed
	*/
	void readyRead();

	/**
	   Emitted when bytes are written to the Console

	   \param bytes the number of bytes that were written

	   \sa bytesAvailable()
	*/
	void bytesWritten(int bytes);

	/**
	   Emitted when the console input is closed
	*/
	void inputClosed();

	/**
	   Emitted when the console output is closed
	*/
	void outputClosed();

private:
	Q_DISABLE_COPY(ConsoleReference)

	friend class ConsoleReferencePrivate;
	ConsoleReferencePrivate *d;

	friend class Console;
};

/**
   \class ConsolePrompt qca_support.h QtCrypto

   Console prompt handler.

   This class provides a convenient way to get user input in a secure way,
as shown below:
\code
QCA::ConsolePrompt prompt;
prompt.getHidden("Passphrase");
prompt.waitForFinished();
QCA:SecureArray pass = prompt.result();
\endcode

   \note It is not necessary to use waitForFinished(), because you can
   just connect the finished() signal to a suitable method, however
   command line (console) applications often require waitForFinished().

   \ingroup UserAPI
*/
class QCA_EXPORT ConsolePrompt : public QObject
{
	Q_OBJECT
public:
	/**
	   Standard constructor

	   \param parent the parent object for this object
	*/
	ConsolePrompt(QObject *parent = 0);
	~ConsolePrompt();

	/**
	   Allow the user to enter data without it being echo'd to 
	   the terminal. This is particularly useful for entry
	   of passwords, passphrases and PINs.

	   \param promptStr the prompt to display to the user

	   \sa result() for how to get the input back.
	*/
	void getHidden(const QString &promptStr);

	/**
	   Obtain one character from the user

	   \sa resultChar() for how to get the input back.
	*/
	void getChar();

	/**
	   Block waiting for user input.

	   You may wish to use the finished() signal to
	   avoid blocking.
	*/
	void waitForFinished();

	/**
	   Obtain the result of the user input.

	   This method is usually called to obtain data
	   from the user that was requested by the getHidden()
	   call.
	*/
	SecureArray result() const;

	/**
	   Obtain the result of the user input.

	   This method is usually called to obtain data
	   from the user that was requested by the getChar()
	   call.
	*/
	QChar resultChar() const;

Q_SIGNALS:
	/**
	   Emitted when the user input activity has been
	   completed.

	   This corresponds to the provision of a string
	   for getHidden() or a single character for getChar().

	   \sa waitForFinished
	*/
	void finished();

private:
	Q_DISABLE_COPY(ConsolePrompt)

	class Private;
	friend class Private;
	Private *d;
};

class AbstractLogDevice;

/**
   \class Logger qca_support.h QtCrypto

   A simple logging system

   This class provides a simple but flexible approach to logging information
   that may be used for debugging or system operation diagnostics.

   There is a single %Logger for each application that uses %QCA. You do not
   need to create this %Logger yourself - %QCA automatically creates it on
   startup. You can get access to the %Logger using the global QCA::logger()
   method.

   By default the Logger just accepts all messages (binary and text). If you
   want to get access to those messages, you need to subclass
   AbstractLogDevice, and register your subclass (using registerLogDevice()).
   You can then take whatever action is appropriate (e.g. show to the user
   using the GUI, log to a file or send to standard error).

   \ingroup UserAPI
*/
class QCA_EXPORT Logger : public QObject
{
	Q_OBJECT
public:
	/**
	   The severity of the message

	   This information may be used by the log device to determine
	   what the appropriate action is.
	*/
	enum Severity
	{
		Quiet = 0,       ///< Quiet: turn of logging
		Emergency = 1,   ///< Emergency: system is unusable
		Alert = 2,       ///< Alert: action must be taken immediately
		Critical = 3,    ///< Critical: critical conditions
		Error = 4,       ///< Error: error conditions
		Warning = 5,     ///< Warning: warning conditions
		Notice = 6,      ///< Notice: normal but significant condition
		Information = 7, ///< Informational: informational messages
		Debug = 8        ///< Debug: debug-level messages
	};

	/**
	   Get the current logging level

	   \return Current level
	*/
	inline Severity level() const { return m_logLevel; }

	/**
	   Set the current logging level

	   \param level new logging level

	   Only severities less or equal than the log level one will be logged
	*/
	void setLevel(Severity level);

	/**
	   Log a message to all available log devices

	   \param message the text to log
	*/
	void logTextMessage(const QString &message, Severity = Information);

	/**
	   Log a binary blob to all available log devices

	   \param blob the information to log

	   \note how this is handled is quite logger specific. For
	   example, it might be logged as a binary, or it might be
	   encoded in some way
	*/
	void logBinaryMessage(const QByteArray &blob, Severity = Information);

	/**
	   Add an AbstractLogDevice subclass to the existing list of loggers

	   \param logger the LogDevice to add
	*/
	void registerLogDevice(AbstractLogDevice *logger);

	/**
	   Remove an AbstractLogDevice subclass from the existing list of loggers

	   \param loggerName the name of the LogDevice to remove

	   \note If there are several log devices with the same name, all will be removed.
	*/
	void unregisterLogDevice(const QString &loggerName);

	/**
	   Get a list of the names of all registered log devices
	*/
	QStringList currentLogDevices() const;

private:
	Q_DISABLE_COPY(Logger)

	friend class Global;

	/**
	   Create a new message logger
	*/
	Logger();

	~Logger();

	QStringList m_loggerNames;
	QList<AbstractLogDevice*> m_loggers;
	Severity m_logLevel;
};

/**
   \class AbstractLogDevice qca_support.h QtCrypto

   An abstract log device

   \ingroup UserAPI
*/
class QCA_EXPORT AbstractLogDevice : public QObject
{
	Q_OBJECT
public:
	/**
	   The name of this log device
	*/
	QString name() const;

	/**
	   Log a message

	   The default implementation does nothing - you should
	   override this method in your subclass to do whatever
	   logging is required

	   \param message the message to log
	   \param severity the severity level of the message
	*/
	virtual void logTextMessage(const QString &message, Logger::Severity severity);

	/**
	   Log a binary blob

	   The default implementation does nothing - you should
	   override this method in your subclass to do whatever
	   logging is required

	   \param blob the message (as a byte array) to log
	   \param severity the severity level of the message
	*/
	virtual void logBinaryMessage(const QByteArray &blob, Logger::Severity severity);

protected:
	/**
	   Create a new message logger

	   \param name the name of this log device
	   \param parent the parent for this logger
	*/
	explicit AbstractLogDevice(const QString &name, QObject *parent = 0);

	virtual ~AbstractLogDevice() = 0;

private:
	Q_DISABLE_COPY(AbstractLogDevice)

	class Private;
	Private *d;

	QString m_name;
};

}

#endif
