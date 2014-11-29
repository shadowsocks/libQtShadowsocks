/*
 * Copyright (C) 2003-2007  Justin Karneges <justin@affinix.com>
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
   \file qpipe.h

   Header file for the QPipe FIFO class

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QPIPE_H
#define QPIPE_H

#ifndef DOXYGEN_SHOULD_SKIP_THIS

#ifndef QPIPE_NO_SECURE
# define QPIPE_SECURE
#endif

#ifdef QPIPE_SECURE
# include "QtCrypto"
#else
# define QCA_EXPORT
#endif

// defs adapted qprocess_p.h
#ifdef Q_OS_WIN
#include <windows.h>
typedef HANDLE Q_PIPE_ID;
#define INVALID_Q_PIPE_ID INVALID_HANDLE_VALUE
#else
typedef int Q_PIPE_ID;
#define INVALID_Q_PIPE_ID -1
#endif

#endif

// Note: for Windows console, I/O must be in UTF-8.  Reads are guaranteed to
//   to completely decode (no partial characters).  Likewise, writes must
//   not contain partial characters.

namespace QCA {


/**
   \class QPipeDevice qpipe.h QtCrypto

   Unbuffered direct pipe.

   This class is not usually required except for very low level operations.
   You should use QPipe and QPipeEnd for most applications.

   \ingroup UserAPI
*/
class QCA_EXPORT QPipeDevice : public QObject
{
	Q_OBJECT
public:
        /**
	   The type of device
	*/
	enum Type
	{
		Read, ///< The pipe end can be read from
		Write ///< The pipe end can be written to
	};

	/**
	   Standard constructor

	   \param parent the parent object to this object
	*/
	QPipeDevice(QObject *parent = 0);
	~QPipeDevice();

	/**
	   The Type of the pipe device (that is, read or write)
	*/
	Type type() const;

	/**
	   Test whether this object corresponds to a valid pipe
	*/
	bool isValid() const;

	/**
	   The low level identification for this pipe.

	   On Windows, this is a HANDLE. On Unix, this is a file descriptor (i.e. integer).

	   Code using this method should be carefully tested for portability.

	   \sa idAsInt
	*/
	Q_PIPE_ID id() const;

	/**
	   The low level identification for this pipe, returned as an integer.

	   Code using this method should be carefully tested for portability.

	   \sa id().
	*/
	int idAsInt() const;

	/**
	   Take over an existing pipe id, closing the old pipe if any.

	   \param id the identification of the pipe end to take over.
	   \param t the type of pipe end (read or write).
	*/
	void take(Q_PIPE_ID id, Type t);

	/**
	   Enable the pipe for reading or writing (depending on Type)
	*/
	void enable();

	/**
	   Close the pipe end.
	*/
	void close();

	/**
	   Release the pipe end, but do not close it.
	*/
	void release();

	/**
	   Set the pipe end to be inheritable

	   \note On Windows, this operation changes the pipe end id value.

	   \param enabled whether the pipe is inheritable (true) or not (false)
	*/
	bool setInheritable(bool enabled);

	/**
	   Obtain the number of bytes available to be read.
	*/
	int bytesAvailable() const;

	/**
	   Read from the pipe end

	   \param data where to put the data that has been read
	   \param maxsize the maximum number of bytes to be read.

	   \return the actual number of bytes read, 0 on end-of-file, or -1 on error.
	*/
	int read(char *data, int maxsize);

	/**
	   Write to the pipe end.

	   \param data the source of the data to be written
	   \param size the number of bytes in the data to be written

	   \note the data source must remain valid

	   \return the number of bytes written, or -1 on error.
	*/
	int write(const char *data, int size);

	/**
	   The result of a write operation

	   \param written if not null, this will be set to the number of 
	   bytes written in the last operation.

	   \return 0 on success (all data written), or -1 on error
	*/
	int writeResult(int *written) const;

Q_SIGNALS:
	/**
	   Emitted when the pipe end can be read from or written to (depending on its Type).
	*/
	void notify();

private:
	Q_DISABLE_COPY(QPipeDevice)

	class Private;
	friend class Private;
	Private *d;
};

/**
   \class QPipeEnd qpipe.h QtCrypto

   A buffered higher-level pipe end

   This is either the read end or write end of a QPipe.

   \ingroup UserAPI
*/
class QCA_EXPORT QPipeEnd : public QObject
{
	Q_OBJECT
public:

	/**
	   The type of error
	*/ 
	enum Error
	{
		ErrorEOF,    ///< End of file error
		ErrorBroken  ///< Broken pipe error
	};

	/**
	   Standard constructor

	   \param parent the parent object for this object
	*/
	QPipeEnd(QObject *parent = 0);

	~QPipeEnd();

	/**
	   Reset the pipe end to an inactive state
	*/
	void reset();

	/**
	   The type of pipe end (either read or write)
	*/
	QPipeDevice::Type type() const;

	/**
	   Determine whether the pipe end is valid.

	   \note This does not mean the pipe is ready to be used - you
	   may need to call enable() first
	*/
	bool isValid() const;

	/**
	   Pipe identification
	*/
	Q_PIPE_ID id() const;

	/**
	   Pipe identification
	*/
	int idAsInt() const;

	/**
	   Take over an existing pipe handle

	   \param id the pipe handle
	   \param t the type of the pipe (read or write)
	*/
	void take(Q_PIPE_ID id, QPipeDevice::Type t);

#ifdef QPIPE_SECURE
	/**
	   Sets whether the pipe uses secure memory for read/write

	   Enabling this may reduce performance, and it should only be used if
	   sensitive data is being transmitted (such as a passphrase).

	   \param secure whether the pipe uses secure memory (true) or not (false).
	*/
	void setSecurityEnabled(bool secure);
#endif

	/**
	   Enable the endpoint for the pipe

	   When an endpoint is created, it is not
	   able to be used until it is enabled.
	*/
	void enable();

	/**
	   Close the end of the pipe

	   \sa closed()
	*/
	void close();

	/**
	   Let go of the active pipe handle, but don't close it

	   Use this before destructing QPipeEnd, if you don't want the pipe
	   to automatically close.
	*/
	void release();

	/**
	   Sets whether the pipe should be inheritable to child processes

	   Returns true if inheritability was successfully changed, otherwise
	   false.

	   \param enabled whether the pipe is inheritable (true) or not (false).
	*/
	bool setInheritable(bool enabled);

	/**
	   Clear the contents of the pipe, and invalidate the pipe
	*/
	void finalize();

	/**
	   Clear the contents of the pipe, and release the pipe
	*/
	void finalizeAndRelease();

	/**
	   Determine how many bytes are available to be read.

	   This only makes sense at the read end of the pipe

	   \sa readyRead() for a signal that can be used to determine
	   when there are bytes available to read.
	*/
	int bytesAvailable() const;

	/**
	   Returns the number of bytes pending to write

	   This only makes sense at the write end of the pipe

	   \sa bytesWritten() for a signal that can be used to determine
	   when bytes have been written
	*/
	int bytesToWrite() const;

	/**
	   Read bytes from the pipe. 

	   You can only call this on the read end of the pipe

	   If the pipe is using secure memory, you should use readSecure()

	   \param bytes the number of bytes to read (-1 for all 
	   content).
	*/
	QByteArray read(int bytes = -1);

	/**
	   Write bytes to the pipe.

	   You can only call this on the write end of the pipe.

	   If the pipe is using secure memory, you should use writeSecure().

	   \param a the array to write to the pipe
	*/
	void write(const QByteArray &a);

#ifdef QPIPE_SECURE
	/**
	   Read bytes from the pipe. 

	   You can only call this on the read end of the pipe

	   If the pipe is using insecure memory, you should use read()

	   \param bytes the number of bytes to read (-1 for all 
	   content).
	*/
	SecureArray readSecure(int bytes = -1);

	/**
	   Write bytes to the pipe.

	   You can only call this on the write end of the pipe.

	   If the pipe is using insecure memory, you should use write().

	   \param a the array to write to the pipe
	*/
	void writeSecure(const SecureArray &a);
#endif

	/**
	   Returns any unsent bytes queued for writing

	   If the pipe is using secure memory, you should use
	   takeBytesToWriteSecure().
	*/
	QByteArray takeBytesToWrite();

#ifdef QPIPE_SECURE
	/**
	   Returns any unsent bytes queued for writing

	   If the pipe is using insecure memory, you should use
	   takeBytesToWrite().
	*/
	SecureArray takeBytesToWriteSecure();
#endif

Q_SIGNALS:
	/**
	   Emitted when there are bytes available to be read
	   from the read end of the pipe.

	   \sa bytesAvailable()
	*/
	void readyRead();

	/**
	   Emitted when bytes have been written to the 
	   write end of the pipe.

	   \param bytes the number of bytes written
	*/
	void bytesWritten(int bytes);

	/**
	   Emitted when this end of the pipe is closed as a result of calling
	   close()

	   If this is the write end of the pipe and there is data still
	   pending to write, this signal will be emitted once all of the data
	   has been written.

	   To be notified if the other end of the pipe has been closed, see
	   error().
	*/
	void closed();

	/**
	   Emitted when the pipe encounters an error trying to read or write,
	   or if the other end of the pipe has been closed

	   \param e the reason for error
	*/
	void error(QCA::QPipeEnd::Error e);

private:
	Q_DISABLE_COPY(QPipeEnd)

	class Private;
	friend class Private;
	Private *d;
};

/**
   \class QPipe qpipe.h QtCrypto

   A FIFO buffer (named pipe) abstraction

   This class creates a full buffer, consisting of two ends
   (QPipeEnd). You can obtain each end (after calling create()) using
   readEnd() and writeEnd(), however you must call enable() on each end
   before using the pipe.

   By default, the pipe ends are not inheritable by child processes.  On
   Windows, the pipe is created with inheritability disabled.  On Unix, the
   FD_CLOEXEC flag is set on each end's file descriptor.

   \ingroup UserAPI
*/
class QCA_EXPORT QPipe
{
public:
	/**
	   Standard constructor

	   \note You must call create() before using the pipe ends.

	   \param parent the parent object for this object
	*/
	QPipe(QObject *parent = 0);

	~QPipe();

	/**
	   Reset the pipe.

	   At this point, the readEnd() and writeEnd() calls
	   will no longer be valid.
	*/
	void reset();

#ifdef QPIPE_SECURE
	/**
	   Create the pipe

	   \param secure whether to use secure memory (true) or not (false)
	*/
	bool create(bool secure = false);
#else
	/**
	   Create the pipe
	*/
	bool create();
#endif

	/**
	   The read end of the pipe.
	*/
	QPipeEnd & readEnd() { return i; }

	/**
	   The write end of the pipe.
	*/
	QPipeEnd & writeEnd() { return o; }

private:
	Q_DISABLE_COPY(QPipe)

	QPipeEnd i, o;
};

}

#endif
