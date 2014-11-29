/*
 * qca_textfilter.h - Qt Cryptographic Architecture
 * Copyright (C) 2003-2005  Justin Karneges <justin@affinix.com>
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
   \file qca_textfilter.h

   Header file for text encoding/decoding classes

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_TEXTFILTER_H
#define QCA_TEXTFILTER_H

#include "qca_core.h"

namespace QCA {

/**
   \class TextFilter qca_textfilter.h QtCrypto

   Superclass for text based filtering algorithms

   This differs from Filter in that it has the concept
   of an algorithm that works in two directions, and 
   supports operations on QString arguments.

   \ingroup UserAPI
*/
class QCA_EXPORT TextFilter : public Filter
{
public:
	/**
	   Standard constructor

	   \param dir the Direction that this TextFilter
	   should use.
	*/
	TextFilter(Direction dir);

	/**
	   Reset the TextFilter

	   \param dir the Direction that this TextFilter
	   should use.
	*/
	void setup(Direction dir);

	/**
	   The direction the TextFilter is set up to use
	*/
	Direction direction() const;

	/**
	   Process an array in the "forward" direction,
	   returning an array

	   This method runs in the forward direction, so
	   for something like a Base64 encoding, it takes
	   the "native" array, and returns that array 
	   encoded in base64.

	   \param a the array to encode
	*/
	MemoryRegion encode(const MemoryRegion &a);

	/**
	   Process an array in the "reverse" direction,
	   returning an array

	   This method runs in the reverse direction, so
	   for something like a Base64 encoding, it takes
	   a Base64 encoded array, and returns the "native"
	   representation.

	   \param a the array to decode
	*/
	MemoryRegion decode(const MemoryRegion &a);

	/**
	   Process an array in the "forward" direction,
	   returning a QString

	   This is equivalent to encode(), except
	   that it returns a QString, rather than a
	   byte array.

	   \param a the array to encode
	*/
	QString arrayToString(const MemoryRegion &a);

	/**
	   Process an string in the "reverse" direction,
	   returning a byte array

	   This is equivalent to decode(), except
	   that it takes a QString, rather than a
	   byte array.

	   \param s the array to decode
	*/
	MemoryRegion stringToArray(const QString &s);

	/**
	   Process a string in the "forward" direction,
	   returning a string

	   This is equivalent to encode(), except
	   that it takes and returns a QString, rather than
	   byte arrays.

	   \param s the string to encode
	*/
	QString encodeString(const QString &s);

	/**
	   Process a string in the "reverse" direction,
	   returning a string

	   This is equivalent to decode(), except
	   that it takes and returns a QString, rather than
	   byte arrays.

	   \param s the string to decode
	*/
	QString decodeString(const QString &s);

protected:
	/**
	   Internal state variable for the Direction
	   that the filter operates in
	*/
	Direction _dir;
};

/**
   \class Hex qca_textfilter.h QtCrypto

   Hexadecimal encoding / decoding

   \ingroup UserAPI
*/
class QCA_EXPORT Hex : public TextFilter
{
public:
	/**
	   Standard constructor

	   \param dir the Direction that should be used.

	   \note The direction can be changed using
	   the setup() call.
	*/
	Hex(Direction dir = Encode);

	/**
	   Reset the internal state.

	   This is useful to reuse an existing Hex object
	*/
	virtual void clear();

	/**
	   Process more data, returning the corresponding
	   encoded or decoded (depending on the Direction
	   set in the constructor or setup() call) representation.

	   If you find yourself with code that only calls
	   this method once, you might be better off using
	   encode() or decode(). Similarly, if the data is
	   really a string, you might be better off using
	   arrayToString(), encodeString(), stringToArray()
	   or decodeString().

	   \param a the array containing data to process
	*/
	virtual MemoryRegion update(const MemoryRegion &a);

	/**
	   Complete the algorithm

	   \return any remaining output. Because of the way
	   hexadecimal encoding works, this will return a 
	   zero length array - any output will have been returned
	   from the update() call.
	*/
	virtual MemoryRegion final();

	/**
	   Test if an update() or final() call succeeded.
	 
	   \return true if the previous call succeeded
	*/
	virtual bool ok() const;

private:
	Q_DISABLE_COPY(Hex)

	uchar val;
	bool partial;
	bool _ok;
};

/**
   \class Base64 qca_textfilter.h QtCrypto

   %Base64 encoding / decoding

   \ingroup UserAPI
*/
class QCA_EXPORT Base64 : public TextFilter
{
public:
	/**
	   Standard constructor

	   \param dir the Direction that should be used.

	   \note The direction can be changed using
	   the setup() call.
	*/
	Base64(Direction dir = Encode);

	/**
	   Returns true if line breaks are enabled
	*/
	bool lineBreaksEnabled() const;

	/**
	   Returns the line break column
	*/
	int lineBreaksColumn() const;

	/**
	   Sets line break mode.  If enabled, linebreaks will be
	   added to encoded output or accepted in encoded input.
	   If disabled, linebreaks in encoded input will cause
	   a failure to decode.  The default is disabled.

	   \param b whether to enable line breaks (true) or disable line breaks (false)
	*/
	void setLineBreaksEnabled(bool b);

	/**
	   Sets the column that linebreaks should be inserted at
	   when encoding.

	   \param column the column number that line breaks should be inserted at.
	*/
	void setLineBreaksColumn(int column);

	/**
	   Reset the internal state. This is useful to 
	   reuse an existing Base64 object
	*/
	virtual void clear();

	/**
	   Process more data, returning the corresponding
	   encoded or decoded (depending on the Direction
	   set in the constructor or setup() call) representation.

	   If you find yourself with code that only calls
	   this method once, you might be better off using
	   encode() or decode(). Similarly, if the data is
	   really a string, you might be better off using
	   arrayToString(), encodeString(), stringToArray()
	   or decodeString().

	   \param a the array containing data to process
	*/
	virtual MemoryRegion update(const MemoryRegion &a);

	/**
	   Complete the algorithm

	   \return any remaining output. Because of the way
	   Base64 encoding works, you will get either an 
	   empty array, or an array containing one or two
	   "=" (equals, 0x3D) characters.
	*/
	virtual MemoryRegion final();

	/**
	   Test if an update() or final() call succeeded.
	 
	   \return true if the previous call succeeded
	*/
	virtual bool ok() const;

private:
	Q_DISABLE_COPY(Base64)

	QByteArray partial;
	bool _ok;
	int col;
	bool _lb_enabled;
	int _lb_column;

	class Private;
	Private *d;
};

}

#endif
