/*
 * common.h - includes commonly used classes or datatype, including the Common class
 *
 * Copyright (C) 2014-2016 Symeon Huang <hzwhuang@gmail.com>
 *
 * This file is part of the libQtShadowsocks.
 *
 * libQtShadowsocks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libQtShadowsocks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libQtShadowsocks; see the file LICENSE. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef COMMON_H
#define COMMON_H

#include <QByteArray>
#include <QHostAddress>
#include <QVector>
#include <QMutex>
#include "address.h"

namespace QSS {

//fist: r; second: d
typedef QPair<Address, Address> CacheKey;

namespace Common {

QSS_EXPORT const QByteArray version();
QSS_EXPORT QByteArray packAddress(const Address &addr, bool auth = false);
QSS_EXPORT QByteArray packAddress(const QHostAddress &addr, const quint16 &port, bool auth = false);//this will never use ADDRTYPE_HOST because addr is an IP address
QSS_EXPORT void parseHeader(const QByteArray &data, Address &addr, int &length, bool &authFlag);
QSS_EXPORT int randomNumber(int max, int min = 0);//generate a random number which is in the range [min, max)
QSS_EXPORT void exclusive_or(unsigned char *ks, const unsigned char *in, unsigned char *out, quint32 length);
QSS_EXPORT void banAddress(const QHostAddress &addr);
QSS_EXPORT bool isAddressBanned(const QHostAddress &addr);

extern QTextStream qOut;
extern QVector<QHostAddress> bannedAddressVector;
extern QMutex bannedAddressMutex;

extern const quint8 ADDRESS_MASK;
extern const quint8 ONETIMEAUTH_FLAG;
}

}

#endif // COMMON_H
