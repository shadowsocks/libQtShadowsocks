/*
 * common.h - includes commonly used classes or datatype, including the Common class
 *
 * Copyright (C) 2014-2015 Symeon Huang <hzwhuang@gmail.com>
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
#include "address.h"

namespace QSS {

class CacheKey
{
public:
    CacheKey(const QString &ra = QString(), const quint16 &rp = 0, const QString &da = QString(), const quint16 &dp = 0) : r(ra, rp), d(da, dp) {}
    CacheKey(const QHostAddress &rip, const quint16 &rp, const QHostAddress &dip, const quint16 &dp) : r(rip, rp), d(dip, dp) {}
    CacheKey(const QHostAddress &rip, const quint16 &rp, const Address &dA) : r(rip, rp), d(dA) {}
    CacheKey(const Address &rA, const Address &dA) : r(rA), d(dA) {}

    Address r;
    Address d;

    inline bool operator<(const CacheKey &o) const {
        if (this->r == o.r) {
            return this->d < o.d;
        }
        else {
            return this->r < o.r;
        }
    }
};

class Common//provide some common functions
{
public:
    virtual ~Common() = 0;//You should never initialise Common class.
    static QByteArray packAddress(const Address &addr);
    static QByteArray packAddress(const QHostAddress &addr, const quint16 &port);//this will never use ADDRTYPE_HOST because addr is an IP address
    static void parseHeader(const QByteArray &data, Address &addr, int &length);
};

inline void exclusive_or(unsigned char *ks, const unsigned char *in, unsigned char *out, quint32 length)
{
    unsigned char *end_ks = ks + length;
    do {
        *out = *in ^ *ks;
        ++out; ++in; ++ks;
    } while (ks < end_ks);
}

}

#endif // COMMON_H
