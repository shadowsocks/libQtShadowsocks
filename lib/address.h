/*
 * address.h - the header file of Address class
 *
 * communicate with lower-level encrytion library
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

#ifndef ADDRESS_H
#define ADDRESS_H

#include <QString>
#include <QHostAddress>
#include <QPair>
#include <QObject>
#include "export.h"

namespace QSS {

class QSS_EXPORT Address : public QObject
{
    Q_OBJECT
public:
    Address(const QString &a = QString(), const quint16 &p = 0, QObject *parent = 0);
    Address(const QHostAddress &ip, const quint16 &p, QObject *parent = 0);
    Address(const Address &o);
    Address(Address &&) = default;//force the generation of default move constructor

    QString getAddress() const;

    /*
     * return a random IP address from ipAddrList if it's non-empty.
     * otherwise, it'll call getRealIPAddress() function
     */
    QHostAddress getIPAddress();

    /*
     * getRealIPAddress() will try to lookup host if ipAddrList is empty and return the first result.
     * Note it's a blocking operation
     * You're recommended to use getIPAddress() function rather than calling this function.
     */
    QHostAddress getRealIPAddress();

    bool isIPValid();
    quint16 getPort() const;

    /*
     * Get the "ping" time of this Address (note: this is a blocking operation)
     * return -1 if the target can't be connected before timed out (3000 ms by default)
     * otherwise, the time used to connect will be returned
     */
    int ping(int timeout = 3000);

    void setAddress(const QString &);
    void setIPAddress(const QHostAddress &);
    void setPort(const quint16 &);

    static const int ADDRTYPE_IPV4 = 1;
    static const int ADDRTYPE_IPV6 = 4;
    static const int ADDRTYPE_HOST = 3;

    int addressType() const;

    Address& operator= (const Address &o);

    inline bool operator< (const Address &o) const {
        return this->data < o.data;
    }

    inline bool operator== (const Address &o) const {
        return this->data == o.data;
    }

signals:
    void pingError(const QString &);

private:
    QPair<QString, quint16> data;//first: address string; second: port
    QList<QHostAddress> ipAddrList;

    void lookUpIP();
};

}

#endif // ADDRESS_H
