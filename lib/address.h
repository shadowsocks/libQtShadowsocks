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
#include <QHostInfo>
#include <QPair>
#include <QObject>
#include "export.h"

namespace QSS {

class QSS_EXPORT Address : public QObject
{
    Q_OBJECT
public:
    explicit Address(const QString &a = QString(), const quint16 &p = 0, QObject *parent = 0);
    explicit Address(const QHostAddress &ip, const quint16 &p, QObject *parent = 0);
    Address(const Address &o);
    Address(Address &&) = default;//force the generation of default move constructor

    QString getAddress() const;

    /*
     * Because the ipAddrList might include both IPv4 and IPv6 addresses
     * getRandomIP() will literally return a random IP address (either IPv4 or IPv6)
     * If there is no valid IP, a default constructed QHostAddress will be returned.
     * TODO: detect IPv4/IPv6 reachability automatically
     */
    QHostAddress getRandomIP() const;

    /*
     * Normally the order is platform-dependent and it'd consider IPv4 and IPv6 precedence
     * which *might* be more suitable to use this function to get a reachable IP address
     * If there is no valid IP, a default constructed QHostAddress will be returned.
     */
    QHostAddress getFirstIP() const;

    bool isIPValid() const;
    quint16 getPort() const;

    /*
     * lookedUp signal will pass if it's successful
     * then you can use getRandomIP() to get a random IP address
     * Note this function will emit lookedUp signal immediately if there is already a valid IP
     */
    void lookUp();

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

    friend QDataStream& operator<< (QDataStream &os, const Address &addr)
    {
        os << QString("%1:%2").arg(addr.ipAddrList.first().toString()).arg(addr.data.second);
        return os;
    }

    friend QDebug& operator<< (QDebug &os, const Address &addr)
    {
        os << QString("%1:%2").arg(addr.ipAddrList.first().toString()).arg(addr.data.second);
        return os;
    }

signals:
    void lookedUp(const bool success, const QString errStr);

private:
    QPair<QString, quint16> data;//first: address string; second: port
    QList<QHostAddress> ipAddrList;

private slots:
    void onLookUpFinished(const QHostInfo &host);
};

}

#endif // ADDRESS_H
