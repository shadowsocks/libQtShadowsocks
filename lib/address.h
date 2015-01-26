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
#include <QObject>

namespace QSS {

class Address : public QObject
{
    Q_OBJECT
public:
    Address(const QString &a = QString(), const quint16 &p = 0, QObject *parent = 0);
    Address(const QHostAddress &ip, const quint16 &p, QObject *parent = 0);
    Address(const Address &o);

    QString getAddress() const;
    QHostAddress getIPAddress() const;
    QHostAddress getRealIPAddress();//will try to lookup host if ipAddress is null. note it's a blocking operation
    bool isIPValid() const;
    quint16 getPort() const;

    /*
     * Get the "ping" time of this Address
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

    Address& operator = (const Address &o);

    inline bool operator<(const Address &o) const {
        if (this->address == o.address) {
            return this->port < o.port;
        }
        else {
            return this->address < o.address;
        }
    }

    inline bool operator==(const Address &o) const {
        return (this->address == o.address) && (this->port == o.port);
    }

private:
    QString address;
    QHostAddress ipAddress;
    quint16 port;
};

}

#endif // ADDRESS_H
