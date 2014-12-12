/*
 * address.h - the header file of Address class
 *
 * communicate with lower-level encrytion library
 *
 * Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
 *
 * This file is part of the libQtShadowsocks.
 *
 * libQtShadowsocks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libQtShadowsocks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdnsd; see the file COPYING. If not, see
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
    Address(const Address &o, QObject *parent = 0);

    QString getAddress() const;
    QHostAddress getIPAddress() const;
    QHostAddress getRealIPAddress();//will try to lookup host if ipAddress is null. note it's a blocking operation
    bool isIPValid() const;
    quint16 getPort() const;

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
