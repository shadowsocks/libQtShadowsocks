/*
 * address.cpp - the source file of Address class
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

#include <QHostInfo>
#include "address.h"

using namespace QSS;

Address::Address(const QString &a, const quint16 &p, QObject *parent) :
    QObject(parent),
    address(a),
    port(p)
{
    ipAddress.setAddress(a);
}

Address::Address(const QHostAddress &ip, const quint16 &p, QObject *parent) :
    QObject(parent),
    ipAddress(ip),
    port(p)
{}

Address::Address(const Address &o, QObject *parent) :
    QObject(parent)
{
    *this = o;
}

QString Address::getAddress() const
{
    return address;
}

QHostAddress Address::getIPAddress() const
{
    return ipAddress;
}

QHostAddress Address::getRealIPAddress()
{
    if (ipAddress.isNull()) {
        //lookup the host
        QList<QHostAddress> ipList = QHostInfo::fromName(address).addresses();
        if (ipList.isEmpty()) {
            qWarning() << "Can't look up the IP addresses of " << address;
        }
        else {
            ipAddress = ipList.first();
        }
    }
    return ipAddress;
}

bool Address::isIPValid() const
{
    return !ipAddress.isNull();
}

quint16 Address::getPort() const
{
    return port;
}

void Address::setAddress(const QString &a)
{
    address = a;
    ipAddress.setAddress(a);
}

void Address::setIPAddress(const QHostAddress &i)
{
    ipAddress = i;
    address = i.toString();
}

void Address::setPort(const quint16 &p)
{
    port = p;
}

int Address::addressType() const
{
    if (ipAddress.isNull()) {//it's a domain if it can't be parsed
        return ADDRTYPE_HOST;
    }
    else if (ipAddress.protocol() == QAbstractSocket::IPv4Protocol) {
        return ADDRTYPE_IPV4;
    }
    else {
        return ADDRTYPE_IPV6;
    }
}

Address &Address::operator = (const Address &o)
{
    this->address = o.getAddress();
    this->ipAddress = o.getIPAddress();
    this->port = o.getPort();
    return *this;
}
