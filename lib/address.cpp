/*
 * address.cpp - the source file of Address class
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

#include "common.h"
#include "address.h"

using namespace QSS;

Address::Address(const QString &a, const quint16 &p, QObject *parent) :
    QObject(parent)
{
    data.second = p;
    setAddress(a);
}

Address::Address(const QHostAddress &ip, const quint16 &p, QObject *parent) :
    QObject(parent)
{
    data.second = p;
    setIPAddress(ip);
}

Address::Address(const Address &o) :
    QObject(o.parent())
{
    *this = o;
}

QString Address::getAddress() const
{
    return data.first;
}

QHostAddress Address::getRandomIP() const
{
    if (ipAddrList.isEmpty()) {
        return QHostAddress();
    } else {
        return ipAddrList.at(Common::randomNumber(ipAddrList.count()));
    }
}

QHostAddress Address::getFirstIP() const
{
    return ipAddrList.isEmpty() ? QHostAddress() : ipAddrList.first();
}

bool Address::isIPValid() const
{
    return !ipAddrList.isEmpty();
}

quint16 Address::getPort() const
{
    return data.second;
}

void Address::lookUp()
{
    if (isIPValid()) {
        emit lookedUp(true, QString());
    } else {
        QHostInfo::lookupHost(data.first, this, SLOT(onLookUpFinished(QHostInfo)));
    }
}

void Address::blockingLookUp()
{
    if (isIPValid()) {
        return;
    }

    QHostInfo result = QHostInfo::fromName(data.first);
    ipAddrList = result.addresses();
}

void Address::setAddress(const QString &a)
{
    data.first = a;
    ipAddrList.clear();
    QHostAddress ipAddress(a);
    if (!ipAddress.isNull()) {
        ipAddrList.append(ipAddress);
    }
}

void Address::setIPAddress(const QHostAddress &ip)
{
    ipAddrList.clear();
    ipAddrList.append(ip);
    data.first = ip.toString();
}

void Address::setPort(const quint16 &p)
{
    data.second = p;
}

Address::ATYP Address::addressType() const
{
    QHostAddress ipAddress(data.first);
    if (ipAddress.isNull()) {//it's a domain if it can't be parsed
        return HOST;
    } else if (ipAddress.protocol() == QAbstractSocket::IPv4Protocol) {
        return IPV4;
    } else {
        return IPV6;
    }
}

QString Address::toString() const
{
    return QString("%1:%2").arg(data.first).arg(QString::number(data.second));
}

Address &Address::operator= (const Address &o)
{
    this->data = o.data;
    this->ipAddrList = o.ipAddrList;
    return *this;
}

void Address::onLookUpFinished(const QHostInfo &host)
{
    if (host.error() != QHostInfo::NoError) {
        emit lookedUp(false, host.errorString());
    } else {
        ipAddrList = host.addresses();
        emit lookedUp(true, QString());
    }
}
