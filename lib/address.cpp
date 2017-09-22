/*
 * address.cpp - the source file of Address class
 *
 * communicate with lower-level encrytion library
 *
 * Copyright (C) 2014-2017 Symeon Huang <hzwhuang@gmail.com>
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

Address::Address(const std::string &a, uint16_t p) :
    QObject()
{
    data.second = p;
    setAddress(a);
}

Address::Address(const QHostAddress &ip, uint16_t p) :
    QObject()
{
    data.second = p;
    setIPAddress(ip);
}

Address::Address(const Address &o) :
    QObject()
{
    *this = o;
}

const std::string& Address::getAddress() const
{
    return data.first;
}

QHostAddress Address::getRandomIP() const
{
    if (ipAddrList.empty()) {
        return QHostAddress();
    } else {
        return ipAddrList.at(Common::randomNumber(ipAddrList.size()));
    }
}

QHostAddress Address::getFirstIP() const
{
    return ipAddrList.empty() ? QHostAddress() : ipAddrList.front();
}

bool Address::isIPValid() const
{
    return !ipAddrList.empty();
}

uint16_t Address::getPort() const
{
    return data.second;
}

void Address::lookUp()
{
    if (isIPValid()) {
        emit lookedUp(true, QString());
    } else {
        QHostInfo::lookupHost(QString::fromStdString(data.first),
                              this,
                              SLOT(onLookUpFinished(QHostInfo)));
    }
}

void Address::blockingLookUp()
{
    if (isIPValid()) {
        return;
    }

    QHostInfo result = QHostInfo::fromName(QString::fromStdString(data.first));
    ipAddrList = result.addresses().toVector().toStdVector();
}

void Address::setAddress(const std::string &a)
{
    data.first = a;//TODO: trim
    ipAddrList.clear();
    QHostAddress ipAddress(QString::fromStdString(a));
    if (!ipAddress.isNull()) {
        ipAddrList.push_back(ipAddress);
    }
}

void Address::setIPAddress(const QHostAddress &ip)
{
    ipAddrList.clear();
    ipAddrList.push_back(ip);
    data.first = ip.toString().toStdString();
}

void Address::setPort(uint16_t p)
{
    data.second = p;
}

Address::ATYP Address::addressType() const
{
    QHostAddress ipAddress(QString::fromStdString(data.first));
    if (ipAddress.isNull()) {//it's a domain if it can't be parsed
        return HOST;
    } else if (ipAddress.protocol() == QAbstractSocket::IPv4Protocol) {
        return IPV4;
    } else {
        return IPV6;
    }
}

std::string Address::toString() const
{
    return data.first + ":" + std::to_string(data.second);
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
        ipAddrList = host.addresses().toVector().toStdVector();
        emit lookedUp(true, QString());
    }
}
