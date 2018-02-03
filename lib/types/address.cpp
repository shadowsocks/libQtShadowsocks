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

#include "address.h"
#include "util/common.h"

namespace  QSS {

void DnsLookup::lookup(const QString& hostname)
{
    QHostInfo::lookupHost(hostname, this, SLOT(lookedUp(QHostInfo)));
}

const QList<QHostAddress> DnsLookup::iplist() const
{
    return m_ips;
}

void DnsLookup::lookedUp(const QHostInfo &info)
{
    if (info.error() != QHostInfo::NoError) {
        qWarning("DNS lookup failed: %s", info.errorString().toStdString().data());
    } else {
        m_ips = info.addresses();
    }
    emit finished();
}

Address::Address(const std::string &a, uint16_t p)
{
    data.second = p;
    setAddress(a);
}

Address::Address(const QHostAddress &ip, uint16_t p)
{
    data.second = p;
    setIPAddress(ip);
}

const std::string& Address::getAddress() const
{
    return data.first;
}

QHostAddress Address::getRandomIP() const
{
    if (ipAddrList.empty()) {
        return QHostAddress();
    }
    return ipAddrList.at(Common::randomNumber(ipAddrList.size()));
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

void Address::lookUp(Address::LookUpCallback cb)
{
    if (isIPValid()) {
        return cb(true);
    }

    if (dns) {
        // DNS lookup is in-progress
        return;
    }

    dns = std::make_shared<DnsLookup>();
    QObject::connect(dns.get(), &DnsLookup::finished, [cb, this]() {
        ipAddrList = dns->iplist().toVector().toStdVector();
        cb(!ipAddrList.empty());
        dns.reset();
    });
    dns->lookup(QString::fromStdString(data.first));
}

bool Address::blockingLookUp()
{
    if (!isIPValid()) {
        QHostInfo result = QHostInfo::fromName(QString::fromStdString(data.first));
        if (result.error() != QHostInfo::NoError) {
            qDebug("Failed to look up host address: %s", result.errorString().toStdString().data());
            return false;
        }
        ipAddrList = result.addresses().toVector().toStdVector();
    }
    return true;
}

void Address::setAddress(const std::string &a)
{
    data.first = QString::fromStdString(a).trimmed().toStdString();
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
    } if (ipAddress.protocol() == QAbstractSocket::IPv4Protocol) {
        return IPV4;
    }
    return IPV6;
}

std::string Address::toString() const
{
    return data.first + ":" + std::to_string(data.second);
}

}  // namespace QSS
