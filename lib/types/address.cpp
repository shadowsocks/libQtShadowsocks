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
    m_data.second = p;
    setAddress(a);
}

Address::Address(const QHostAddress &ip, uint16_t p)
{
    m_data.second = p;
    setIPAddress(ip);
}

const std::string& Address::getAddress() const
{
    return m_data.first;
}

QHostAddress Address::getRandomIP() const
{
    if (m_ipAddrList.empty()) {
        return QHostAddress();
    }
    return m_ipAddrList.at(Common::randomNumber(m_ipAddrList.size()));
}

QHostAddress Address::getFirstIP() const
{
    return m_ipAddrList.empty() ? QHostAddress() : m_ipAddrList.front();
}

bool Address::isIPValid() const
{
    return !m_ipAddrList.empty();
}

uint16_t Address::getPort() const
{
    return m_data.second;
}

void Address::lookUp(Address::LookUpCallback cb)
{
    if (isIPValid()) {
        return cb(true);
    }

    if (m_dns) {
        // DNS lookup is in-progress
        return;
    }

    m_dns = std::make_shared<DnsLookup>();
    QObject::connect(m_dns.get(), &DnsLookup::finished, [cb, this]() {
        m_ipAddrList = m_dns->iplist().toVector().toStdVector();
        cb(!m_ipAddrList.empty());
        m_dns.reset();
    });
    m_dns->lookup(QString::fromStdString(m_data.first));
}

bool Address::blockingLookUp()
{
    if (!isIPValid()) {
        QHostInfo result = QHostInfo::fromName(QString::fromStdString(m_data.first));
        if (result.error() != QHostInfo::NoError) {
            qDebug("Failed to look up host address: %s", result.errorString().toStdString().data());
            return false;
        }
        m_ipAddrList = result.addresses().toVector().toStdVector();
    }
    return true;
}

void Address::setAddress(const std::string &a)
{
    m_data.first = QString::fromStdString(a).trimmed().toStdString();
    m_ipAddrList.clear();
    QHostAddress ipAddress(QString::fromStdString(a));
    if (!ipAddress.isNull()) {
        m_ipAddrList.push_back(ipAddress);
    }
}

void Address::setIPAddress(const QHostAddress &ip)
{
    m_ipAddrList.clear();
    m_ipAddrList.push_back(ip);
    m_data.first = ip.toString().toStdString();
}

void Address::setPort(uint16_t p)
{
    m_data.second = p;
}

Address::ATYP Address::addressType() const
{
    QHostAddress ipAddress(QString::fromStdString(m_data.first));
    if (ipAddress.isNull()) {//it's a domain if it can't be parsed
        return HOST;
    } if (ipAddress.protocol() == QAbstractSocket::IPv4Protocol) {
        return IPV4;
    }
    return IPV6;
}

std::string Address::toString() const
{
    return m_data.first + ":" + std::to_string(m_data.second);
}

}  // namespace QSS
