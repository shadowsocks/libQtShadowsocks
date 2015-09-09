/*
 * common.cpp - the source file of Common class
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

#include <QTextStream>
#include <QHostInfo>
#include <QtEndian>
#include <random>
#include "common.h"

using namespace QSS;

QTextStream Common::qOut(stdout, QIODevice::WriteOnly | QIODevice::Unbuffered);
QVector<QByteArray> Common::failedIVVector;
QVector<QHostAddress> Common::failedAddressVector;
QVector<QHostAddress> Common::bannedAddressVector;
QMutex Common::failedIVMutex;
QMutex Common::failedAddressMutex;
QMutex Common::bannedAddressMutex;

const QByteArray Common::version()
{
    return QSS_VERSION;
}

QByteArray Common::packAddress(const Address &addr)//pack a shadowsocks header
{
    QByteArray type_bin, addr_bin, port_ns;
    port_ns.resize(2);
    qToBigEndian(addr.getPort(), reinterpret_cast<uchar*>(port_ns.data()));

    int type = addr.addressType();
    type_bin.append(static_cast<char>(type));
    if (type == Address::ADDRTYPE_HOST) {//should we care if it exceeds 255?
        QByteArray address_str = addr.getAddress().toLocal8Bit();
        addr_bin.append(static_cast<char>(address_str.length()));
        addr_bin += address_str;
    } else {
        bool ipv4;
        quint32 ipv4_addr = qToBigEndian(addr.getFirstIP().toIPv4Address(&ipv4));
        if (ipv4) {
            addr_bin = QByteArray(reinterpret_cast<char*>(&ipv4_addr), 4);
        } else {
            Q_IPV6ADDR ipv6_addr = addr.getFirstIP().toIPv6Address();//Q_IPV6ADDR is a 16-unsigned-char struct (big endian)
            addr_bin = QByteArray(reinterpret_cast<char*>(ipv6_addr.c), 16);
        }
    }

    return type_bin + addr_bin + port_ns;
}

QByteArray Common::packAddress(const QHostAddress &addr, const quint16 &port)
{
    QByteArray type_bin, addr_bin, port_ns;
    bool ipv4;
    quint32 ipv4_addr = qToBigEndian(addr.toIPv4Address(&ipv4));
    port_ns.resize(2);
    qToBigEndian(port, reinterpret_cast<uchar*>(port_ns.data()));
    if (ipv4) {
        type_bin.append(static_cast<char>(Address::ADDRTYPE_IPV4));
        addr_bin = QByteArray(reinterpret_cast<char*>(&ipv4_addr), 4);
    } else {
        type_bin.append(static_cast<char>(Address::ADDRTYPE_IPV6));
        Q_IPV6ADDR ipv6_addr = addr.toIPv6Address();
        addr_bin = QByteArray(reinterpret_cast<char*>(ipv6_addr.c), 16);
    }
    return type_bin + addr_bin + port_ns;
}

void Common::parseHeader(const QByteArray &data, Address &dest, int &header_length)
{
    int addrtype = static_cast<int>(data[0]);
    header_length = 0;

    if (addrtype == Address::ADDRTYPE_HOST) {
        if (data.length() > 2) {
            int addrlen = static_cast<int>(data[1]);
            if (data.size() >= 2 + addrlen) {
                dest.setPort(qFromBigEndian(*reinterpret_cast<const quint16 *>(data.data() + 2 + addrlen)));
                dest.setAddress(QString(data.mid(2, addrlen)));
                header_length = 4 + addrlen;
            }
        }
    } else if (addrtype == Address::ADDRTYPE_IPV4) {
        if (data.length() >= 7) {
            QHostAddress addr(qFromBigEndian(*reinterpret_cast<const quint32 *>(data.data() + 1)));
            if (!addr.isNull()) {
                header_length = 7;
                dest.setIPAddress(addr);
                dest.setPort(qFromBigEndian(*reinterpret_cast<const quint16 *>(data.data() + 5)));
            }
        }
    } else if (addrtype == Address::ADDRTYPE_IPV6) {
        if (data.length() >= 19) {
            Q_IPV6ADDR ipv6_addr;
            memcpy(ipv6_addr.c, data.data() + 1, 16);
            QHostAddress addr(ipv6_addr);
            if (!addr.isNull()) {
                header_length = 19;
                dest.setIPAddress(addr);
                dest.setPort(qFromBigEndian(*reinterpret_cast<const quint16 *>(data.data() + 17)));
            }
        }
    }
}

int Common::randomNumber(int max, int min)
{
    std::random_device rd;
    std::default_random_engine engine(rd());
    std::uniform_int_distribution<int> dis(min, max - 1);
    return dis(engine);
}

void Common::exclusive_or(unsigned char *ks, const unsigned char *in, unsigned char *out, quint32 length)
{
    unsigned char *end_ks = ks + length;
    do {
        *out = *in ^ *ks;
        ++out; ++in; ++ks;
    } while (ks < end_ks);
}
