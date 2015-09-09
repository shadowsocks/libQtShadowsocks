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

#ifdef Q_OS_WIN32
#include <winsock2.h>
#include <windows.h>
#include <Ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

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
    QByteArray ss_header;
    ss_header.reserve(256);
    QByteArray address_str = addr.getAddress().toLocal8Bit();
    quint16 port_net = qToBigEndian(addr.getPort());
    QByteArray port_ns(reinterpret_cast<const char *>(&port_net), 2);

    int type = addr.addressType();
    switch (type) {
    case Address::ADDRTYPE_HOST://should we care if it exceeds 255?
        ss_header.append(static_cast<char>(address_str.length()));
        ss_header += address_str;
        break;
    case Address::ADDRTYPE_IPV4:
        ss_header.resize(INET_ADDRSTRLEN);
        inet_pton(AF_INET, address_str.constData(), reinterpret_cast<void *>(ss_header.data()));
        break;
    case Address::ADDRTYPE_IPV6:
        ss_header.resize(INET6_ADDRSTRLEN);
        inet_pton(AF_INET6, address_str.constData(), reinterpret_cast<void *>(ss_header.data()));
        break;
    }
    ss_header.prepend(static_cast<char>(type));

    return ss_header + port_ns;
}

QByteArray Common::packAddress(const QHostAddress &addr, const quint16 &port)
{
    QByteArray ss_header;
    ss_header.reserve(INET6_ADDRSTRLEN + 1);
    QByteArray address_str = addr.toString().toLocal8Bit();
    quint16 port_net = qToBigEndian(port);
    QByteArray port_ns(reinterpret_cast<const char *>(&port_net), 2);

    if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        ss_header.resize(INET_ADDRSTRLEN);
        inet_pton(AF_INET, address_str.constData(), reinterpret_cast<void *>(ss_header.data()));
        ss_header.prepend(static_cast<char>(Address::ADDRTYPE_IPV4));
    } else {
        ss_header.resize(INET6_ADDRSTRLEN);
        inet_pton(AF_INET6, address_str.constData(), reinterpret_cast<void *>(ss_header.data()));
        ss_header.prepend(static_cast<char>(Address::ADDRTYPE_IPV6));
    }
    return ss_header + port_ns;
}

void Common::parseHeader(const QByteArray &data, Address &dest, int &header_length)
{
    int addrtype = static_cast<int>(data[0]);
    header_length = 0;

    if (addrtype == Address::ADDRTYPE_HOST) {
        if (data.length() > 2) {
            int addrlen = static_cast<int>(data[1]);
            if (data.size() >= 2 + addrlen) {
                QByteArray host = data.mid(2, addrlen);
                dest.setPort(qFromBigEndian(*reinterpret_cast<quint16 *>(data.mid(2 + addrlen, 2).data())));
                dest.setAddress(QString(host));
                header_length = 4 + addrlen;
            }
        }
    } else if (addrtype == Address::ADDRTYPE_IPV4) {
        if (data.length() >= 7) {
            QByteArray d_addr;
            d_addr.resize(INET_ADDRSTRLEN);
            inet_ntop(AF_INET, reinterpret_cast<void *>(data.mid(1, 4).data()), d_addr.data(), INET_ADDRSTRLEN);
            dest.setAddress(QString(d_addr));
            dest.setPort(qFromBigEndian(*reinterpret_cast<quint16 *>(data.mid(5, 2).data())));
            if (dest.isIPValid()) {
                header_length = 7;
            }
        }
    } else if (addrtype == Address::ADDRTYPE_IPV6) {
        if (data.length() >= 19) {
            QByteArray d_addr;
            d_addr.resize(INET_ADDRSTRLEN);
            inet_ntop(AF_INET6, reinterpret_cast<void *>(data.mid(1, 16).data()), d_addr.data(), INET6_ADDRSTRLEN);
            dest.setAddress(QString(d_addr));
            dest.setPort(qFromBigEndian(*reinterpret_cast<quint16 *>(data.mid(17, 2).data())));
            if (dest.isIPValid()) {
                header_length = 19;
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
