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

#include <QDebug>
#include <QHostInfo>

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

QByteArray Common::packAddress(const Address &addr)//pack a shadowsocks header
{
    QByteArray ss_header;
    QByteArray address_str = addr.getAddress().toLocal8Bit();
    QByteArray address_bin;
    quint16 port_net = htons(addr.getPort());
    QByteArray port_ns = QByteArray::fromRawData(reinterpret_cast<char *>(&port_net), 2);

    int type = addr.addressType();
    ss_header.append(static_cast<char>(type));
    switch (type) {
    case Address::ADDRTYPE_HOST://should we care if it exceeds 255?
        ss_header.append(static_cast<char>(address_str.length()));
        ss_header += address_str;
        break;
    case Address::ADDRTYPE_IPV4:
        address_bin.resize(INET_ADDRSTRLEN);
        inet_pton(AF_INET, address_str.constData(), reinterpret_cast<void *>(address_bin.data()));
        ss_header += address_bin;
        break;
    case Address::ADDRTYPE_IPV6:
        address_bin.resize(INET6_ADDRSTRLEN);
        inet_pton(AF_INET6, address_str.constData(), reinterpret_cast<void *>(address_bin.data()));
        ss_header += address_bin;
        break;
    default:
        qWarning() << "Unknown address type. Shouldn't get here.";
    }
    return ss_header + port_ns;
}

QByteArray Common::packAddress(const QHostAddress &addr, const quint16 &port)
{
    QByteArray type;
    quint16 port_net = htons(port);
    QByteArray port_ns = QByteArray::fromRawData(reinterpret_cast<char *>(&port_net), 2);
    if (addr.protocol() == QAbstractSocket::IPv6Protocol) {
        type.append(static_cast<char>(Address::ADDRTYPE_IPV6));
    } else {
        type.append(static_cast<char>(Address::ADDRTYPE_IPV4));
    }
    return type + addr.toString().toLocal8Bit() + port_ns;
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
                dest.setPort(ntohs(*reinterpret_cast<quint16 *>(data.mid(2 + addrlen, 2).data())));
                dest.setAddress(QString(host));
                header_length = 4 + addrlen;
            } else {
                qDebug() << "Host header is too short";
            }
        } else {
            qDebug() << "Host header is too short to contain a port";
        }
    } else if (addrtype == Address::ADDRTYPE_IPV4) {
        if (data.length() >= 7) {
            QByteArray d_addr(INET_ADDRSTRLEN, '0');
            inet_ntop(AF_INET, reinterpret_cast<void *>(data.mid(1, 4).data()), d_addr.data(), INET_ADDRSTRLEN);
            dest.setAddress(QString(d_addr));
            dest.setPort(ntohs(*reinterpret_cast<quint16 *>(data.mid(5, 2).data())));
            header_length = 7;
        } else {
            qDebug() << "IPv4 header is too short";
        }
    } else if (addrtype == Address::ADDRTYPE_IPV6) {
        if (data.length() >= 19) {
            QByteArray d_addr(INET6_ADDRSTRLEN, '0');
            inet_ntop(AF_INET6, reinterpret_cast<void *>(data.mid(1, 16).data()), d_addr.data(), INET6_ADDRSTRLEN);
            dest.setAddress(QString(d_addr));
            dest.setPort(ntohs(*reinterpret_cast<quint16 *>(data.mid(17, 2).data())));
            header_length = 19;
        } else {
            qDebug() << "IPv6 header is too short";
        }
    } else {
        qDebug() << "Unsupported addrtype" << addrtype << "maybe wrong password";
    }
}

int Common::randomNumber(int max, int min)
{
    std::random_device rd;
    std::default_random_engine engine(rd());
    std::uniform_int_distribution<int> dis(min, max - 1);
    return dis(engine);
}
