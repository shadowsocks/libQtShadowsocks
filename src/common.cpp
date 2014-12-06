/*
 * common.cpp - the source file of Common class
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

#include <QDebug>
#include <QHostInfo>
#ifdef Q_OS_WIN32
    #include <windows.h>
#else
    #include <arpa/inet.h>
#endif
#include "common.h"
using namespace QSS;

QByteArray Common::packAddress(const QHostAddress &addr, const quint16 &port)//TODO FIX
{
    QByteArray address_str = addr.toString().toLatin1();
    QByteArray port_str = QString::number(port).toLatin1();
    if (addr.protocol() == QAbstractSocket::IPv6Protocol || addr.protocol() == QAbstractSocket::AnyIPProtocol) {
        return char(4) + address_str + port_str;
    }
    else {// if (addr.protocol() == QAbstractSocket::IPv4Protocol) {
        return char(1) + address_str + port_str;
    }
    /*if (address_str.length() > 255) {
        address_str = address_str.mid(0, 255);
    }*/
    //return char(3) + static_cast<char>(address_str.length()) + address_str + port_str;
}

void Common::parseHeader(const QByteArray &data, QHostAddress &addr, quint16 &port, int &length)
{
    int addrtype = static_cast<int>(data[0]);
    int header_length = 0;
    QHostAddress dest_addr;
    quint16 dest_port = 0;

    if (addrtype == ADDRTYPE_HOST) {
        //always lookup it
        if (data.length() > 2) {
            int addrlen = static_cast<int>(data[1]);
            if (data.size() >= 2 + addrlen) {
                QByteArray host = data.mid(2, addrlen);
                QList<QHostAddress> addrList = QHostInfo::fromName(host).addresses();
                if (addrList.isEmpty()) {
                    qWarning() << "Cannot look up the IP addresses of " << host;
                }
                else {
                    dest_addr = addrList.first();
                }
                dest_port = ntohs(*reinterpret_cast<quint16 *>(data.mid(2 + addrlen, 2).data()));
                header_length = 4 + addrlen;
            }
            else {
                qDebug() << "header is too short";
            }
        }
        else {
            qDebug() << "header is too short";
        }
    }
    else if (addrtype == ADDRTYPE_IPV4) {
        if (data.length() >= 7) {
            dest_addr = QHostAddress(data.mid(1, 4).toUInt());//TODO FIX
            dest_port = ntohs(*reinterpret_cast<quint16 *>(data.mid(5, 2).data()));
            header_length = 7;
        }
        else {
            qDebug() << "header is too short";
        }
    }
    else if (addrtype == ADDRTYPE_IPV6) {
        if (data.length() > 19) {
            dest_addr = QHostAddress(data.mid(1, 16).toUInt());//TODO FIX
            dest_port = ntohs(*reinterpret_cast<quint16 *>(data.mid(17, 2).data()));
            header_length = 19;
        }
        else {
            qDebug() << "header is too short";
        }
    }
    else {
        qDebug() << "unsupported addrtype" << addrtype << "maybe wrong password";
    }
    if (dest_addr.isNull()) {
        qDebug() << "parsing header to get address failed";
    }
    addr = dest_addr;
    port = dest_port;
    length = header_length;
}
