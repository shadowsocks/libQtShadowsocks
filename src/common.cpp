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
#include "common.h"
using namespace QSS;

void Common::parseHeader(const QByteArray &data, QHostAddress &addr, quint16 &port, int &length)
{
    int addrtype = static_cast<int>(data[0]);
    int header_length = 0;
    QString dest_addr;
    quint16 dest_port = 0;
    if (addrtype == ADDRTYPE_IPV4) {
        if (data.length() >= 7) {
            dest_addr = QString(data.mid(1, 4));
            dest_port = data.mid(5, 2).toInt();
            header_length = 7;
        }
        else {
            qDebug() << "header is too short";
        }
    }
    else if (addrtype == ADDRTYPE_HOST) {
        if (data.length() > 2) {
            int addrlen = static_cast<int>(data[1]);
            if (data.size() >= 2 + addrlen) {
                dest_addr = data.mid(2, addrlen);
                dest_port = data.mid(2 + addrlen, 2).toInt();
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
    else if (addrtype == ADDRTYPE_IPV6) {
        if (data.length() > 19) {
            dest_addr = QString(data.mid(1, 16));
            dest_port = data.mid(17, 2).toInt();
            header_length = 19;
        }
        else {
            qDebug() << "header is too short";
        }
    }
    else {
        qDebug() << "unsupported addrtype" << addrtype << "maybe wrong password";
    }
    if (dest_addr.isEmpty()) {
        qDebug() << "parsing header to get address failed";
        return;
    }
    addr = QHostAddress(dest_addr);
    port = dest_port;
    length = header_length;
}
