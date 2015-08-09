/*
 * Copyright (C) 2015 Symeon Huang <hzwhuang@gmail.com>
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

#include "mtsocketthread.h"
#include "tcprelay.h"

using namespace QSS;

MTSocketThread::MTSocketThread(int socketDescriptor, const int &timeout, const Address &server, const EncryptorPrivate *ep, const bool &isLocal, QObject *parent) :
    QThread(parent),
    socketDescriptor(socketDescriptor),
    isLocal(isLocal),
    timeout(timeout),
    ep(ep),
    serverAddress(server)
{}

void MTSocketThread::run()
{
    QTcpSocket local, remote;
    if (!local.setSocketDescriptor(socketDescriptor)) {
        emit error(local.error());
        return;
    }

    TcpRelay con(local, remote, timeout, serverAddress, ep, isLocal);
    connect (&con, &TcpRelay::finished, this, &MTSocketThread::quit);
    connect (&con, &TcpRelay::info, this, &MTSocketThread::info);
    connect (&con, &TcpRelay::debug, this, &MTSocketThread::debug);
    connect (&con, &TcpRelay::bytesRead, this, &MTSocketThread::bytesRead);
    connect (&con, &TcpRelay::bytesSend, this, &MTSocketThread::bytesSend);

    exec();
}

