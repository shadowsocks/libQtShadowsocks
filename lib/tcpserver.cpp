/*
 * tcpserver.cpp
 *
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

#include "tcpserver.h"
#include "tcprelay.h"
#include "common.h"
#include <QThread>

using namespace QSS;

TcpServer::TcpServer(const EncryptorPrivate &ep, const int &timeout, const bool &is_local, const bool &auto_ban, const bool &auth, const Address &serverAddress, QObject *parent) :
    QTcpServer(parent),
    isLocal(is_local),
    autoBan(auto_ban),
    auth(auth),
    serverAddress(serverAddress),
    timeout(timeout),
    ep(ep)
{}

TcpServer::~TcpServer()
{
    socketsCleaner.clear();
}

void TcpServer::clear()
{
    socketsCleaner.clear();
}

void TcpServer::incomingConnection(qintptr socketDescriptor)
{
    QTcpSocket *localSocket = new QTcpSocket;
    localSocket->setSocketDescriptor(socketDescriptor);

    if (!isLocal && autoBan && Common::isAddressBanned(localSocket->peerAddress())) {
        emit debug(QString("A banned IP %1 attempted to access this server").arg(localSocket->peerAddress().toString()));
        localSocket->deleteLater();
        return;
    }

    //timeout * 1000: convert sec to msec
    TcpRelay *con = new TcpRelay(localSocket, timeout * 1000, serverAddress, ep, isLocal, autoBan, auth);
    QThread *thread = new QThread(this);
    connect(con, &TcpRelay::info, this, &TcpServer::info);
    connect(con, &TcpRelay::debug, this, &TcpServer::debug);
    connect(con, &TcpRelay::bytesRead, this, &TcpServer::bytesRead);
    connect(con, &TcpRelay::bytesSend, this, &TcpServer::bytesSend);
    connect(con, &TcpRelay::finished, thread, &QThread::quit);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);
    connect(thread, &QThread::finished, con, &TcpServer::deleteLater);
    con->moveToThread(thread);
    thread->start();
}
