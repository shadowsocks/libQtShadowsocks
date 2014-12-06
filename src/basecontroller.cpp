/*
 * basecontroller.cpp - the source file of BaseController class
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

#include <QHostInfo>
#include "basecontroller.h"

BaseController::BaseController(const Profile &p, QObject *parent) :
    QObject(parent)
{
    profile = p;
    serverAddrList = QHostInfo::fromName(profile.server).addresses();
    Q_ASSERT(!serverAddrList.isEmpty());

    tcpServer = new QTcpServer(this);
    tcpServer->setMaxPendingConnections(1024);//1024 is the default FD_SETSIZE value on Linux.

    connect(tcpServer, &QTcpServer::acceptError, this, &BaseController::onTcpServerError);
    connect(tcpServer, &QTcpServer::newConnection, this, &BaseController::onNewConnection);
}

BaseController::~BaseController()
{
    if (running) {
        stop();
    }
}

void BaseController::stop()
{
    tcpServer->close();
    running = false;
}


quint16 BaseController::getServerPort()
{
    return profile.server_port;
}

QHostAddress BaseController::getServerAddr()
{
    return serverAddrList.first();//Todo: maybe randomly pick one?
}

Address BaseController::getAServer()
{
    return Address(serverAddrList.first(), profile.server_port);//TODO
}

quint16 BaseController::getLocalPort()
{
    return profile.local_port;
}

QHostAddress BaseController::getLocalAddr()
{
    return profile.shareOverLAN ? QHostAddress::Any : QHostAddress::LocalHost;
}

Connection *BaseController::socketDescriptorInList(qintptr tsd)
{
    Connection *found = NULL;
    QtConcurrent::blockingMap(conList, [&](Connection *c) {//would this be faster than the old foreach loop?
        if (tsd == c->socketDescriptor) {
            found = c;
        }
    });
    return found;
}

void BaseController::onTcpServerError()
{
    QString str = QString("tcp server error: ") + tcpServer->errorString();
    emit error(str);
}

void BaseController::onConnectionDisconnected()
{
    Connection *con = qobject_cast<Connection *>(sender());
    if (con) {
        conList.removeOne(con);
        con->deleteLater();
        emit connectionCountChanged(conList.size());
    }
    else {
        emit error("a false sender called onConnectionDisconnected slot");
    }
}
