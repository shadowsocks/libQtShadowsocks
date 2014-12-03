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

#include "basecontroller.h"

BaseController::BaseController(const Profile &p, QObject *parent) :
    QObject(parent)
{
    profile = p;

    tcpServer = new QTcpServer(this);
    tcpServer->setMaxPendingConnections(1024);//1024 is the default FD_SETSIZE value on Linux.
    udpRelay = new UdpRelay(this);

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

QString BaseController::getServerAddr()
{
    return profile.server;
}

quint16 BaseController::getLocalPort()
{
    return profile.local_port;
}

QHostAddress BaseController::getLocalAddr()
{
    return profile.shareOverLAN ? QHostAddress::Any : QHostAddress::LocalHost;
}

void BaseController::onTcpServerError()
{
    QString str = QString("tcp server error: ") + tcpServer->errorString();
    emit error(str);
}

void BaseController::onNewConnection()
{
    QTcpSocket *ts = tcpServer->nextPendingConnection();
    qintptr tsd = ts->socketDescriptor();

    Connection *con = NULL;

    foreach (Connection *c, conList) {
        if (tsd == c->socketDescriptor) {
            con = c;
        }
    }

    if (con == NULL) {
        con = new Connection(ts, this);
        conList.append(con);
        connect (con, &Connection::disconnected, this, &BaseController::onConnectionDisconnected);
        connect (con, &Connection::info, this, &BaseController::info);
        connect (con, &Connection::error, this, &BaseController::error);
    }
    else {
        con->appendTcpSocket(ts);
    }
}

void BaseController::onConnectionDisconnected()
{
    Connection *con = qobject_cast<Connection *>(sender());
    if (con) {
        conList.removeOne(con);
        con->deleteLater();
        emit info("a connection closed");
        QString str = QString("current connections: ") + QString::number(conList.size());
        emit info(str);
    }
    else {
        emit error("a false sender called onConnectionDisconnected slot");
    }
}
