/*
 * controller.cpp - the source file of Controller class
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
#include "controller.h"

Controller::Controller(const Profile &p, bool is_local, QObject *parent) :
    QObject(parent),
    isLocal(is_local)
{
    profile = p;
    serverAddrList = QHostInfo::fromName(profile.server).addresses();
    Q_ASSERT(!serverAddrList.isEmpty());

    tcpServer = new QTcpServer(this);
    tcpServer->setMaxPendingConnections(FD_SETSIZE);//FD_SETSIZE which is the maximum value on *nix platforms. (1024 by default)
    udpRelay = new UdpRelay(isLocal, this);

    connect(tcpServer, &QTcpServer::acceptError, this, &Controller::onTcpServerError);
    connect(tcpServer, &QTcpServer::newConnection, this, &Controller::onNewConnection);
}

Controller::~Controller()
{
    if (running) {
        stop();
    }
}

bool Controller::start()
{
    emit info("Initialising ciphers...");
    if (!Encryptor::initialise(profile.method, profile.password)) {
        emit error("Initialisation failed.");
        return false;
    }

    emit info(Encryptor::getInternalMethodName() + " (" + profile.method + ") initialised.");
    QString sstr("TCP server listen at port ");
    if (isLocal) {
        emit info("Running in local mode.");
        tcpServer->listen(getLocalAddr(), profile.local_port);
        sstr.append(QString::number(profile.local_port));
    }
    else {
        emit info("Running in server mode.");
        tcpServer->listen(getServerAddr(), profile.server_port);
        sstr.append(QString::number(profile.server_port));
    }
    emit info(sstr);

    running = true;
    return true;
}

void Controller::stop()
{
    tcpServer->close();
    while (!conList.isEmpty()) {
        Connection *con = conList.takeLast();
        con->deleteLater();
    }
    emit connectionCountChanged(conList.size());
    running = false;
}


quint16 Controller::getServerPort()
{
    return profile.server_port;
}

QHostAddress Controller::getServerAddr()
{
    return serverAddrList.first();//Todo: maybe randomly pick one?
}

quint16 Controller::getLocalPort()
{
    return profile.local_port;
}

QHostAddress Controller::getLocalAddr()
{
    QHostAddress addr(profile.local_address);
    if (!addr.isNull()) {
        return addr;
    }
    else {
        emit error("Can't get address from " + profile.local_address.toLocal8Bit() + ". Using localhost instead.");
        return QHostAddress::LocalHost;
    }
}

bool Controller::isRunning() const
{
    return running;
}

Connection *Controller::socketDescriptorInList(qintptr tsd)
{
    Connection *found = NULL;
    QtConcurrent::blockingMap(conList, [&](Connection *c) {//would this be faster than the old foreach loop?
        if (tsd == c->socketDescriptor) {
            found = c;
        }
    });
    return found;
}

void Controller::onTcpServerError()
{
    QString str = QString("TCP server error: ") + tcpServer->errorString();
    emit error(str);
}

void Controller::onNewConnection()
{
    QTcpSocket *ts = tcpServer->nextPendingConnection();
    Connection *con = socketDescriptorInList(ts->socketDescriptor());

    if (con == NULL) {
        con = new Connection(ts, isLocal, this);
        conList.append(con);
        connect (con, &Connection::disconnected, this, &Controller::onConnectionDisconnected);
        connect (con, &Connection::info, this, &Controller::info);
        connect (con, &Connection::error, this, &Controller::error);
        emit connectionCountChanged(conList.size());
    }
    else {
        con->appendTcpSocket(ts);
    }
}

void Controller::onConnectionDisconnected()
{
    Connection *con = qobject_cast<Connection *>(sender());
    if (con) {
        conList.removeOne(con);
        con->deleteLater();
        emit connectionCountChanged(conList.size());
    }
    else {
        emit error("A false sender called onConnectionDisconnected slot");
    }
}
