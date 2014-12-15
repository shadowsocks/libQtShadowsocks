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
#include <QTcpSocket>
#include "controller.h"
#include "connection.h"
#include "encryptor.h"

Controller::Controller(const Profile &p, bool is_local, QObject *parent) :
    QObject(parent),
    isLocal(is_local)
{
    profile = p;
    hasError = false;
    running = false;

    //try to use address directly at first (IP address)
    QHostAddress s_addr(profile.server);
    if (s_addr.isNull()) {
        serverAddrList = QHostInfo::fromName(profile.server).addresses();
        if(serverAddrList.isEmpty()) {//well, we can't get server ip address.
            qCritical() << "Error. Can't look up IP address of server " << profile.server;
            hasError = true;
        }
    }
    else {
        serverAddrList.append(s_addr);
    }

    tcpServer = new QTcpServer(this);
    tcpServer->setMaxPendingConnections(FD_SETSIZE);//FD_SETSIZE which is the maximum value on *nix platforms. (1024 by default)
    udpRelay = new UdpRelay(isLocal, this);
    connectionCollector = new QObjectCleanupHandler;

    connect(tcpServer, &QTcpServer::acceptError, this, &Controller::onTcpServerError);
    connect(tcpServer, &QTcpServer::newConnection, this, &Controller::onNewTCPConnection);

    connect(udpRelay, &UdpRelay::error, this, &Controller::error);
    connect(udpRelay, &UdpRelay::info, this, &Controller::info);
    connect(udpRelay, &UdpRelay::debug, this, &Controller::debug);

    connect(this, &Controller::error, this, &Controller::info);//you shouldn't bind any other classes' error with info (and info with debug). we only need to do that once here.
    connect(this, &Controller::info, this, &Controller::debug);
}

Controller::~Controller()
{
    delete connectionCollector;//we have to delete all connections at first. otherwise, the application will crash.
    qDebug() << "Exited gracefully.";
}

bool Controller::start()
{
    if (hasError) {
        emit error("Can't start due to an error during construction.");
        return false;
    }

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
    running = false;
}


quint16 Controller::getServerPort()
{
    return profile.server_port;
}

QHostAddress Controller::getServerAddr()
{
    if (serverAddrList.isEmpty()) {
        return QHostAddress();
    }
    else {
        return serverAddrList.first();//Todo: maybe randomly pick one?
    }
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

int Controller::getTimeout()
{
    return profile.timeout * 1000;
}

bool Controller::isRunning() const
{
    return running;
}

void Controller::onTcpServerError()
{
    emit error("TCP server error: " + tcpServer->errorString());
}

void Controller::onNewTCPConnection()
{
    QTcpSocket *ts = tcpServer->nextPendingConnection();
    Connection *con = new Connection(ts, isLocal, this);
    connect (con, &Connection::debug, this, &Controller::debug);
    connect (con, &Connection::info, this, &Controller::info);
    connect (con, &Connection::error, this, &Controller::error);
    connectionCollector->add(con);
}
