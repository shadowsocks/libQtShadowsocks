/*
 * controller.cpp - the source file of Controller class
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

#include <QHostInfo>
#include <QTcpSocket>
#include <botan/init.h>

#include "controller.h"
#include "connection.h"
#include "encryptor.h"

using namespace QSS;

Controller::Controller(bool is_local, QObject *parent) :
    QObject(parent),
    isLocal(is_local)
{
    Botan::LibraryInitializer::initialize();

    valid = false;

    tcpServer = new QTcpServer(this);
    tcpServer->setMaxPendingConnections(FD_SETSIZE);//FD_SETSIZE which is the maximum value on *nix platforms. (1024 by default)

    udpRelay = new UdpRelay(isLocal, this);
    connectionCollector = new QObjectCleanupHandler;

    connect(tcpServer, &QTcpServer::acceptError, this, &Controller::onTcpServerError);
    connect(tcpServer, &QTcpServer::newConnection, this, &Controller::onNewTCPConnection);

    connect(udpRelay, &UdpRelay::error, this, &Controller::error);
    connect(udpRelay, &UdpRelay::info, this, &Controller::info);
    connect(udpRelay, &UdpRelay::debug, this, &Controller::debug);
    connect(udpRelay, &UdpRelay::bytesRead, this, &Controller::onBytesRead);
    connect(udpRelay, &UdpRelay::bytesSend, this, &Controller::onBytesSend);

    connect(this, &Controller::error, this, &Controller::info);//you shouldn't bind any other classes' error with info (and info with debug). we only need to do that once here.
    connect(this, &Controller::info, this, &Controller::debug);
}

Controller::Controller(const Profile &_profile, bool is_local, QObject *parent) :
    Controller(is_local, parent)
{
    setup(_profile);
}

Controller::~Controller()
{
    delete connectionCollector;//we have to delete all connections at first. otherwise, the application will crash.
    Botan::LibraryInitializer::deinitialize();
}

bool Controller::setup(const Profile &p)
{
    profile = p;

    /*
     * the default QHostAddress constructor will construct "::" as AnyIPv6
     * we explicitly use Any to enable dual stack which is the case in other shadowsocks ports
     */
    if (p.server == "::") {
        serverAddress = Address(QHostAddress::Any, p.server_port);
    } else {
        serverAddress = Address(p.server, p.server_port);
    }

    if (serverAddress.isIPValid()) {
        valid = true;
    } else {
        if (isLocal) {
            emit error("Error. Can't look up IP address of server " + profile.server);
            valid = false;
        } else {
            emit error("Error. Can't get a valid IP address of server. Shadowsocks server will listen on all addresses.");
            serverAddress.setIPAddress(QHostAddress::Any);
            valid = true;
        }
    }

    emit info("Initialising ciphers...");
    if (!Encryptor::initialise(profile.method, profile.password)) {
        emit error("Initialisation failed.");
        valid = false;
    } else {
        emit info(Encryptor::getInternalMethodName() + " (" + profile.method + ") initialised.");
    }

    udpRelay->setup(serverAddress, getLocalAddr(), profile.local_port);

    return valid;
}

bool Controller::start()
{
    if (!valid) {
        emit error("Controller is not valid. Maybe improper setup?");
        return false;
    }

    bool listen_ret = false;

    QString sstr("TCP server listen at port ");
    if (isLocal) {
        emit info("Running in local mode.");
        listen_ret = tcpServer->listen(getLocalAddr(), profile.local_port);
        sstr.append(QString::number(profile.local_port));
    } else {
        emit info("Running in server mode.");
        listen_ret = tcpServer->listen(getServerAddr(), profile.server_port);
        sstr.append(QString::number(profile.server_port));
    }
    emit info(sstr);

    if (listen_ret) {
        emit runningStateChanged(true);
    } else {
        emit error("Listen failed.");
    }

    return listen_ret;
}

void Controller::stop()
{
    tcpServer->close();
    connectionCollector->clear();
    emit runningStateChanged(false);
    emit debug("Stopped.");
}

quint16 Controller::getServerPort() const
{
    return profile.server_port;
}

QHostAddress Controller::getServerAddr()
{
    return serverAddress.getIPAddress();
}

QString Controller::getServerString() const
{
    return profile.server;
}

quint16 Controller::getLocalPort() const
{
    return profile.local_port;
}

QHostAddress Controller::getLocalAddr()
{
    QHostAddress addr(profile.local_address);
    if (!addr.isNull()) {
        return addr;
    } else {
        emit error("Can't get address from " + profile.local_address.toLocal8Bit() + ". Using localhost instead.");
        return QHostAddress::LocalHost;
    }
}

int Controller::getTimeout() const
{
    return profile.timeout * 1000;
}

void Controller::onTcpServerError(QAbstractSocket::SocketError err)
{
    emit error("TCP server error: " + tcpServer->errorString());

    //can't continue if address is already in use
    if (err == QAbstractSocket::AddressInUseError) {
        stop();
    }
}

void Controller::onNewTCPConnection()
{
    QTcpSocket *ts = tcpServer->nextPendingConnection();
    Connection *con = new Connection(ts, isLocal, this);
    connect (con, &Connection::debug, this, &Controller::debug);
    connect (con, &Connection::info, this, &Controller::info);
    connect (con, &Connection::error, this, &Controller::error);
    connect (con, &Connection::bytesRead, this, &Controller::onBytesRead);
    connect (con, &Connection::bytesSend, this, &Controller::onBytesSend);
    connectionCollector->add(con);
}

void Controller::onBytesRead(const qint64 &r)
{
    if (r != -1) {//-1 means read failed. don't count
        bytesReceived += r;
        emit newBytesReceived(r);
        emit bytesReceivedChanged(bytesReceived);
    }
}

void Controller::onBytesSend(const qint64 &s)
{
    if (s != -1) {//-1 means write failed. don't count
        bytesSent += s;
        emit newBytesSent(s);
        emit bytesSentChanged(bytesSent);
    }
}
