/*
 * controller.cpp - the source file of Controller class
 *
 * Copyright (C) 2014-2017 Symeon Huang <hzwhuang@gmail.com>
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
#include <QTcpSocket>

#include <botan/init.h>

#include "controller.h"
#include "encryptor.h"

namespace QSS {

Controller::Controller(Profile _profile,
                       bool is_local,
                       bool auto_ban,
                       QObject *parent) :
    QObject(parent),
    bytesReceived(0),
    bytesSent(0),
    profile(std::move(_profile)),
    isLocal(is_local),
    autoBan(auto_ban)
{
#ifndef USE_BOTAN2
    try {
        Botan::LibraryInitializer::initialize("thread_safe");
    } catch (std::exception &e) {
        qFatal("Failed to initialise Botan library: %s", e.what());
    }
#endif

    qInfo("Initialising cipher: %s", profile.method().data());
    /*
     * the default QHostAddress constructor will construct "::" as AnyIPv6
     * we explicitly use Any to enable dual stack
     * which is the case in other shadowsocks ports
     */
    if (profile.serverAddress() == "::") {
        serverAddress = Address(QHostAddress::Any, profile.serverPort());
    } else {
        serverAddress = Address(profile.serverAddress(), profile.serverPort());
        if (!serverAddress.blockingLookUp()) {
            QDebug(QtMsgType::QtCriticalMsg).noquote().nospace()
                    << "Cannot look up the host records of server address "
                    << serverAddress << ". Please make sure your Internet "
                    << "connection is good and the configuration is correct";
        }
    }

    tcpServer = std::make_unique<QSS::TcpServer>(profile.method(),
                                  profile.password(),
                                  profile.timeout(),
                                  isLocal,
                                  autoBan,
                                  serverAddress);

    //FD_SETSIZE which is the maximum value on *nix platforms. (1024 by default)
    tcpServer->setMaxPendingConnections(FD_SETSIZE);
    udpRelay = std::make_unique<QSS::UdpRelay>(profile.method(),
                                profile.password(),
                                isLocal,
                                autoBan,
                                serverAddress);

    connect(tcpServer.get(), &TcpServer::acceptError,
            this, &Controller::onTcpServerError);
    connect(tcpServer.get(), &TcpServer::bytesRead, this, &Controller::onBytesRead);
    connect(tcpServer.get(), &TcpServer::bytesSend, this, &Controller::onBytesSend);
    connect(tcpServer.get(), &TcpServer::latencyAvailable,
            this, &Controller::tcpLatencyAvailable);

    connect(udpRelay.get(), &UdpRelay::bytesRead, this, &Controller::onBytesRead);
    connect(udpRelay.get(), &UdpRelay::bytesSend, this, &Controller::onBytesSend);
}

Controller::~Controller()
{
    if (tcpServer->isListening()) {
        stop();
    }
#ifndef USE_BOTAN2
    Botan::LibraryInitializer::deinitialize();
#endif
}

bool Controller::start()
{
    bool listen_ret = false;

    if (isLocal) {
        qInfo("Running in local mode.");
        listen_ret = tcpServer->listen(
                    getLocalAddr(),
                    profile.httpProxy() ? 0 : profile.localPort());
        if (listen_ret) {
            listen_ret = udpRelay->listen(getLocalAddr(), profile.localPort());
            if (profile.httpProxy() && listen_ret) {
                QDebug(QtMsgType::QtInfoMsg) << "SOCKS5 port is "
                                             << tcpServer->serverPort();
                httpProxy = std::make_unique<QSS::HttpProxy>();
                if (httpProxy->httpListen(getLocalAddr(),
                                          profile.localPort(),
                                          tcpServer->serverPort())) {
                    qInfo("Running as a HTTP proxy server");
                } else {
                    qCritical("HTTP proxy server listen failed.");
                    listen_ret = false;
                }
            }
        }
    } else {
        qInfo("Running in server mode.");
        listen_ret = tcpServer->listen(serverAddress.getFirstIP(),
                                       profile.serverPort());
        if (listen_ret) {
            listen_ret = udpRelay->listen(serverAddress.getFirstIP(),
                                       profile.serverPort());
        }
    }

    if (listen_ret) {
        QDebug(QtMsgType::QtInfoMsg).noquote().nospace()
                << "TCP server listening at "
                << (isLocal ? getLocalAddr().toString() : serverAddress.getFirstIP().toString())
                << ":" << (isLocal ? profile.localPort() : profile.serverPort());
        emit runningStateChanged(true);
    } else {
        qCritical("TCP server listen failed.");
    }

    return listen_ret;
}

void Controller::stop()
{
    if (httpProxy) {
        httpProxy->close();
    }
    tcpServer->close();
    udpRelay->close();
    emit runningStateChanged(false);
    qInfo("Stopped.");
}

QHostAddress Controller::getLocalAddr()
{
    QHostAddress addr(QString::fromStdString(profile.localAddress()));
    if (!addr.isNull()) {
        return addr;
    }
    QDebug(QtMsgType::QtInfoMsg).noquote() << "Can't get address from "
                                           << QString::fromStdString(profile.localAddress())
                                           << ". Using localhost instead.";
    return QHostAddress::LocalHost;
}

void Controller::onTcpServerError(QAbstractSocket::SocketError err)
{
    QDebug(QtMsgType::QtWarningMsg).noquote() << "TCP server error: " << tcpServer->errorString();

    //can't continue if address is already in use
    if (err == QAbstractSocket::AddressInUseError) {
        stop();
    }
}

void Controller::onBytesRead(quint64 r)
{
    if (r != -1) {//-1 means read failed. don't count
        bytesReceived += r;
        emit newBytesReceived(r);
        emit bytesReceivedChanged(bytesReceived);
    }
}

void Controller::onBytesSend(quint64 s)
{
    if (s != -1) {//-1 means write failed. don't count
        bytesSent += s;
        emit newBytesSent(s);
        emit bytesSentChanged(bytesSent);
    }
}

} // namespace QSS
