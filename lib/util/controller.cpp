/*
 * controller.cpp - the source file of Controller class
 *
 * Copyright (C) 2014-2018 Symeon Huang <hzwhuang@gmail.com>
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

#ifndef USE_BOTAN2
#include <botan/init.h>
#endif

#include "controller.h"
#include "crypto/encryptor.h"

namespace QSS {

Controller::Controller(Profile _profile,
                       bool is_local,
                       bool auto_ban,
                       QObject *parent) :
    QObject(parent),
    m_bytesReceived(0),
    m_bytesSent(0),
    m_profile(std::move(_profile)),
    m_isLocal(is_local),
    m_autoBan(auto_ban)
{
#ifndef USE_BOTAN2
    try {
        botanInit = std::make_unique<Botan::LibraryInitializer>("thread_safe");
    } catch (std::exception &e) {
        qFatal("Failed to initialise Botan library: %s", e.what());
    }
#endif

    qInfo("Initialising cipher: %s", m_profile.method().data());
    /*
     * the default QHostAddress constructor will construct "::" as AnyIPv6
     * we explicitly use Any to enable dual stack
     * which is the case in other shadowsocks ports
     */
    if (m_profile.serverAddress() == "::") {
        m_serverAddress = Address(QHostAddress::Any, m_profile.serverPort());
    } else {
        m_serverAddress = Address(m_profile.serverAddress(), m_profile.serverPort());
        if (!m_serverAddress.blockingLookUp()) {
            QDebug(QtMsgType::QtCriticalMsg).noquote().nospace()
                    << "Cannot look up the host records of server address "
                    << m_serverAddress << ". Please make sure your Internet "
                    << "connection is good and the configuration is correct";
        }
    }

    m_tcpServer = std::make_unique<QSS::TcpServer>(
                    [this]() { return std::make_unique<Encryptor>(m_profile.method(), m_profile.password()); },
                    m_profile.timeout(),
                    m_isLocal,
                    m_autoBan,
                    m_serverAddress);

    //FD_SETSIZE which is the maximum value on *nix platforms. (1024 by default)
    m_tcpServer->setMaxPendingConnections(FD_SETSIZE);
    m_udpRelay = std::make_unique<QSS::UdpRelay>(
                   [this]() { return std::make_unique<Encryptor>(m_profile.method(), m_profile.password()); },
                   m_isLocal,
                   m_autoBan,
                   m_serverAddress);

    connect(m_tcpServer.get(), &TcpServer::acceptError,
            this, &Controller::onTcpServerError);
    connect(m_tcpServer.get(), &TcpServer::bytesRead, this, &Controller::onBytesRead);
    connect(m_tcpServer.get(), &TcpServer::bytesSend, this, &Controller::onBytesSend);
    connect(m_tcpServer.get(), &TcpServer::latencyAvailable,
            this, &Controller::tcpLatencyAvailable);

    connect(m_udpRelay.get(), &UdpRelay::bytesRead, this, &Controller::onBytesRead);
    connect(m_udpRelay.get(), &UdpRelay::bytesSend, this, &Controller::onBytesSend);
}

Controller::~Controller()
{
    if (m_tcpServer->isListening()) {
        stop();
    }
}

bool Controller::start()
{
    bool listen_ret = false;

    if (m_isLocal) {
        qInfo("Running in local mode.");
        QHostAddress localAddress = m_profile.httpProxy()
            ? QHostAddress::LocalHost
            : getLocalAddr();
        listen_ret = m_tcpServer->listen(
                    localAddress,
                    m_profile.httpProxy() ? 0 : m_profile.localPort());
        if (listen_ret) {
            listen_ret = m_udpRelay->listen(localAddress, m_profile.localPort());
            if (m_profile.httpProxy() && listen_ret) {
                QDebug(QtMsgType::QtInfoMsg) << "SOCKS5 port is"
                                             << m_tcpServer->serverPort();
                m_httpProxy = std::make_unique<QSS::HttpProxy>();
                if (m_httpProxy->httpListen(getLocalAddr(),
                                          m_profile.localPort(),
                                          m_tcpServer->serverPort())) {
                    qInfo("Running as a HTTP proxy server");
                } else {
                    qCritical("HTTP proxy server listen failed.");
                    listen_ret = false;
                }
            }
        }
    } else {
        qInfo("Running in server mode.");
        listen_ret = m_tcpServer->listen(m_serverAddress.getFirstIP(),
                                       m_profile.serverPort());
        if (listen_ret) {
            listen_ret = m_udpRelay->listen(m_serverAddress.getFirstIP(),
                                       m_profile.serverPort());
        }
    }

    if (listen_ret) {
        QDebug(QtMsgType::QtInfoMsg).noquote().nospace()
                << "TCP server listening at "
                << (m_isLocal ? getLocalAddr().toString() : m_serverAddress.getFirstIP().toString())
                << ":" << (m_isLocal ? m_profile.localPort() : m_profile.serverPort());
        emit runningStateChanged(true);
    } else {
        qCritical("TCP server listen failed.");
    }

    return listen_ret;
}

void Controller::stop()
{
    if (m_httpProxy) {
        m_httpProxy->close();
    }
    m_tcpServer->close();
    m_udpRelay->close();
    emit runningStateChanged(false);
    qInfo("Stopped.");
}

QHostAddress Controller::getLocalAddr()
{
    QHostAddress addr(QString::fromStdString(m_profile.localAddress()));
    if (!addr.isNull()) {
        return addr;
    }
    QDebug(QtMsgType::QtInfoMsg).noquote() << "Can't get address from "
                                           << QString::fromStdString(m_profile.localAddress())
                                           << ". Using localhost instead.";
    return QHostAddress::LocalHost;
}

void Controller::onTcpServerError(QAbstractSocket::SocketError err)
{
    QDebug(QtMsgType::QtWarningMsg).noquote() << "TCP server error: " << m_tcpServer->errorString();

    //can't continue if address is already in use
    if (err == QAbstractSocket::AddressInUseError) {
        stop();
    }
}

void Controller::onBytesRead(quint64 r)
{
    if (r != -1) {//-1 means read failed. don't count
        m_bytesReceived += r;
        emit newBytesReceived(r);
        emit bytesReceivedChanged(m_bytesReceived);
    }
}

void Controller::onBytesSend(quint64 s)
{
    if (s != -1) {//-1 means write failed. don't count
        m_bytesSent += s;
        emit newBytesSent(s);
        emit bytesSentChanged(m_bytesSent);
    }
}

} // namespace QSS
