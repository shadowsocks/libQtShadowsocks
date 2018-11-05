/*
 * tcpserver.cpp
 *
 * Copyright (C) 2015-2017 Symeon Huang <hzwhuang@gmail.com>
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


#include "tcprelayclient.h"
#include "tcprelayserver.h"
#include "tcpserver.h"
#include "util/common.h"
#include <QDebug>
#include <utility>

namespace QSS {

TcpServer::TcpServer(Encryptor::Creator&& ec,
                     int timeout,
                     bool is_local,
                     bool auto_ban,
                     Address serverAddress)
    : m_encryptorCreator(std::move(ec))
    , m_isLocal(is_local)
    , m_autoBan(auto_ban)
    , m_serverAddress(std::move(serverAddress))
    , m_timeout(timeout)
{
}

TcpServer::~TcpServer()
{
    if (isListening()) {
        close();
    }
}

void TcpServer::incomingConnection(qintptr socketDescriptor)
{
    auto localSocket = std::make_unique<QTcpSocket>();
    localSocket->setSocketDescriptor(socketDescriptor);

    if (!m_isLocal && m_autoBan && Common::isAddressBanned(localSocket->peerAddress())) {
        QDebug(QtMsgType::QtInfoMsg).noquote() << "A banned IP" << localSocket->peerAddress()
                                               << "attempted to access this server";
        return;
    }

    //timeout * 1000: convert sec to msec
    std::shared_ptr<TcpRelay> con;
    if (m_isLocal) {
        con = std::make_shared<TcpRelayClient>(localSocket.release(),
                                               m_timeout * 1000,
                                               m_serverAddress,
                                               m_encryptorCreator);
    } else {
        con = std::make_shared<TcpRelayServer>(localSocket.release(),
                                               m_timeout * 1000,
                                               m_serverAddress,
                                               m_encryptorCreator,
                                               m_autoBan);
    }
    m_conList.push_back(con);
    connect(con.get(), &TcpRelay::bytesRead, this, &TcpServer::bytesRead);
    connect(con.get(), &TcpRelay::bytesSend, this, &TcpServer::bytesSend);
    connect(con.get(), &TcpRelay::latencyAvailable,
            this, &TcpServer::latencyAvailable);
    connect(con.get(), &TcpRelay::finished, this, [con, this]() {
        m_conList.remove(con);
    });
}

}  // namespace QSS
