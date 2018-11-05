/*
 * tcprelayserver.cpp - the source file of TcpRelayServer class
 *
 * Copyright (C) 2018 Symeon Huang <hzwhuang@gmail.com>
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

#include "tcprelayserver.h"
#include "util/common.h"
#include <QDebug>
#include <utility>

namespace QSS {

TcpRelayServer::TcpRelayServer(QTcpSocket *localSocket,
                               int timeout,
                               Address server_addr,
                               const Encryptor::Creator& ec,
                               bool autoBan)
    : TcpRelay(localSocket, timeout, server_addr, ec)
    , autoBan(autoBan)
{}

void TcpRelayServer::handleStageAddr(std::string &data)
{
    int header_length = 0;
    Common::parseHeader(data, m_remoteAddress, header_length);
    if (header_length == 0) {
        qCritical("Can't parse header. Wrong encryption method or password?");
        if (autoBan) {
            Common::banAddress(m_local->peerAddress());
        }
        close();
        return;
    }

    QDebug(QtMsgType::QtInfoMsg).noquote().nospace()
            << "Connecting " << m_remoteAddress << " from "
            << m_local->peerAddress().toString() << ":" << m_local->peerPort();

    m_stage = DNS;
    if (data.size() > header_length) {
        data = data.substr(header_length);
        m_dataToWrite += data;
    }
    m_remoteAddress.lookUp([this](bool success) {
        if (success) {
            m_stage = CONNECTING;
            m_startTime = QTime::currentTime();
            m_remote->connectToHost(m_remoteAddress.getFirstIP(), m_remoteAddress.getPort());
        } else {
            QDebug(QtMsgType::QtDebugMsg).noquote() << "Failed to lookup remote address. Closing TCP connection.";
            close();
        }
    });
}

void TcpRelayServer::handleLocalTcpData(std::string &data)
{
    try {
        data = m_encryptor->decrypt(data);
    } catch (const std::exception &e) {
        QDebug(QtMsgType::QtCriticalMsg) << "Local:" << e.what();
        close();
        return;
    }

    if (data.empty()) {
        qWarning("Data is empty after decryption.");
        return;
    }

    if (m_stage == STREAM) {
        writeToRemote(data.data(), data.size());
    } else if (m_stage == CONNECTING || m_stage == DNS) {
        // take DNS into account, otherwise some data will get lost
        m_dataToWrite += data;
    } else if (m_stage == INIT) {
        handleStageAddr(data);
    } else {
        qCritical("Local unknown stage.");
    }
}

void TcpRelayServer::handleRemoteTcpData(std::string &data)
{
    data = m_encryptor->encrypt(data);
}

}  // namespace QSS
