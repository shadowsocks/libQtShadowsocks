/*
 * tcprelayclient.cpp - the source file of TcpRelayClient class
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

#include "tcprelayclient.h"
#include "util/common.h"
#include <QDebug>
#include <utility>

namespace QSS {

TcpRelayClient::TcpRelayClient(QTcpSocket *localSocket,
                               int timeout,
                               Address server_addr,
                               const Encryptor::Creator& ec)
    : TcpRelay(localSocket, timeout, server_addr, ec)
{
}

void TcpRelayClient::handleStageAddr(std::string &data)
{
    auto cmd = static_cast<int>(data.at(1));
    if (cmd == 3) {//CMD_UDP_ASSOCIATE
        qDebug("UDP associate");
        static const char header_data [] = { 5, 0, 0 };
        QHostAddress addr = m_local->localAddress();
        uint16_t port = m_local->localPort();
        std::string toWrite = std::string(header_data, 3) + Common::packAddress(addr, port);
        m_local->write(toWrite.data(), toWrite.length());
        m_stage = UDP_ASSOC;
        return;
    } if (cmd == 1) {//CMD_CONNECT
        data = data.substr(3);
    } else {
        qCritical("Unknown command %d", cmd);
        close();
        return;
    }

    int header_length = 0;
    Common::parseHeader(data, m_remoteAddress, header_length);
    if (header_length == 0) {
        qCritical("Can't parse header. Wrong encryption method or password?");
        close();
        return;
    }

    QDebug(QtMsgType::QtInfoMsg).noquote().nospace()
            << "Connecting " << m_remoteAddress << " from "
            << m_local->peerAddress().toString() << ":" << m_local->peerPort();

    m_stage = DNS;
    static constexpr const char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 16, 16 };
    static const QByteArray response(res, 10);
    m_local->write(response);
    m_dataToWrite += m_encryptor->encrypt(data);
    m_serverAddress.lookUp([this](bool success) {
        if (success) {
            m_stage = CONNECTING;
            m_startTime = QTime::currentTime();
            m_remote->connectToHost(m_serverAddress.getFirstIP(), m_serverAddress.getPort());
        } else {
            QDebug(QtMsgType::QtDebugMsg).noquote() << "Failed to lookup server address. Closing TCP connection.";
            close();
        }
    });
}

void TcpRelayClient::handleLocalTcpData(std::string &data)
{
    switch (m_stage) {
    case STREAM:
        data = m_encryptor->encrypt(data);
        writeToRemote(data.data(), data.size());
        break;
    case INIT:
    {
        static constexpr const char reject_data [] = { 0, 91 };
        static constexpr const char accept_data [] = { 5, 0 };
        static const QByteArray reject(reject_data, 2);
        static const QByteArray accept(accept_data, 2);
        if (data[0] != char(5)) {
            qCritical("An invalid socket connection was rejected. "
                      "Please make sure the connection type is SOCKS5.");
            m_local->write(reject);
        } else {
            m_local->write(accept);
        }
        m_stage = ADDR;
        break;
    }
    case CONNECTING:
    case DNS:
        // take DNS into account, otherwise some data will get lost
        m_dataToWrite += m_encryptor->encrypt(data);
        break;
    case ADDR:
        handleStageAddr(data);
        break;
    default:
        qCritical("Local unknown stage.");
    }
}

void TcpRelayClient::handleRemoteTcpData(std::string &data)
{
    data = m_encryptor->decrypt(data);
}

}  // namespace QSS
