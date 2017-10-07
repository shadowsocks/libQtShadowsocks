/*
 * udprelay.cpp - the source file of UdpRelay class
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

#include "udprelay.h"
#include "common.h"
#include <QDebug>
#include <utility>

namespace QSS {

UdpRelay::UdpRelay(const std::string &method,
                   const std::string &password,
                   bool is_local,
                   bool auto_ban,
                   Address serverAddress) :
    serverAddress(std::move(serverAddress)),
    isLocal(is_local),
    autoBan(auto_ban),
    encryptor(new Encryptor(method, password))
{
    listenSocket.setReadBufferSize(RemoteRecvSize);
    listenSocket.setSocketOption(QAbstractSocket::LowDelayOption, 1);

    connect(&listenSocket, &QUdpSocket::stateChanged,
            this, &UdpRelay::onListenStateChanged);
    connect(&listenSocket, &QUdpSocket::readyRead,
            this, &UdpRelay::onServerUdpSocketReadyRead);
    connect(&listenSocket,
            static_cast<void (QUdpSocket::*)(QAbstractSocket::SocketError)>
            (&QUdpSocket::error),
            this,
            &UdpRelay::onSocketError);
    connect(&listenSocket, &QUdpSocket::bytesWritten,
            this, &UdpRelay::bytesSend);
}

bool UdpRelay::isListening() const
{
    return listenSocket.isOpen();
}

bool UdpRelay::listen(const QHostAddress& addr, uint16_t port)
{
    return listenSocket.bind(
              addr,
              port,
              QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint
              );
}

void UdpRelay::close()
{
    listenSocket.close();
    encryptor->reset();
    m_cache.clear();
}

void UdpRelay::onSocketError()
{
    auto *sock = qobject_cast<QUdpSocket *>(sender());
    if (sock == nullptr) {
        qFatal("Fatal. A false object calling onSocketError.");
        return;
    }
    if (sock == &listenSocket) {
        QDebug(QtMsgType::QtCriticalMsg).noquote() << "[UDP] server socket error" << sock->errorString();
    } else {
        QDebug(QtMsgType::QtCriticalMsg).noquote() << "[UDP] client socket error" << sock->errorString();
    }
}

void UdpRelay::onListenStateChanged(QAbstractSocket::SocketState s)
{
    QDebug(QtMsgType::QtDebugMsg) << "Listen UDP socket state changed to" << s;
}

void UdpRelay::onServerUdpSocketReadyRead()
{
    const size_t packetSize = listenSocket.pendingDatagramSize();
    if (packetSize > RemoteRecvSize) {
        qWarning("[UDP] Datagram is too large. discarded.");
        return;
    }

    std::string data;
    data.resize(packetSize);
    QHostAddress r_addr;
    uint16_t r_port;
    int64_t readSize = listenSocket.readDatagram(&data[0],
                                                 packetSize,
                                                 &r_addr,
                                                 &r_port);
    emit bytesRead(readSize);

    if (isLocal) {
        if (static_cast<int>(data[2]) != 0) {
            qWarning("[UDP] Drop a message since frag is not 0");
            return;
        }
        data = data.substr(3);
    } else {
        if (autoBan && Common::isAddressBanned(r_addr)) {
            QDebug(QtMsgType::QtInfoMsg).noquote() << "[UDP] A banned IP" << r_addr
                                                   << "attempted to access this server";
            return;
        }
        data = encryptor->decryptAll(data);
    }

    Address destAddr, remoteAddr(r_addr, r_port);//remote == client
    int header_length = 0;
    Common::parseHeader(data, destAddr, header_length);
    if (header_length == 0) {
        qCritical("[UDP] Can't parse header. Wrong encryption method or password?");
        if (!isLocal && autoBan) {
            Common::banAddress(r_addr);
        }
        return;
    }

    auto clientIt = m_cache.find(remoteAddr);
    if (clientIt == m_cache.end()) {
        std::shared_ptr<QUdpSocket> client(new QUdpSocket());
        client->setReadBufferSize(RemoteRecvSize);
        client->setSocketOption(QAbstractSocket::LowDelayOption, 1);
        clientIt = m_cache.insert(clientIt, std::make_pair(remoteAddr, client));
        connect(client.get(), &QUdpSocket::readyRead,
                [remoteAddr, this]() {
            std::shared_ptr<QUdpSocket> sock = m_cache.at(remoteAddr);
            const size_t packetSize = sock->pendingDatagramSize();
            if (packetSize > RemoteRecvSize) {
                qWarning("[UDP] Datagram is too large. Discarded.");
                return;
            }

            std::string data;
            data.resize(packetSize);
            QHostAddress r_addr;
            uint16_t r_port;
            sock->readDatagram(&data[0], packetSize, &r_addr, &r_port);

            std::string response;
            if (isLocal) {
                data = encryptor->decryptAll(data);
                Address destAddr;
                int header_length = 0;

                Common::parseHeader(data, destAddr, header_length);
                if (header_length == 0) {
                    qCritical("[UDP] Can't parse header. "
                              "Wrong encryption method or password?");
                    return;
                }
                response = std::string(3, static_cast<char>(0)) + data;
            } else {
                data = Common::packAddress(r_addr, r_port) + data;
                response = encryptor->encryptAll(data);
            }

            if (remoteAddr.getPort() != 0) {
                listenSocket.writeDatagram(response.data(),
                                           response.size(),
                                           remoteAddr.getFirstIP(),
                                           remoteAddr.getPort());
            } else {
                qDebug("[UDP] Drop a packet from somewhere else we know.");
            }
        });
        connect(client.get(), &QUdpSocket::disconnected,
                [remoteAddr, this]() {
            m_cache.erase(remoteAddr);
            qDebug("[UDP] A client connection is disconnected and destroyed.");
        });
        QDebug(QtMsgType::QtDebugMsg).noquote() << "[UDP] cache miss:" << destAddr << "<->" << remoteAddr;
    } else {
        QDebug(QtMsgType::QtDebugMsg).noquote() << "[UDP] cache hit:" << destAddr << "<->" << remoteAddr;
    }

    if (isLocal) {
        data = encryptor->encryptAll(data);
        destAddr = serverAddress;
    } else {
        data = data.substr(header_length);
    }

    if (!destAddr.isIPValid()) {// TODO(symeon): async dns
        if (!destAddr.blockingLookUp()) {
            qDebug("[UDP] Failed to look up destination address. Closing this connection");
            close();
        }
    }
    clientIt->second->writeDatagram(data.data(), data.size(),
                                    destAddr.getFirstIP(), destAddr.getPort());
}

}  // namespace QSS
