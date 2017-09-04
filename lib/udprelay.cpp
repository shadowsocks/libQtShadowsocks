/*
 * udprelay.cpp - the source file of UdpRelay class
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

#include "udprelay.h"
#include "common.h"
#include <QDebug>

using namespace QSS;

UdpRelay::UdpRelay(const QByteArray &method,
                   const QByteArray &password,
                   const bool &is_local,
                   const bool &auto_ban,
                   const bool &auth,
                   const Address &serverAddress,
                   QObject *parent) :
    QObject(parent),
    serverAddress(serverAddress),
    isLocal(is_local),
    autoBan(auto_ban),
    auth(auth),
    encryptor{new Encryptor(method, password, this)}
{
    // To make sure datagram doesn't exceed remote server's maximum, we can
    // limit how many bytes we take from local socket at a time. This is due
    // the overhead introduced by OTA.
    quint64 localRecvSize = RemoteRecvSize;
    if (auth && isLocal) {
        localRecvSize -= (Cipher::AUTH_LEN + 2);
    }
    listenSocket.setReadBufferSize(localRecvSize);
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

bool UdpRelay::listen(const QHostAddress& addr, quint16 port)
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
    QList<QUdpSocket*> cachedSockets = cache.values();
    for (QUdpSocket* sock : cachedSockets) {
        sock->deleteLater();
    }
    cache.clear();
}

void UdpRelay::onSocketError()
{
    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (!sock) {
        emit info("Fatal. A false object calling onSocketError.");
        return;
    }
    if (sock == &listenSocket) {
        emit info("[UDP] server socket error " + sock->errorString());
    } else {
        emit info("[UDP] client socket error " + sock->errorString());
    }
}

void UdpRelay::onListenStateChanged(QAbstractSocket::SocketState s)
{
    QString stateChanged("Listen UDP socket state changed to ");
    QDebug(&stateChanged) << s;
    emit debug(stateChanged);
}

void UdpRelay::onServerUdpSocketReadyRead()
{
    const size_t packetSize = listenSocket.pendingDatagramSize();
    if (packetSize > RemoteRecvSize) {
        emit info("[UDP] Datagram is too large. discarded.");
        return;
    }

    std::string data;
    data.reserve(packetSize);
    QHostAddress r_addr;
    quint16 r_port;
    qint64 readSize = listenSocket.readDatagram(&data[0],
                                                packetSize,
                                                &r_addr,
                                                &r_port);
    emit bytesRead(readSize);

    if (isLocal) {
        if (static_cast<int>(data[2]) != 0) {
            emit info("[UDP] Drop a message since frag is not 0");
            return;
        }
        data = data.substr(3);
    } else {
        if (autoBan && Common::isAddressBanned(r_addr)) {
            emit debug(QString("[UDP] A banned IP %1 "
                               "attempted to access this server")
                       .arg(r_addr.toString()));
            return;
        }
        data = encryptor->decryptAll(QByteArray::fromStdString(data)).toStdString();
    }

    Address destAddr, remoteAddr(r_addr, r_port);//remote == client
    int header_length = 0;
    bool at_auth = false;
    Common::parseHeader(QByteArray::fromStdString(data), destAddr, header_length, at_auth);
    if (header_length == 0) {
        emit info("[UDP] Can't parse header. "
                  "Wrong encryption method or password?");
        if (!isLocal && autoBan) {
            Common::banAddress(r_addr);
        }
        return;
    }

    QUdpSocket *client = cache.value(remoteAddr, nullptr);
    QString dbg;
    if (!client) {
        client = new QUdpSocket(this);
        client->setReadBufferSize(RemoteRecvSize);
        client->setSocketOption(QAbstractSocket::LowDelayOption, 1);
        cache.insert(remoteAddr, client);
        connect(client, &QUdpSocket::readyRead,
                this, &UdpRelay::onClientUdpSocketReadyRead);
        connect(client, &QUdpSocket::disconnected,
                this, &UdpRelay::onClientDisconnected);
        QDebug(&dbg) << "[UDP] cache miss:" << destAddr << "<->" << remoteAddr;
    } else {
        QDebug(&dbg) << "[UDP] cache hit:" << destAddr << "<->" << remoteAddr;
    }
    emit debug(dbg);

    if (isLocal) {
        if (auth || at_auth) {
            /*
             * shadowsocks UDP Request (OTA-enabled, unencrypted)
             * +------+----------+----------+----------+-------------+
             * | ATYP | DST.ADDR | DST.PORT |   DATA   |  HMAC-SHA1  |
             * +------+----------+----------+----------+-------------+
             * |  1   | Variable |    2     | Variable |     10      |
             * +------+----------+----------+----------+-------------+
             */
            encryptor->addHeaderAuth(data);
        }
        data = encryptor->encryptAll(QByteArray::fromStdString(data)).toStdString();
        destAddr = serverAddress;
    } else {
        if (auth || at_auth) {
            if (!encryptor->verifyHeaderAuth(data.data(),
                                             data.length() - Cipher::AUTH_LEN)) {
                emit info("[UDP] One-time message authentication "
                          "for header failed.");
                if (autoBan) {
                    Common::banAddress(r_addr);
                }
                return;
            }
        }
        data = data.substr(header_length,
                        data.length() - header_length - Cipher::AUTH_LEN);
    }

    if (!destAddr.isIPValid()) {//TODO async dns
        destAddr.blockingLookUp();
    }
    client->writeDatagram(data.data(), data.size(), destAddr.getFirstIP(), destAddr.getPort());
}

void UdpRelay::onClientUdpSocketReadyRead()
{
    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (!sock) {
        emit info("Fatal. A false object calling onClientUdpSocketReadyRead.");
        return;
    }

    if (sock->pendingDatagramSize() > RemoteRecvSize) {
        emit info("[UDP] Datagram is too large. Discarded.");
        return;
    }

    QByteArray data;
    data.resize(sock->pendingDatagramSize());
    QHostAddress r_addr;
    quint16 r_port;
    sock->readDatagram(data.data(), RemoteRecvSize, &r_addr, &r_port);

    QByteArray response;
    if (isLocal) {
        data = encryptor->decryptAll(data);
        Address destAddr;
        int header_length = 0;
        bool _auth;

        Common::parseHeader(data, destAddr, header_length, _auth);
        if (header_length == 0) {
            emit info("[UDP] Can't parse header. "
                      "Wrong encryption method or password?");
            return;
        }
        response = QByteArray(3, static_cast<char>(0)) + data;
    } else {
        data.prepend(Common::packAddress(r_addr, r_port));
        response = encryptor->encryptAll(data);
    }

    Address clientAddress = cache.key(sock);
    if (clientAddress.getPort() != 0) {
        listenSocket.writeDatagram(response,
                                   clientAddress.getFirstIP(),
                                   clientAddress.getPort());
    } else {
        emit debug("[UDP] Drop a packet from somewhere else we know.");
    }
}

void UdpRelay::onClientDisconnected()
{
    QUdpSocket *client = qobject_cast<QUdpSocket *>(sender());
    if (!client) {
        emit info("Fatal. A false object calling onClientDisconnected.");
        return;
    }
    cache.remove(cache.key(client));
    client->deleteLater();
    emit debug("[UDP] A client connection is disconnected and destroyed.");
}
