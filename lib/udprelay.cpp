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

UdpRelay::UdpRelay(const EncryptorPrivate &ep, const bool &is_local, const bool &auto_ban, const bool &auth, const Address &serverAddress, QObject *parent) :
    QObject(parent),
    serverAddress(serverAddress),
    isLocal(is_local),
    autoBan(auto_ban),
    auth(auth)
{
    encryptor = new Encryptor(ep, this);

    listen.setReadBufferSize(RecvSize);
    listen.setSocketOption(QAbstractSocket::LowDelayOption, 1);

    connect(&listen, &QUdpSocket::stateChanged, this, &UdpRelay::onListenStateChanged);
    connect(&listen, &QUdpSocket::readyRead, this, &UdpRelay::onServerUdpSocketReadyRead);
    connect(&listen, static_cast<void (QUdpSocket::*)(QAbstractSocket::SocketError)> (&QUdpSocket::error), this, &UdpRelay::onSocketError);
    connect(&listen, &QUdpSocket::bytesWritten, this, &UdpRelay::bytesSend);
}

void UdpRelay::setup(const QHostAddress &localAddr, const quint16 &localPort)
{
    listen.close();
    if (isLocal) {
        listen.bind(localAddr, localPort, QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
    } else {
        listen.bind(serverAddress.getFirstIP(), serverAddress.getPort(), QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
    }
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
    if (sock == &listen) {
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
    if (listen.pendingDatagramSize() > RecvSize) {
        emit info("[UDP] Datagram is too large. discarded.");
        return;
    }

    QByteArray data;
    data.resize(listen.pendingDatagramSize());
    QHostAddress r_addr;
    quint16 r_port;
    qint64 readSize = listen.readDatagram(data.data(), RecvSize, &r_addr, &r_port);
    emit bytesRead(readSize);

    if (isLocal) {
        if (static_cast<int>(data[2]) != 0) {
            emit info("[UDP] Drop a message since frag is not 0");
            return;
        }
        data.remove(0, 3);
    } else {
        if (autoBan && Common::isAddressBanned(r_addr)) {
            emit debug(QString("[UDP] A banned IP %1 attempted to access this server").arg(r_addr.toString()));
            return;
        }
        data = encryptor->decryptAll(data);
    }

    Address destAddr, remoteAddr(r_addr, r_port);//remote == client
    int header_length = 0;
    bool at_auth = false;
    Common::parseHeader(data, destAddr, header_length, at_auth);
    if (header_length == 0) {
        emit info("[UDP] Can't parse header. Wrong encryption method or password?");
        if (!isLocal && autoBan) {
            Common::banAddress(r_addr);
        }
        return;
    }

    QUdpSocket *client = cache.value(remoteAddr, nullptr);
    QString dbg;
    if (!client) {
        client = new QUdpSocket(this);
        client->setReadBufferSize(RecvSize);
        client->setSocketOption(QAbstractSocket::LowDelayOption, 1);
        cache.insert(remoteAddr, client);
        connect(client, &QUdpSocket::readyRead, this, &UdpRelay::onClientUdpSocketReadyRead);
        connect(client, &QUdpSocket::disconnected, this, &UdpRelay::onClientDisconnected);
        QDebug(&dbg) << "[UDP] cache miss:" << destAddr << "<->" << remoteAddr;
    } else {
        QDebug(&dbg) << "[UDP] cache hit:" << destAddr << "<->" << remoteAddr;
    }
    emit debug(dbg);

    if (isLocal) {
        if (auth || at_auth) {
            encryptor->addOneTimeAuth(data, header_length);
        }
        data = encryptor->encryptAll(data);
        destAddr = serverAddress;
    } else {
        if (auth || at_auth) {
            if (!encryptor->verifyOneTimeAuth(data, header_length)) {
                emit info("[UDP] One-time message authentication failed.");
                if (autoBan) {
                    Common::banAddress(r_addr);
                }
                return;
            }
            header_length += Cipher::AUTH_LEN;
        }
        data = data.mid(header_length);
    }

    if (!destAddr.isIPValid()) {//TODO async dns
        destAddr.blockingLookUp();
    }
    client->writeDatagram(data, destAddr.getFirstIP(), destAddr.getPort());
}

void UdpRelay::onClientUdpSocketReadyRead()
{
    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (!sock) {
        emit info("Fatal. A false object calling onClientUdpSocketReadyRead.");
        return;
    }

    if (sock->pendingDatagramSize() > RecvSize) {
        emit info("[UDP] Datagram is too large. Discarded.");
        return;
    }

    QByteArray data;
    data.resize(sock->pendingDatagramSize());
    QHostAddress r_addr;
    quint16 r_port;
    sock->readDatagram(data.data(), RecvSize, &r_addr, &r_port);

    QByteArray response;
    if (isLocal) {
        data = encryptor->decryptAll(data);
        Address destAddr;
        int header_length = 0;
        bool _auth;

        Common::parseHeader(data, destAddr, header_length, _auth);
        if (header_length == 0) {
            emit info("[UDP] Can't parse header. Wrong encryption method or password?");
            return;
        }
        response = QByteArray(3, static_cast<char>(0)) + data;
    } else {
        data.prepend(Common::packAddress(r_addr, r_port));
        response = encryptor->encryptAll(data);
    }

    Address clientAddress = cache.key(sock);
    if (clientAddress.getPort() != 0) {
        listen.writeDatagram(response, clientAddress.getFirstIP(), clientAddress.getPort());
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
