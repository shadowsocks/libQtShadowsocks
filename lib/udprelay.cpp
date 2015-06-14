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
#include <QDebug>

using namespace QSS;

UdpRelay::UdpRelay(bool is_local, QObject *parent) :
    QObject(parent),
    isLocal(is_local),
    encryptor(nullptr)
{
    listen = new QUdpSocket(this);
    listen->setReadBufferSize(RecvSize);
    listen->setSocketOption(QAbstractSocket::LowDelayOption, 1);

    connect(listen, &QUdpSocket::stateChanged, this, &UdpRelay::onListenStateChanged);
    connect(listen, &QUdpSocket::readyRead, this, &UdpRelay::onServerUdpSocketReadyRead);
    connect(listen, static_cast<void (QUdpSocket::*)(QAbstractSocket::SocketError)> (&QUdpSocket::error), this, &UdpRelay::onSocketError);
    connect(listen, &QUdpSocket::bytesWritten, this, &UdpRelay::bytesSend);
}

//static member
QMap<CacheKey, QUdpSocket *> UdpRelay::cache;
QMap<qintptr, Address> UdpRelay::clientDescriptorToServerAddr;

void UdpRelay::setup(const EncryptorPrivate *ep, const Address &serverAddress, const QHostAddress &localAddr, const quint16 &localPort)
{
    listen->close();
    if (isLocal) {
        listen->bind(localAddr, localPort, QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
        destination = serverAddress;
    } else {
        listen->bind(serverAddress.getFirstIP(), serverAddress.getPort(), QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
    }
    if (encryptor) {
        encryptor->deleteLater();
    }
    encryptor = new Encryptor(ep, this);
}

void UdpRelay::onSocketError()
{
    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (!sock) {
        emit log("Fatal. A false object calling onSocketError.");
        return;
    }
    if (sock == listen) {
        emit log("UDP server socket error " + sock->errorString());
    } else {
        emit log("UDP client socket error " + sock->errorString());
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
    if (!encryptor) {
        emit log("Fatal. Encryptor in UdpRelay is NULL!");
        return;
    }

    if (listen->pendingDatagramSize() > RecvSize) {
        emit log("Datagram is too large. discarded.");
        return;
    }

    QByteArray data;
    data.resize(listen->pendingDatagramSize());
    QHostAddress r_addr;
    quint16 r_port;
    qint64 readSize = listen->readDatagram(data.data(), RecvSize, &r_addr, &r_port);
    emit bytesRead(readSize);
    if (readSize > 0) {
        data.resize(readSize);
    }

    QString dbg("Received UDP packet from ");
    QDebug(&dbg) << r_addr << r_port;
    emit debug(dbg);

    if (isLocal) {
        if (static_cast<int> (data[2]) != 0) {
            emit log("Drop a message since frag is not 0");
            return;
        }
        data.remove(0, 2);
    } else {
        data = encryptor->decryptAll(data);
    }

    Address destAddr;
    int header_length = 0;
    Common::parseHeader(data, destAddr, header_length);
    if (header_length == 0) {
        emit log("Can't parse UDP packet header.");
        return;
    }

    CacheKey key(Address(r_addr, r_port), destAddr);
    QUdpSocket *client = cache.value(key, nullptr);
    if (!client) {
        client = new QUdpSocket(this);
        client->setReadBufferSize(RecvSize);
        client->setSocketOption(QAbstractSocket::LowDelayOption, 1);
        cache.insert(key, client);
        clientDescriptorToServerAddr.insert(client->socketDescriptor(), key.first);
        connect(client, &QUdpSocket::readyRead, this, &UdpRelay::onClientUdpSocketReadyRead);
        connect(client, &QUdpSocket::disconnected, this, &UdpRelay::onClientDisconnected);
        emit debug("A new UDP client is connected.");
    }

    if (isLocal) {
        data = encryptor->encryptAll(data);
        destAddr = destination;
    } else {
        data = data.mid(header_length);
    }

    client->writeDatagram(data, destAddr.getFirstIP(), destAddr.getPort());
}

void UdpRelay::onClientUdpSocketReadyRead()
{
    if (!encryptor) {
        emit log("Fatal. Encryptor in UdpRelay is NULL!");
        return;
    }

    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (!sock) {
        emit log("Fatal. A false object calling onClientUdpSocketReadyRead.");
        return;
    }

    if (sock->pendingDatagramSize() > RecvSize) {
        emit log("Datagram is too large. Discarded.");
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

        Common::parseHeader(data, destAddr, header_length);
        if (header_length == 0) {
            return;
        }
        response = QByteArray(3, char(0)) + data;
    } else {
        data.prepend(Common::packAddress(r_addr, r_port));
        response = encryptor->encryptAll(data);
    }

    Address clientAddress = clientDescriptorToServerAddr.value(sock->socketDescriptor());
    if (clientAddress.getPort() != 0) {
        listen->writeDatagram(response, clientAddress.getFirstIP(), clientAddress.getPort());
    } else {
        emit debug("Drop a UDP packet from somewhere else we know.");
    }
}

void UdpRelay::onClientDisconnected()
{
    QUdpSocket *client = qobject_cast<QUdpSocket *>(sender());
    if (!client) {
        emit log("Fatal. A false object calling onClientDisconnected.");
        return;
    }
    cache.remove(cache.key(client));
    clientDescriptorToServerAddr.remove(client->socketDescriptor());
    client->deleteLater();
    emit debug("A UDP client connection is disconnected and destroyed.");
}
