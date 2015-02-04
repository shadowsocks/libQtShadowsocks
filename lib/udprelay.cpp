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

using namespace QSS;

UdpRelay::UdpRelay(bool is_local, QObject *parent) :
    QObject(parent),
    isLocal(is_local)
{
    encryptor = new Encryptor(this);
    listen = new QUdpSocket(this);
    listen->setReadBufferSize(RecvSize);
    listen->setSocketOption(QAbstractSocket::LowDelayOption, 1);

    connect(listen, &QUdpSocket::stateChanged, this, &UdpRelay::onListenStateChanged);
    connect(listen, &QUdpSocket::readyRead, this, &UdpRelay::onServerUdpSocketReadyRead);
    connect(listen, static_cast<void (QUdpSocket::*)(QAbstractSocket::SocketError)> (&QUdpSocket::error), this, &UdpRelay::onSocketError);   
}

//static member
QMap<CacheKey, QUdpSocket *> UdpRelay::cache;
QMap<qintptr, Address> UdpRelay::clientDescriptorToServerAddr;

void UdpRelay::setup(Address &serverAddress, const QHostAddress &localAddr, const quint16 &localPort)
{
    listen->close();
    if (isLocal) {
        listen->bind(localAddr, localPort, QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
        destination = serverAddress;
    }
    else {
        listen->bind(serverAddress.getIPAddress(), serverAddress.getPort(), QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
    }
}

void UdpRelay::onSocketError()
{
    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (sock == NULL) {
        emit error("Fatal. A false object calling onSocketError.");
        return;
    }
    if (sock == listen) {
        emit error("UDP server socket error " + sock->errorString());
    }
    else {
        emit error("UDP client socket error " + sock->errorString());
    }
}

void UdpRelay::onListenStateChanged(QAbstractSocket::SocketState s)
{
    QString stateChanged("Listen UDP socket state changed to ");
    QDebug(&stateChanged) << s;
    emit info(stateChanged);
}

void UdpRelay::onServerUdpSocketReadyRead()
{
    if (listen->pendingDatagramSize() > RecvSize) {
        emit error("Datagram is too large. discarded.");
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
            emit error("Drop a message since frag is not 0");
            return;
        }
        data.remove(0, 2);
    }
    else {
        data = encryptor->decryptAll(data);
    }

    Address destAddr;
    int header_length = 0;
    Common::parseHeader(data, destAddr, header_length);
    if (header_length == 0) {
        emit error("Can't parse UDP packet header.");
        return;
    }

    CacheKey key(r_addr, r_port, destAddr);
    QUdpSocket *client = cache.value(key, NULL);
    if (client == NULL) {
        client = new QUdpSocket(this);
        client->setReadBufferSize(RecvSize);
        client->setSocketOption(QAbstractSocket::LowDelayOption, 1);
        cache.insert(key, client);
        clientDescriptorToServerAddr.insert(client->socketDescriptor(), key.r);
        connect(client, &QUdpSocket::readyRead, this, &UdpRelay::onClientUdpSocketReadyRead);
        connect(client, &QUdpSocket::disconnected, this, &UdpRelay::onClientDisconnected);
        emit debug("A new UDP client is connected.");
    }

    if (isLocal) {
        data = encryptor->encryptAll(data);
        destAddr = destination;
    }
    else {
        data = data.mid(header_length);
    }

    client->writeDatagram(data, destAddr.getIPAddress(), destAddr.getPort());
}

void UdpRelay::onClientUdpSocketReadyRead()
{
    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (sock == NULL) {
        emit error("Fatal. A false object calling onClientUdpSocketReadyRead.");
        return;
    }

    if (sock->pendingDatagramSize() > RecvSize) {
        emit error("Datagram is too large. Discarded.");
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
    }
    else {
        data.prepend(Common::packAddress(r_addr, r_port));
        response = encryptor->encryptAll(data);
    }

    Address clientAddress = clientDescriptorToServerAddr.value(sock->socketDescriptor());
    if (clientAddress.getPort() != 0) {
        qint64 writtenBytes = listen->writeDatagram(response, clientAddress.getIPAddress(), clientAddress.getPort());
        emit bytesSend(writtenBytes);
    }
    else {
        emit debug("Drop a UDP packet from somewhere else we know.");
    }
}

void UdpRelay::onClientDisconnected()
{
    QUdpSocket *client = qobject_cast<QUdpSocket *>(sender());
    if (client == NULL) {
        emit error("Fatal. A false object calling onClientDisconnected.");
        return;
    }
    cache.remove(cache.key(client));
    clientDescriptorToServerAddr.remove(client->socketDescriptor());
    client->deleteLater();
    emit debug("A UDP client connection is disconnected and destroyed.");
}
