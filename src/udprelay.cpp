/*
 * udprelay.cpp - the source file of UdpRelay class
 *
 * Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
 *
 * This file is part of the libQtShadowsocks.
 *
 * libQtShadowsocks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libQtShadowsocks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "udprelay.h"
#include "controller.h"

UdpRelay::UdpRelay(bool is_local, QObject *parent) :
    QObject(parent),
    isLocal(is_local)
{
    Controller *c = qobject_cast<Controller *>(parent);

    if(c == NULL) {
        qCritical() << "Fatal. UdpRelay's parent must be a BaseController object.";
        return;
    }

    encryptor = new Encryptor(this);
    listen = new QUdpSocket(this);

    connect(listen, &QUdpSocket::stateChanged, this, &UdpRelay::onListenStateChanged);
    connect(listen, &QUdpSocket::readyRead, this, &UdpRelay::onServerUdpSocketReadyRead);
    connect(listen, static_cast<void (QUdpSocket::*)(QAbstractSocket::SocketError)> (&QUdpSocket::error), this, &UdpRelay::onSocketError);

    if (isLocal) {
        listen->bind(c->getLocalAddr(), c->getLocalPort(), QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
        remote = new QUdpSocket(this);
        connect(remote, static_cast<void (QUdpSocket::*)(QAbstractSocket::SocketError)> (&QUdpSocket::error), this, &UdpRelay::onSocketError);
        remote->connectToHost(c->getServerAddr(), c->getServerPort());
        remote->setReadBufferSize(RecvSize);
        remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    }
    else {
        listen->bind(c->getServerAddr(), c->getServerPort(), QAbstractSocket::ShareAddress | QAbstractSocket::ReuseAddressHint);
    }

    listen->setReadBufferSize(RecvSize);
    listen->setSocketOption(QAbstractSocket::LowDelayOption, 1);
}

//static member
QMap<CacheKey, QUdpSocket *> UdpRelay::cache;
QMap<qintptr, Address> UdpRelay::clientDescriptorToServerAddr;

void UdpRelay::onSocketError()
{
    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (sock == NULL) {
        qCritical() << "Fatal. A false object calling onSocketError.";
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
    qDebug() << "listen udp socket state changed to" << s;
}

void UdpRelay::onServerUdpSocketReadyRead()
{
    QUdpSocket *server = qobject_cast<QUdpSocket *>(sender());
    if (server->pendingDatagramSize() > RecvSize) {
        qDebug() << "datagram is too large. discarded.";
        return;
    }

    QByteArray data;
    data.resize(server->pendingDatagramSize());
    QHostAddress r_addr;
    quint16 r_port;
    server->readDatagram(data.data(), RecvSize, &r_addr, &r_port);

    if (isLocal) {
        if (static_cast<int> (data[2]) != 0) {
            qDebug() << "drop a message since frag is not 0";
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
    }

    if (isLocal) {
        data = encryptor->encryptAll(data);
        destAddr.setIPAddress(remote->peerAddress());
        destAddr.setPort(remote->peerPort());
    }
    else {
        data = data.mid(header_length);
    }

    client->writeDatagram(data, destAddr.getRealIPAddress(), destAddr.getPort());
}

void UdpRelay::onClientUdpSocketReadyRead()
{
    QUdpSocket *sock = qobject_cast<QUdpSocket *>(sender());
    if (sock == NULL) {
        qCritical() << "Fatal. A false object calling onClientUdpSocketReadyRead.";
        return;
    }

    if (sock->pendingDatagramSize() > RecvSize) {
        qDebug() << "datagram is too large. discarded.";
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
        listen->writeDatagram(response, clientAddress.getRealIPAddress(), clientAddress.getPort());
    }
    //else this packet is from somewhere else we know
    //simply drop that packet
}

void UdpRelay::onClientDisconnected()
{
    QUdpSocket *client = qobject_cast<QUdpSocket *>(sender());
    if (client == NULL) {
        qCritical() << "Fatal. A false object calling onClientDisconnected.";
        return;
    }
    cache.remove(cache.key(client));
    clientDescriptorToServerAddr.remove(client->socketDescriptor());
    client->deleteLater();
}
