/*
 * connection.cpp - the source file of Connection class
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

#include "connection.h"
#include "controller.h"

Connection::Connection(QTcpSocket *localTcpSocket, bool is_local, QObject *parent) :
    QObject(parent)
{
    Controller *c = qobject_cast<Controller *>(parent);

    if(c == NULL) {
        qCritical() << "Fatal. Connection's parent must be a BaseController object.";
        return;
    }

    isLocal = is_local;
    stage = INIT;
    encryptor = new Encryptor(this);

    local = localTcpSocket;
    local->setParent(this);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local->setReadBufferSize(RecvSize);

    remote = new QTcpSocket(this);
    remote->setReadBufferSize(RecvSize);
    remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    if (isLocal) {
        remote->connectToHost(c->getServerAddr(), c->getServerPort());
    }

    socketDescriptor = local->socketDescriptor();

    connect(local, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onLocalTcpSocketError);
    connect(local, &QTcpSocket::disconnected, this, &Connection::disconnected, Qt::DirectConnection);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onLocalTcpSocketReadyRead, Qt::DirectConnection);

    connect(remote, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onRemoteTcpSocketError);
    connect(remote, &QTcpSocket::disconnected, this, &Connection::disconnected, Qt::DirectConnection);
    connect(remote, &QTcpSocket::readyRead, this, &Connection::onRemoteTcpSocketReadyRead, Qt::DirectConnection);
}

void Connection::appendTcpSocket(QTcpSocket *t)
{
    disconnect(local, &QTcpSocket::disconnected, this, &Connection::disconnected);
    connect(local, &QTcpSocket::disconnected, local, &QTcpSocket::deleteLater);

    local = t;
    local->setParent(this);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local->setReadBufferSize(RecvSize);

    connect(local, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onLocalTcpSocketError);
    connect(local, &QTcpSocket::disconnected, this, &Connection::disconnected, Qt::DirectConnection);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onLocalTcpSocketReadyRead, Qt::DirectConnection);
}

void Connection::handleStageHello(QByteArray &data)
{
    if (isLocal) {
        int cmd = static_cast<int>(data.at(1));
        if (cmd == 3) {//CMD_UDP_ASSOCIATE
            emit info("UDP associate");
            QByteArray header;
            header.append(char(5));
            header.append(char(0));
            header.append(char(0));
            if (local->peerAddress().protocol() == QAbstractSocket::IPv6Protocol) {
                header.append(char(4));
            }
            else {
                header.append(char(1));
            }
            QHostAddress addr = local->peerAddress();
            quint16 port = local->peerPort();
            writeToLocal(header + addr.toString().toLatin1() + QString::number(port).toLatin1());
            stage = UDP_ASSOC;
            return;
        }
        else if (cmd == 1) {//CMD_CONNECT
            data = data.mid(3);
        }
        else {
            emit error("Unknown command " + QString::number(cmd).toLocal8Bit());
            return;
        }
    }

    int header_length = 0;
    Common::parseHeader(data, remoteAddress, header_length);
    if (header_length == 0) {
        emit error("Can't parse header");
        return;
    }
    emit info("connecting " + remoteAddress.getAddress().toLocal8Bit() + ":" + QString::number(remoteAddress.getPort()).toLocal8Bit());
    stage = REPLY;//skip DNS, because remote_addr is already an IP address now.

    if (isLocal) {
        static char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 1, 1 };
        QByteArray response(res, 10);
        writeToLocal(response);
        data = encryptor->encrypt(data);
        writeToRemote(data);
    }
    else {
        if (data.length() > header_length) {
            writeToRemote(data.mid(header_length));
        }
    }
}

void Connection::handleStageReply(QByteArray &data)
{
    if (isLocal) {
        data = encryptor->encrypt(data);
    }
    writeToRemote(data);
}

bool Connection::writeToLocal(const QByteArray &data)
{
    qint64 s = local->write(data);
    return s != -1;
}

bool Connection::writeToRemote(const QByteArray &data)
{
    if (remote->state() != QAbstractSocket::ConnectedState) {
        remote->connectToHost(remoteAddress.getIPAddress(), remoteAddress.getPort());
    }
    qint64 s = remote->write(data);
    return s != -1;
}

void Connection::onLocalTcpSocketError()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (socket == NULL) {
        emit error("Error. Invalid object called onLocalTcpSocketError.");
        return;
    }

    if (socket->error() != QAbstractSocket::RemoteHostClosedError) {//it's not an "error" if remote host closed a connection
        QString str = QString("local socket error: ") + socket->errorString();
        emit error(str);
    }
}

void Connection::onRemoteTcpSocketError()
{
    if (remote->error() != QAbstractSocket::RemoteHostClosedError) {//it's not an "error" if remote host closed a connection
        QString str = QString("remote socket error: ") + remote->errorString();
        emit error(str);
    }
}

void Connection::onLocalTcpSocketReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (socket == NULL) {
        emit error("Error. Invalid object called onLocalTcpSocketReadyRead.");
        return;
    }

    if (isLocal && stage == INIT) {
        QByteArray buf = socket->read(256);
        QByteArray response;
        if (buf[0] != char(5)) {
            response.append(char(0));
            response.append(char(91));
        }
        else {
            response.append(char(5));
            response.append(char(0));
        }
        writeToLocal(response);
        stage = HELLO;
        return;
    }

    QByteArray buf = socket->readAll();
    if (!isLocal) {
        buf = encryptor->decrypt(buf);
    }

    switch (stage) {
    case STREAM:
        if (isLocal) {
            buf = encryptor->encrypt(buf);
        }
        writeToRemote(buf);
        break;
    case HELLO:
        if (isLocal)    handleStageHello(buf);
        break;
    case INIT:
        if (!isLocal)   handleStageHello(buf);
        break;
    case REPLY:
        handleStageReply(buf);
        break;
    default:
        emit error("Unknown stage");
    }
}

void Connection::onRemoteTcpSocketReadyRead()
{
    QByteArray buf = remote->readAll();
    if (isLocal) {
        buf = encryptor->decrypt(buf);
    }
    else {
        buf = encryptor->encrypt(buf);
    }
    writeToLocal(buf);
}
