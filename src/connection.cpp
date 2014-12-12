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
    QObject(parent),
    isLocal(is_local)
{
    Controller *c = qobject_cast<Controller *>(parent);

    if(c == NULL) {
        qCritical() << "Fatal. Connection's parent must be a BaseController object.";
        return;
    }

    stage = INIT;
    encryptor = new Encryptor(this);
    timer = new QTimer(this);
    timer->setInterval(c->getTimeout());

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

    connect(timer, &QTimer::timeout, this, &Connection::deleteLater, Qt::DirectConnection);

    connect(local, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onLocalTcpSocketError, Qt::DirectConnection);
    connect(local, &QTcpSocket::disconnected, this, &Connection::deleteLater, Qt::DirectConnection);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onLocalTcpSocketReadyRead, Qt::DirectConnection);
    connect(local, &QTcpSocket::readyRead, timer, static_cast<void (QTimer::*)()> (&QTimer::start), Qt::DirectConnection);

    connect(remote, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onRemoteTcpSocketError, Qt::DirectConnection);
    connect(remote, &QTcpSocket::disconnected, this, &Connection::deleteLater, Qt::DirectConnection);
    connect(remote, &QTcpSocket::readyRead, this, &Connection::onRemoteTcpSocketReadyRead, Qt::DirectConnection);
    connect(remote, &QTcpSocket::readyRead, timer, static_cast<void (QTimer::*)()> (&QTimer::start), Qt::DirectConnection);

    connect(this, &Connection::destroyMe, this, &Connection::deleteLater, Qt::DirectConnection);
}

Connection::~Connection()
{
    if (remote->isOpen()) {
        remote->close();
    }
    if (local->isOpen()) {
        local->close();
    }
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
            QHostAddress addr = local->peerAddress();
            quint16 port = local->peerPort();
            local->write(header + Common::packAddress(addr, port));
            stage = UDP_ASSOC;
            return;
        }
        else if (cmd == 1) {//CMD_CONNECT
            data = data.mid(3);
        }
        else {
            emit error("Unknown command " + QString::number(cmd));
            emit destroyMe();
            return;
        }
    }

    int header_length = 0;
    Common::parseHeader(data, remoteAddress, header_length);
    if (header_length == 0) {
        emit error("Can't parse header");
        return;
    }
    emit info("Connecting " + remoteAddress.getAddress().toLocal8Bit() + ":" + QString::number(remoteAddress.getPort()).toLocal8Bit());
    stage = REPLY;//skip DNS, because we use getRealIPAddress function of Address class, which will always return IP address.

    if (isLocal) {
        static char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 16, 16 };
        QByteArray response(res, 10);
        local->write(response);
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

bool Connection::writeToRemote(const QByteArray &data)
{
    if (!isLocal && remote->state() != QAbstractSocket::ConnectedState) {
        remote->connectToHost(remoteAddress.getRealIPAddress(), remoteAddress.getPort());
    }
    qint64 s = remote->write(data);
    return s != -1;
}

void Connection::onLocalTcpSocketError()
{
    if (local->error() != QAbstractSocket::RemoteHostClosedError) {//it's not an "error" if remote host closed a connection
        QString str = QString("Local socket error: ") + local->errorString();
        emit error(str);
        emit destroyMe();
    }
}

void Connection::onRemoteTcpSocketError()
{
    if (remote->error() != QAbstractSocket::RemoteHostClosedError) {//it's not an "error" if remote host closed a connection
        QString str = QString("Remote socket error: ") + remote->errorString();
        emit error(str);
        emit destroyMe();
    }
}

void Connection::onLocalTcpSocketReadyRead()
{
    QByteArray data = local->readAll();

    if (data.isEmpty()) {
        emit destroyMe();
        return;
    }
    if (!isLocal) {
        data = encryptor->decrypt(data);
        if (data.isEmpty()) {
            return;
        }
    }
    if (stage == STREAM) {
        if (isLocal) {
            data = encryptor->encrypt(data);
        }
        writeToRemote(data);
        return;
    }
    else if (isLocal && stage == INIT) {
        QByteArray auth;
        if (data[0] != char(5)) {
            auth.append(char(0));
            auth.append(char(91));
        }
        else {
            auth.append(char(5));
            auth.append(char(0));
        }
        local->write(auth);
        stage = HELLO;
        return;
    }
    else if (stage == REPLY) {
        handleStageReply(data);
    }
    else if ((isLocal && stage == HELLO) || (!isLocal && stage == INIT)) {
        handleStageHello(data);
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
    local->write(buf);
}
