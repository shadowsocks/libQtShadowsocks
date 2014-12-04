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
#include "basecontroller.h"

Connection::Connection(QTcpSocket *localTcpSocket, QObject *parent) :
    QObject(parent)
{
    BaseController *c = qobject_cast<BaseController *>(parent);

    if(c == NULL) {
        qCritical() << "Fatal. Connection's parent must be a BaseController object.";
        return;
    }

    encryptor = new Encryptor(this);

    local = localTcpSocket;
    local->setParent(this);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local->setReadBufferSize(RecvSize);

    remote = new QTcpSocket(this);
    remote->setReadBufferSize(RecvSize);
    remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    remote->connectToHost(c->getServerAddr(), c->getServerPort());

    socketDescriptor = local->socketDescriptor();

    connect(local, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onLocalTcpSocketError);
    connect(local, &QTcpSocket::disconnected, this, &Connection::disconnected, Qt::DirectConnection);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onHandshaked, Qt::DirectConnection);

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

void Connection::onLocalTcpSocketError()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (socket == NULL) {
        emit error("Error. Invalid object called onLocalTcpSocketError.");
        return;
    }

    QString str = QString("local socket error: ") + socket->errorString();
    emit error(str);
}

void Connection::onRemoteTcpSocketError()
{
    QString str = QString("remote socket error: ") + remote->errorString();
    emit error(str);
}

void Connection::onHandshaked()
{
    QByteArray buf = local->read(256);
    if (buf.isEmpty()) {
        emit info("onHandshaked. Error! Received empty data from server.");
        return;
    }

    QByteArray response;
    response.append(char(5)).append(char(0));
    if (buf[0] != char(5)) {//reject socket v4
        emit info("a socket v4 connection was rejected.");
        response[0] = 0;
        response[1] = 91;
    }

    disconnect(local, &QTcpSocket::readyRead, this, &Connection::onHandshaked);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onHandshaked2, Qt::DirectConnection);

    local->write(response);
}

void Connection::onHandshaked2()
{
    QByteArray buf = local->read(3);
    if (buf.isEmpty()) {
        emit error("onHandshaked2 Error! Received empty data from server.");
        return;
    }

    static char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
    static QByteArray response = QByteArray::fromRawData(res, sizeof(res));

    disconnect(local, &QTcpSocket::readyRead, this, &Connection::onHandshaked2);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onLocalTcpSocketReadyRead, Qt::DirectConnection);

    local->write(response);
}

void Connection::onLocalTcpSocketReadyRead()
{
    QTcpSocket *socket = qobject_cast<QTcpSocket *>(sender());
    if (socket == NULL) {
        emit error("Error. Invalid object called onLocalTcpSocketReadyRead.");
        return;
    }

    QByteArray buf = socket->readAll();
    QByteArray dataToSend = encryptor->encrypt(buf);
    remote->write(dataToSend);
}

void Connection::onRemoteTcpSocketReadyRead()
{
    QByteArray buf = remote->readAll();
    QByteArray dataToSend = encryptor->decrypt(buf);
    local->write(dataToSend);
}
