/*
 * connection.cpp - the source file of Connection class
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

#include <QDebug>
#include "connection.h"
#include "controller.h"
#include "common.h"

using namespace QSS;

Connection::Connection(QTcpSocket *localTcpSocket, bool is_local, QObject *parent) :
    QObject(parent),
    isLocal(is_local)
{
    Controller *c = qobject_cast<Controller *>(parent);

    if(!c) {
        qCritical() << "Fatal. Connection's parent must be a Controller object.";
        return;
    }

    stage = INIT;
    encryptor = new Encryptor(c->getEncryptorPrivate(), this);
    timer = new QTimer(this);
    timer->setInterval(c->getTimeout());

    local = localTcpSocket;
    remote = new QTcpSocket(this);
    serverAddress = c->getServerAddress();

    connect(&remoteAddress, &Address::lookedUp, this, &Connection::onDNSResolved);
    connect(&serverAddress, &Address::lookedUp, this, &Connection::onDNSResolved);

    connect(timer, &QTimer::timeout, this, &Connection::onTimeout);

    connect(local, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onLocalTcpSocketError);
    connect(local, &QTcpSocket::disconnected, this, &Connection::deleteLater);
    connect(local, &QTcpSocket::readyRead, this, &Connection::onLocalTcpSocketReadyRead);
    connect(local, &QTcpSocket::readyRead, timer, static_cast<void (QTimer::*)()> (&QTimer::start));

    connect(remote, &QTcpSocket::connected, this, &Connection::onRemoteConnected);
    connect(remote, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &Connection::onRemoteTcpSocketError);
    connect(remote, &QTcpSocket::disconnected, this, &Connection::deleteLater);
    connect(remote, &QTcpSocket::readyRead, this, &Connection::onRemoteTcpSocketReadyRead);
    connect(remote, &QTcpSocket::readyRead, timer, static_cast<void (QTimer::*)()> (&QTimer::start));
    connect(remote, &QTcpSocket::bytesWritten, this, &Connection::bytesSend);

    local->setParent(this);
    local->setReadBufferSize(RecvSize);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local->setSocketOption(QAbstractSocket::KeepAliveOption, 1);

    remote->setReadBufferSize(RecvSize);
    remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    remote->setSocketOption(QAbstractSocket::KeepAliveOption, 1);
}

void Connection::handleStageAddr(QByteArray &data)
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
        } else if (cmd == 1) {//CMD_CONNECT
            data = data.mid(3);
        } else {
            emit error("Unknown command " + QString::number(cmd));
            deleteLater();
            return;
        }
    }

    int header_length = 0;
    Common::parseHeader(data, remoteAddress, header_length);
    if (header_length == 0) {
        emit error("Can't parse header");
        return;
    }

    QString con_info;
    QDebug(&con_info) << "Connecting" << remoteAddress.getAddress().toLocal8Bit() << "at port" << remoteAddress.getPort() << "from" << local->peerAddress().toString().toLocal8Bit() << "at port" << local->peerPort();
    emit info(con_info);

    stage = DNS;
    if (isLocal) {
        static const char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 16, 16 };
        static const QByteArray response(res, 10);
        local->write(response);

        dataToWrite.append(encryptor->encrypt(data));
        serverAddress.lookUp();
    } else {
        if (data.length() > header_length) {
            dataToWrite.append(data.mid(header_length));
        }
        remoteAddress.lookUp();
    }
}

void Connection::onLocalTcpSocketError()
{
    if (local->error() != QAbstractSocket::RemoteHostClosedError) {//it's not an "error" if remote host closed a connection
        emit error("Local socket error: " + local->errorString());
    }
}

void Connection::onDNSResolved(const bool success, const QString errStr)
{
    if (success) {
        stage = CONNECTING;
        if (isLocal) {
            remote->connectToHost(serverAddress.getFirstIP(), serverAddress.getPort());
        } else {
            remote->connectToHost(remoteAddress.getFirstIP(), remoteAddress.getPort());
        }
    } else {
        emit error("DNS resolve failed: " + errStr);
        deleteLater();
    }
}

bool Connection::writeToRemote(const QByteArray &data)
{
    return remote->write(data) != -1;
}

void Connection::onRemoteConnected()
{
    stage = STREAM;
    writeToRemote(dataToWrite);
    dataToWrite.clear();
}

void Connection::onRemoteTcpSocketError()
{
    if (remote->error() != QAbstractSocket::RemoteHostClosedError) {//it's not an "error" if remote host closed a connection
        emit error("Remote socket error: " + remote->errorString());
    }
}

void Connection::onLocalTcpSocketReadyRead()
{
    QByteArray data = local->readAll();

    if (data.isEmpty()) {
        emit error("Received empty data.");
        deleteLater();
        return;
    }

    if (!isLocal) {
        data = encryptor->decrypt(data);
        if (data.isEmpty()) {
            emit debug("Data is empty after decryption.");
            return;
        }
    }

    if (stage == STREAM) {
        if (isLocal) {
            data = encryptor->encrypt(data);
        }
        writeToRemote(data);
    } else if (isLocal && stage == INIT) {
        QByteArray auth;
        if (data[0] != char(5)) {
            auth.append(char(0));
            auth.append(char(91));
            emit error("An invalid socket connection was rejected. Please make sure the connection type is SOCKS5.");
        } else {
            auth.append(char(5));
            auth.append(char(0));
            emit debug("Accept a local socket connection.");
        }
        local->write(auth);
        stage = ADDR;
    } else if (stage == CONNECTING || stage == DNS) {//take DNS into account, otherwise some data will get lost
        if (isLocal) {
            data = encryptor->encrypt(data);
        }
        dataToWrite.append(data);
    } else if ((isLocal && stage == ADDR) || (!isLocal && stage == INIT)) {
        handleStageAddr(data);
    }
}

void Connection::onRemoteTcpSocketReadyRead()
{
    QByteArray buf = remote->readAll();
    emit bytesRead(buf.size());

    if (isLocal) {
        buf = encryptor->decrypt(buf);
    } else {
        buf = encryptor->encrypt(buf);
    }
    local->write(buf);
}

void Connection::onTimeout()
{
    emit info("Connection timeout.");
    deleteLater();
}
