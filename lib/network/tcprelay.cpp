/*
 * tcprelay.cpp - the source file of TcpRelay class
 *
 * Copyright (C) 2014-2018 Symeon Huang <hzwhuang@gmail.com>
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

#include "tcprelay.h"
#include "util/common.h"
#include <QDebug>
#include <utility>

namespace QSS {

TcpRelay::TcpRelay(QTcpSocket *localSocket,
                   int timeout,
                   Address server_addr,
                   const std::string &method,
                   const std::string &password) :
    stage(INIT),
    serverAddress(std::move(server_addr)),
    encryptor(new Encryptor(method, password)),
    local(localSocket),
    remote(new QTcpSocket()),
    timer(new QTimer())
{
    timer->setInterval(timeout);
    connect(timer.get(), &QTimer::timeout, this, &TcpRelay::onTimeout);

    connect(local.get(),
            static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>
            (&QTcpSocket::error),
            this,
            &TcpRelay::onLocalTcpSocketError);
    connect(local.get(), &QTcpSocket::disconnected, this, &TcpRelay::close);
    connect(local.get(), &QTcpSocket::readyRead,
            this, &TcpRelay::onLocalTcpSocketReadyRead);
    connect(local.get(), &QTcpSocket::readyRead,
            timer.get(), static_cast<void (QTimer::*)()> (&QTimer::start));

    connect(remote.get(), &QTcpSocket::connected, this, &TcpRelay::onRemoteConnected);
    connect(remote.get(),
            static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>
            (&QTcpSocket::error),
            this, &TcpRelay::onRemoteTcpSocketError);
    connect(remote.get(), &QTcpSocket::disconnected, this, &TcpRelay::close);
    connect(remote.get(), &QTcpSocket::readyRead,
            this, &TcpRelay::onRemoteTcpSocketReadyRead);
    connect(remote.get(), &QTcpSocket::readyRead,
            timer.get(), static_cast<void (QTimer::*)()> (&QTimer::start));
    connect(remote.get(), &QTcpSocket::bytesWritten, this, &TcpRelay::bytesSend);

    local->setReadBufferSize(RemoteRecvSize);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local->setSocketOption(QAbstractSocket::KeepAliveOption, 1);

    remote->setReadBufferSize(RemoteRecvSize);
    remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    remote->setSocketOption(QAbstractSocket::KeepAliveOption, 1);
}

void TcpRelay::close()
{
    if (stage == DESTROYED) {
        return;
    }

    local->close();
    remote->close();
    stage = DESTROYED;
    emit finished();
}

void TcpRelay::onLocalTcpSocketError()
{
    //it's not an "error" if remote host closed a connection
    if (local->error() != QAbstractSocket::RemoteHostClosedError) {
        QDebug(QtMsgType::QtWarningMsg).noquote() << "Local socket:" << local->errorString();
    } else {
        QDebug(QtMsgType::QtDebugMsg).noquote() << "Local socket:" << local->errorString();
    }
    close();
}

bool TcpRelay::writeToRemote(const char *data, size_t length)
{
    return remote->write(data, length) != -1;
}

void TcpRelay::onRemoteConnected()
{
    emit latencyAvailable(startTime.msecsTo(QTime::currentTime()));
    stage = STREAM;
    if (!dataToWrite.empty()) {
        writeToRemote(dataToWrite.data(), dataToWrite.size());
        dataToWrite.clear();
    }
}

void TcpRelay::onRemoteTcpSocketError()
{
    //it's not an "error" if remote host closed a connection
    if (remote->error() != QAbstractSocket::RemoteHostClosedError) {
        QDebug(QtMsgType::QtWarningMsg).noquote() << "Remote socket:" << remote->errorString();
    } else {
        QDebug(QtMsgType::QtDebugMsg).noquote() << "Remote socket:" << remote->errorString();
    }
    close();
}

void TcpRelay::onLocalTcpSocketReadyRead()
{
    std::string data;
    data.resize(RemoteRecvSize);
    int64_t readSize = local->read(&data[0], data.size());
    if (readSize == -1) {
        qCritical("Attempted to read from closed local socket.");
        close();
        return;
    }
    data.resize(readSize);

    if (data.empty()) {
        qCritical("Local received empty data.");
        close();
        return;
    }
    handleLocalTcpData(data);
}

void TcpRelay::onRemoteTcpSocketReadyRead()
{
    std::string buf;
    buf.resize(RemoteRecvSize);
    int64_t readSize = remote->read(&buf[0], buf.size());
    if (readSize == -1) {
        qCritical("Attempted to read from closed remote socket.");
        close();
        return;
    }
    buf.resize(readSize);

    if (buf.empty()) {
        qWarning("Remote received empty data.");
        close();
        return;
    }
    emit bytesRead(buf.size());
    try {
        handleRemoteTcpData(buf);
    } catch (const std::exception &e) {
        QDebug(QtMsgType::QtCriticalMsg) << "Remote:" << e.what();
        close();
        return;
    }
    local->write(buf.data(), buf.size());
}

void TcpRelay::onTimeout()
{
    qInfo("TCP connection timeout.");
    close();
}

}  // namespace QSS
