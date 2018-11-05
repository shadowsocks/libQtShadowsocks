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
                   const Encryptor::Creator& ec) :
    m_stage(INIT),
    m_serverAddress(std::move(server_addr)),
    m_encryptor(ec()),
    m_local(localSocket),
    m_remote(new QTcpSocket()),
    m_timer(new QTimer())
{
    m_timer->setInterval(timeout);
    connect(m_timer.get(), &QTimer::timeout, this, &TcpRelay::onTimeout);

    connect(m_local.get(),
            static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>
            (&QTcpSocket::error),
            this,
            &TcpRelay::onLocalTcpSocketError);
    connect(m_local.get(), &QTcpSocket::disconnected, this, &TcpRelay::close);
    connect(m_local.get(), &QTcpSocket::readyRead,
            this, &TcpRelay::onLocalTcpSocketReadyRead);
    connect(m_local.get(), &QTcpSocket::readyRead,
            m_timer.get(), static_cast<void (QTimer::*)()> (&QTimer::start));

    connect(m_remote.get(), &QTcpSocket::connected, this, &TcpRelay::onRemoteConnected);
    connect(m_remote.get(),
            static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>
            (&QTcpSocket::error),
            this, &TcpRelay::onRemoteTcpSocketError);
    connect(m_remote.get(), &QTcpSocket::disconnected, this, &TcpRelay::close);
    connect(m_remote.get(), &QTcpSocket::readyRead,
            this, &TcpRelay::onRemoteTcpSocketReadyRead);
    connect(m_remote.get(), &QTcpSocket::readyRead,
            m_timer.get(), static_cast<void (QTimer::*)()> (&QTimer::start));
    connect(m_remote.get(), &QTcpSocket::bytesWritten, this, &TcpRelay::bytesSend);

    m_local->setReadBufferSize(RemoteRecvSize);
    m_local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    m_local->setSocketOption(QAbstractSocket::KeepAliveOption, 1);

    m_remote->setReadBufferSize(RemoteRecvSize);
    m_remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    m_remote->setSocketOption(QAbstractSocket::KeepAliveOption, 1);
}

void TcpRelay::close()
{
    if (m_stage == DESTROYED) {
        return;
    }

    m_local->close();
    m_remote->close();
    m_stage = DESTROYED;
    emit finished();
}

void TcpRelay::onLocalTcpSocketError()
{
    //it's not an "error" if remote host closed a connection
    if (m_local->error() != QAbstractSocket::RemoteHostClosedError) {
        QDebug(QtMsgType::QtWarningMsg).noquote() << "Local socket:" << m_local->errorString();
    } else {
        QDebug(QtMsgType::QtDebugMsg).noquote() << "Local socket:" << m_local->errorString();
    }
    close();
}

bool TcpRelay::writeToRemote(const char *data, size_t length)
{
    return m_remote->write(data, length) != -1;
}

void TcpRelay::onRemoteConnected()
{
    emit latencyAvailable(m_startTime.msecsTo(QTime::currentTime()));
    m_stage = STREAM;
    if (!m_dataToWrite.empty()) {
        writeToRemote(m_dataToWrite.data(), m_dataToWrite.size());
        m_dataToWrite.clear();
    }
}

void TcpRelay::onRemoteTcpSocketError()
{
    //it's not an "error" if remote host closed a connection
    if (m_remote->error() != QAbstractSocket::RemoteHostClosedError) {
        QDebug(QtMsgType::QtWarningMsg).noquote() << "Remote socket:" << m_remote->errorString();
    } else {
        QDebug(QtMsgType::QtDebugMsg).noquote() << "Remote socket:" << m_remote->errorString();
    }
    close();
}

void TcpRelay::onLocalTcpSocketReadyRead()
{
    std::string data;
    data.resize(RemoteRecvSize);
    int64_t readSize = m_local->read(&data[0], data.size());
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
    int64_t readSize = m_remote->read(&buf[0], buf.size());
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
    m_local->write(buf.data(), buf.size());
}

void TcpRelay::onTimeout()
{
    qInfo("TCP connection timeout.");
    close();
}

}  // namespace QSS
