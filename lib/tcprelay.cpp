/*
 * tcprelay.cpp - the source file of TcpRelay class
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

#include "tcprelay.h"
#include "common.h"
#include <QDebug>

using namespace QSS;

TcpRelay::TcpRelay(QTcpSocket *localSocket,
                   int timeout,
                   const Address &server_addr,
                   const std::string &method,
                   const std::string &password,
                   bool is_local,
                   bool autoBan,
                   QObject *parent) :
    QObject(parent),
    stage(INIT),
    serverAddress(server_addr),
    isLocal(is_local),
    autoBan(autoBan),
    local(localSocket),
    encryptor{new Encryptor(method, password)}
{
    connect(&remoteAddress, &Address::lookedUp,
            this, &TcpRelay::onDNSResolved);
    connect(&serverAddress, &Address::lookedUp,
            this, &TcpRelay::onDNSResolved);

    timer = new QTimer(this);
    timer->setInterval(timeout);
    connect(timer, &QTimer::timeout, this, &TcpRelay::onTimeout);

    local->setParent(this);
    connect(local,
            static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>
            (&QTcpSocket::error),
            this,
            &TcpRelay::onLocalTcpSocketError);
    connect(local, &QTcpSocket::disconnected, this, &TcpRelay::close);
    connect(local, &QTcpSocket::readyRead,
            this, &TcpRelay::onLocalTcpSocketReadyRead);
    connect(local, &QTcpSocket::readyRead,
            timer, static_cast<void (QTimer::*)()> (&QTimer::start));

    remote = new QTcpSocket(this);
    connect(remote, &QTcpSocket::connected, this, &TcpRelay::onRemoteConnected);
    connect(remote,
            static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>
            (&QTcpSocket::error),
            this, &TcpRelay::onRemoteTcpSocketError);
    connect(remote, &QTcpSocket::disconnected, this, &TcpRelay::close);
    connect(remote, &QTcpSocket::readyRead,
            this, &TcpRelay::onRemoteTcpSocketReadyRead);
    connect(remote, &QTcpSocket::readyRead,
            timer, static_cast<void (QTimer::*)()> (&QTimer::start));
    connect(remote, &QTcpSocket::bytesWritten, this, &TcpRelay::bytesSend);

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

void TcpRelay::handleStageAddr(std::string &data)
{
    if (isLocal) {
        int cmd = static_cast<int>(data.at(1));
        if (cmd == 3) {//CMD_UDP_ASSOCIATE
            qDebug("UDP associate");
            static const char header_data [] = { 5, 0, 0 };
            QHostAddress addr = local->localAddress();
            uint16_t port = local->localPort();
            std::string toWrite = std::string(header_data, 3) + Common::packAddress(addr, port);
            local->write(toWrite.data(), toWrite.length());
            stage = UDP_ASSOC;
            return;
        } else if (cmd == 1) {//CMD_CONNECT
            data = data.substr(3);
        } else {
            qCritical("Unknown command %d", cmd);
            close();
            return;
        }
    }

    int header_length = 0;
    Common::parseHeader(data, remoteAddress, header_length);
    if (header_length == 0) {
        qCritical("Can't parse header. Wrong encryption method or password?");
        if (!isLocal && autoBan) {
            Common::banAddress(local->peerAddress());
        }
        close();
        return;
    }

    QDebug(QtMsgType::QtInfoMsg) << "Connecting " << remoteAddress
                                 << " from " << local->peerAddress().toString()
                                 << ":" << local->peerPort();

    stage = DNS;
    if (isLocal) {
        static const char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 16, 16 };
        static const QByteArray response(res, 10);
        local->write(response);
        std::string toWrite = encryptor->encrypt(data);
        dataToWrite += toWrite;
        serverAddress.lookUp();
    } else {
        if (data.size() > header_length) {
            data = data.substr(header_length);
            dataToWrite += data;
        }
        remoteAddress.lookUp();
    }
}

void TcpRelay::onLocalTcpSocketError()
{
    //it's not an "error" if remote host closed a connection
    if (local->error() != QAbstractSocket::RemoteHostClosedError) {
        QDebug(QtMsgType::QtWarningMsg) << "Local socket error: " << local->errorString();
    } else {
        QDebug(QtMsgType::QtInfoMsg) << "Local socket info: " << local->errorString();
    }
    close();
}

void TcpRelay::onDNSResolved(const bool success, const QString &errStr)
{
    if (success) {
        stage = CONNECTING;
        Address *addr = qobject_cast<Address*>(sender());
        startTime = QTime::currentTime();
        remote->connectToHost(addr->getFirstIP(), addr->getPort());
    } else {
        QDebug(QtMsgType::QtCriticalMsg) << "DNS resolve failed: " << errStr;
        close();
    }
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
        QDebug(QtMsgType::QtWarningMsg) << "Remote socket error: " << remote->errorString();
    } else {
        QDebug(QtMsgType::QtInfoMsg) << "Remote socket info: " << remote->errorString();
    }
    close();
}

void TcpRelay::onLocalTcpSocketReadyRead()
{
    const QByteArray _data = local->readAll();
    std::string data(_data.data(), _data.size());

    if (data.empty()) {
        qCritical("Local received empty data.");
        close();
        return;
    }

    if (!isLocal) {
        try {
            data = encryptor->decrypt(data);
        } catch (const std::exception &e) {
            QDebug(QtMsgType::QtCriticalMsg) << "Local: " << e.what();
            close();
            return;
        }

        if (data.empty()) {
            qWarning("Data is empty after decryption.");
            return;
        }
    }

    if (stage == STREAM) {
        if (isLocal) {
            data = encryptor->encrypt(data);
        }
        writeToRemote(data.data(), data.size());
    } else if (isLocal && stage == INIT) {
        static const char reject_data [] = { 0, 91 };
        static const char accept_data [] = { 5, 0 };
        static const QByteArray reject(reject_data, 2);
        static const QByteArray accept(accept_data, 2);
        if (data[0] != char(5)) {
            qCritical("An invalid socket connection was rejected. "
                      "Please make sure the connection type is SOCKS5.");
            local->write(reject);
        } else {
            local->write(accept);
        }
        stage = ADDR;
    } else if (stage == CONNECTING || stage == DNS) {
        //take DNS into account, otherwise some data will get lost
        if (isLocal) {
            data = encryptor->encrypt(data);
        }
        dataToWrite += data;
    } else if ((isLocal && stage == ADDR) || (!isLocal && stage == INIT)) {
        handleStageAddr(data);
    }
}

void TcpRelay::onRemoteTcpSocketReadyRead()
{
    QByteArray _buf = remote->readAll();
    std::string buf(_buf.data(), _buf.size());
    if (buf.empty()) {
        qWarning("Remote received empty data.");
        close();
        return;
    }
    emit bytesRead(buf.size());
    try {
        buf = isLocal ? encryptor->decrypt(buf) : encryptor->encrypt(buf);
    } catch (const std::exception &e) {
        QDebug(QtMsgType::QtCriticalMsg) << "Remote: " << e.what();
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
