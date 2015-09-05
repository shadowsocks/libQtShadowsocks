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

#include <QDebug>
#include "tcprelay.h"
#include "common.h"

using namespace QSS;

TcpRelay::TcpRelay(QTcpSocket &localTcpSocket, QTcpSocket &remoteTcpSocket, int timeout, const Address &server_addr, const EncryptorPrivate *ep, bool is_local, QObject *parent) :
    QObject(parent),
    stage(INIT),
    serverAddress(server_addr),
    isLocal(is_local),
    local(localTcpSocket),
    remote(remoteTcpSocket),
    encryptor(ep)
{
    timer.setInterval(timeout);

    connect(&remoteAddress, &Address::lookedUp, this, &TcpRelay::onDNSResolved);
    connect(&serverAddress, &Address::lookedUp, this, &TcpRelay::onDNSResolved);

    connect(&timer, &QTimer::timeout, this, &TcpRelay::onTimeout);

    connect(&local, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &TcpRelay::onLocalTcpSocketError);
    connect(&local, &QTcpSocket::disconnected, this, &TcpRelay::finished);
    connect(&local, &QTcpSocket::readyRead, this, &TcpRelay::onLocalTcpSocketReadyRead);
    connect(&local, &QTcpSocket::readyRead, &timer, static_cast<void (QTimer::*)()> (&QTimer::start));

    connect(&remote, &QTcpSocket::connected, this, &TcpRelay::onRemoteConnected);
    connect(&remote, static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)> (&QTcpSocket::error), this, &TcpRelay::onRemoteTcpSocketError);
    connect(&remote, &QTcpSocket::disconnected, this, &TcpRelay::finished);
    connect(&remote, &QTcpSocket::readyRead, this, &TcpRelay::onRemoteTcpSocketReadyRead);
    connect(&remote, &QTcpSocket::readyRead, &timer, static_cast<void (QTimer::*)()> (&QTimer::start));
    connect(&remote, &QTcpSocket::bytesWritten, this, &TcpRelay::bytesSend);

    local.setReadBufferSize(RecvSize);
    local.setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local.setSocketOption(QAbstractSocket::KeepAliveOption, 1);

    remote.setReadBufferSize(RecvSize);
    remote.setSocketOption(QAbstractSocket::LowDelayOption, 1);
    remote.setSocketOption(QAbstractSocket::KeepAliveOption, 1);
}

void TcpRelay::handleStageAddr(QByteArray data)
{
    if (isLocal) {
        int cmd = static_cast<int>(data.at(1));
        if (cmd == 3) {//CMD_UDP_ASSOCIATE
            emit info("UDP associate");
            QByteArray header;
            header.append(char(5));
            header.append(char(0));
            header.append(char(0));
            QHostAddress addr = local.peerAddress();
            quint16 port = local.peerPort();
            local.write(header + Common::packAddress(addr, port));
            stage = UDP_ASSOC;
            return;
        } else if (cmd == 1) {//CMD_CONNECT
            data = data.mid(3);
        } else {
            emit info("Unknown command " + QString::number(cmd));
            emit finished();
            return;
        }
    }

    int header_length = 0;
    Common::parseHeader(data, remoteAddress, header_length);
    if (header_length == 0) {
        emit info("Can't parse header");
        if (!isLocal) {//return random data as an anti-attack measure
            QByteArray badIV = encryptor.deCipherIV();
            QHostAddress badAddr = local.peerAddress();
            bool banThisIP = false;

            Common::failedIVMutex.lock();
            if (Common::failedIVVector.contains(badIV)) {
                banThisIP = true;
            } else {
                Common::failedIVVector.append(badIV);
                Common::failedAddressMutex.lock();
                if (Common::failedAddressVector.contains(badAddr)) {
                    banThisIP = true;
                } else {
                    Common::failedAddressVector.append(badAddr);
                }
                Common::failedAddressMutex.unlock();
            }
            Common::failedIVMutex.unlock();

            if (banThisIP) {
                Common::bannedAddressMutex.lock();
                if (!Common::bannedAddressVector.contains(badAddr)) {
                    Common::bannedAddressVector.append(badAddr);
                    emit info(badAddr.toString() + " is banned for accessing this server using a malformed header");
                }
                Common::bannedAddressMutex.unlock();
            }

            std::random_device rd;
            std::default_random_engine gen(rd());
            std::uniform_int_distribution<> dis(1, 256);
            //let's be naughty, we may, or may not send it some data
            int random_threshold = dis(gen);
            if (dis(gen) > random_threshold) {
                local.write(Cipher::randomIv(dis(gen)));//randomIv returns a random byte array
            }
        }
        emit finished();
        return;
    }

    QString con_info;
    QDebug(&con_info) << "Connecting" << remoteAddress.getAddress().toLocal8Bit() << "at port" << remoteAddress.getPort() << "from" << local.peerAddress().toString().toLocal8Bit() << "at port" << local.peerPort();
    emit info(con_info);

    stage = DNS;
    if (isLocal) {
        static const char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 16, 16 };
        static const QByteArray response(res, 10);
        local.write(response);

        dataToWrite.append(encryptor.encrypt(data));
        serverAddress.lookUp();
    } else {
        if (data.length() > header_length) {
            dataToWrite.append(data.mid(header_length));
        }
        remoteAddress.lookUp();
    }
}

void TcpRelay::onLocalTcpSocketError()
{
    if (local.error() != QAbstractSocket::RemoteHostClosedError) {//it's not an "error" if remote host closed a connection
        emit info("Local socket error: " + local.errorString());
    }
    emit finished();
}

void TcpRelay::onDNSResolved(const bool success, const QString errStr)
{
    if (success) {
        stage = CONNECTING;
        if (isLocal) {
            remote.connectToHost(serverAddress.getFirstIP(), serverAddress.getPort());
        } else {
            remote.connectToHost(remoteAddress.getFirstIP(), remoteAddress.getPort());
        }
    } else {
        emit info("DNS resolve failed: " + errStr);
        emit finished();
    }
}

bool TcpRelay::writeToRemote(const QByteArray &data)
{
    return remote.write(data) != -1;
}

void TcpRelay::onRemoteConnected()
{
    stage = STREAM;
    writeToRemote(dataToWrite);
    dataToWrite.clear();
}

void TcpRelay::onRemoteTcpSocketError()
{
    if (remote.error() != QAbstractSocket::RemoteHostClosedError) {//it's not an "error" if remote host closed a connection
        emit info("Remote socket error: " + remote.errorString());
    }
    emit finished();
}

void TcpRelay::onLocalTcpSocketReadyRead()
{
    QByteArray data = local.readAll();

    if (data.isEmpty()) {
        emit info("Local received empty data.");
        emit finished();
        return;
    }

    if (!isLocal) {
        data = encryptor.decrypt(data);
        if (data.isEmpty()) {
            emit debug("Data is empty after decryption.");
            return;
        }
    }

    if (stage == STREAM) {
        if (isLocal) {
            data = encryptor.encrypt(data);
        }
        writeToRemote(data);
    } else if (isLocal && stage == INIT) {
        QByteArray auth;
        if (data[0] != char(5)) {
            auth.append(char(0));
            auth.append(char(91));
            emit info("An invalid socket connection was rejected. Please make sure the connection type is SOCKS5.");
        } else {
            auth.append(char(5));
            auth.append(char(0));
        }
        local.write(auth);
        stage = ADDR;
    } else if (stage == CONNECTING || stage == DNS) {//take DNS into account, otherwise some data will get lost
        if (isLocal) {
            data = encryptor.encrypt(data);
        }
        dataToWrite.append(data);
    } else if ((isLocal && stage == ADDR) || (!isLocal && stage == INIT)) {
        handleStageAddr(data);
    }
}

void TcpRelay::onRemoteTcpSocketReadyRead()
{
    QByteArray buf = remote.readAll();
    if (buf.isEmpty()) {
        emit info("Remote received empty data.");
        emit finished();
        return;
    }
    emit bytesRead(buf.size());
    buf = isLocal ? encryptor.decrypt(buf) : encryptor.encrypt(buf);
    local.write(buf);
}

void TcpRelay::onTimeout()
{
    emit info("TCP connection timeout.");
    emit finished();
}
