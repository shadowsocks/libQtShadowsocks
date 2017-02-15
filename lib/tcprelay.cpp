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

using namespace QSS;

TcpRelay::TcpRelay(QTcpSocket *localSocket,
                   int timeout,
                   const Address &server_addr,
                   const EncryptorPrivate &ep,
                   const bool &is_local,
                   const bool &autoBan,
                   const bool &auth,
                   QObject *parent) :
    QObject(parent),
    stage(INIT),
    serverAddress(server_addr),
    isLocal(is_local),
    autoBan(autoBan),
    auth(auth),
    local(localSocket)
{
    encryptor = new Encryptor(ep, this);

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

    // To make sure datagram doesn't exceed remote server's maximum, we can
    // limit how many bytes we take from local socket at a time. This is due
    // the overhead introduced by OTA.
    quint64 localRecvSize = RemoteRecvSize;
    if (auth && isLocal) {
        localRecvSize -= (Cipher::AUTH_LEN + 2);
    }
    local->setReadBufferSize(localRecvSize);
    local->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    local->setSocketOption(QAbstractSocket::KeepAliveOption, 1);

    remote->setReadBufferSize(RemoteRecvSize);
    remote->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    remote->setSocketOption(QAbstractSocket::KeepAliveOption, 1);
}

TcpRelay::~TcpRelay()
{
	encryptor->deleteLater();
	timer->deleteLater();
	remote->deleteLater();
	local->deleteLater();
}

void TcpRelay::close()
{
    if (stage == DESTROYED) {
        return;
    }

    stage = DESTROYED;
    local->close();
    remote->close();
    emit finished();
}

void TcpRelay::handleStageAddr(QByteArray &data)
{
    if (isLocal) {
        int cmd = static_cast<int>(data.at(1));
        if (cmd == 3) {//CMD_UDP_ASSOCIATE
            emit debug("UDP associate");
            static const char header_data [] = { 5, 0, 0 };
            static const QByteArray header(header_data, 3);
            QHostAddress addr = local->localAddress();
            quint16 port = local->localPort();
            local->write(header + Common::packAddress(addr, port));
            stage = UDP_ASSOC;
            return;
        } else if (cmd == 1) {//CMD_CONNECT
            data = data.mid(3);
        } else {
            emit info("Unknown command " + QString::number(cmd));
            close();
            return;
        }
    }

    int header_length = 0;
    Common::parseHeader(data, remoteAddress, header_length, auth);
    if (header_length == 0) {
        emit info("Can't parse header. Wrong encryption method or password?");
        if (!isLocal && autoBan) {
            Common::banAddress(local->peerAddress());
        }
        close();
        return;
    }

    emit info(QString("Connecting %1:%2 from %3:%4")
              .arg(remoteAddress.getAddress())
              .arg(remoteAddress.getPort())
              .arg(local->peerAddress().toString())
              .arg(local->peerPort()));

    stage = DNS;
    if (isLocal) {
        static const char res [] = { 5, 0, 0, 1, 0, 0, 0, 0, 16, 16 };
        static const QByteArray response(res, 10);
        local->write(response);

        if (auth) {
            char atyp = data[0];
            data[0] = (atyp | Common::ONETIMEAUTH_FLAG);
            if (data.length() > header_length) {
                QByteArray header = data.left(header_length);
                QByteArray chunk = data.mid(header_length);
                encryptor->addHeaderAuth(header);
                encryptor->addChunkAuth(chunk);
                data = header + chunk;
            } else {
                encryptor->addHeaderAuth(data);
            }
        }
        dataToWrite.append(encryptor->encrypt(data));
        serverAddress.lookUp();
    } else {
        if (auth) {
            if (!encryptor->verifyHeaderAuth(data, header_length)) {
                emit info("One-time message authentication for header failed.");
                if (autoBan) {
                    Common::banAddress(local->peerAddress());
                }
                close();
                return;
            } else {
                header_length += Cipher::AUTH_LEN;
            }
        }

        if (data.length() > header_length) {
            data.remove(0, header_length);
            if (auth) {
                if (!encryptor->verifyExtractChunkAuth(data)) {
                    emit info("Data chunk hash authentication failed.");
                    if (autoBan) {
                        Common::banAddress(local->peerAddress());
                    }
                    close();
                    return;
                }
            }
            dataToWrite.append(data);
        }
        remoteAddress.lookUp();
    }
}

void TcpRelay::onLocalTcpSocketError()
{
    //it's not an "error" if remote host closed a connection
    if (local->error() != QAbstractSocket::RemoteHostClosedError) {
        emit info("Local socket error: " + local->errorString());
    } else {
        emit debug("Local socket debug: " + local->errorString());
    }
    close();
}

void TcpRelay::onDNSResolved(const bool success, const QString errStr)
{
    if (success) {
        stage = CONNECTING;
        Address *addr = qobject_cast<Address*>(sender());
        startTime = QTime::currentTime();
        remote->connectToHost(addr->getFirstIP(), addr->getPort());
    } else {
        emit info("DNS resolve failed: " + errStr);
        close();
    }
}

bool TcpRelay::writeToRemote(const QByteArray &data)
{
    return remote->write(data) != -1;
}

void TcpRelay::onRemoteConnected()
{
    emit latencyAvailable(startTime.msecsTo(QTime::currentTime()));
    stage = STREAM;
    if (!dataToWrite.isEmpty()) {
        writeToRemote(dataToWrite);
    }
    dataToWrite.clear();
}

void TcpRelay::onRemoteTcpSocketError()
{
    //it's not an "error" if remote host closed a connection
    if (remote->error() != QAbstractSocket::RemoteHostClosedError) {
        emit info("Remote socket error: " + remote->errorString());
    } else {
        emit debug("Remote socket debug: " + remote->errorString());
    }
    close();
}

void TcpRelay::onLocalTcpSocketReadyRead()
{
    QByteArray data = local->readAll();

    if (data.isEmpty()) {
        emit info("Local received empty data.");
        close();
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
            Common::qOut << data.toHex() << endl;
            if (auth) {
                encryptor->addChunkAuth(data);
            }
            data = encryptor->encrypt(data);
        } else if (auth) {
            if (!encryptor->verifyExtractChunkAuth(data)) {
                emit info("Data chunk hash authentication failed.");
                if (autoBan) {
                    Common::banAddress(local->peerAddress());
                }
                close();
                return;
            } else if (data.isEmpty()) {
                return;
            }
        }
        writeToRemote(data);
    } else if (isLocal && stage == INIT) {
        static const char reject_data [] = { 0, 91 };
        static const char accept_data [] = { 5, 0 };
        static const QByteArray reject(reject_data, 2);
        static const QByteArray accept(accept_data, 2);
        if (data[0] != char(5)) {
            emit info("An invalid socket connection was rejected. "
                      "Please make sure the connection type is SOCKS5.");
            local->write(reject);
        } else {
            local->write(accept);
        }
        stage = ADDR;
    } else if (stage == CONNECTING || stage == DNS) {
        //take DNS into account, otherwise some data will get lost
        if (isLocal) {
            if (auth) {
                encryptor->addChunkAuth(data);
            }
            data = encryptor->encrypt(data);
        } else if (auth) {
            if (!encryptor->verifyExtractChunkAuth(data)) {
                emit info("Data chunk hash authentication failed.");
                if (autoBan) {
                    Common::banAddress(local->peerAddress());
                }
                close();
                return;
            }
        }
        dataToWrite.append(data);
    } else if ((isLocal && stage == ADDR) || (!isLocal && stage == INIT)) {
        handleStageAddr(data);
    }
}

void TcpRelay::onRemoteTcpSocketReadyRead()
{
    QByteArray buf = remote->readAll();
    if (buf.isEmpty()) {
        emit info("Remote received empty data.");
        close();
        return;
    }
    emit bytesRead(buf.size());
    buf = isLocal ? encryptor->decrypt(buf) : encryptor->encrypt(buf);
    local->write(buf);
}

void TcpRelay::onTimeout()
{
    emit info("TCP connection timeout.");
    close();
}
