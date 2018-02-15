/*
 * tcprelay.h - the header file of TcpRelay class
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

#ifndef TCPRELAY_H
#define TCPRELAY_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include <QTime>
#include "types/address.h"
#include "crypto/encryptor.h"

namespace QSS {

/**
 * The abstract base class representing a Shadowsocks TCP connection
 */
class QSS_EXPORT TcpRelay : public QObject
{
    Q_OBJECT
public:
    TcpRelay(QTcpSocket *localSocket,
             int timeout,
             Address server_addr,
             const std::string& method,
             const std::string& password);

    TcpRelay(const TcpRelay &) = delete;

    enum STAGE { INIT, ADDR, UDP_ASSOC, DNS, CONNECTING, STREAM, DESTROYED };

signals:
    /*
     * Count only remote socket's traffic
     * Either in local or server mode, the remote socket is used to communicate
     * with other-side shadowsocks instance (a local or a server)
     */
    void bytesRead(quint64);
    void bytesSend(quint64);

    //time used for remote to connect to the host (msec)
    void latencyAvailable(int);
    void finished();

protected:
    static const int64_t RemoteRecvSize = 65536;

    STAGE stage;
    Address remoteAddress;
    Address serverAddress;
    std::string dataToWrite;

    std::unique_ptr<Encryptor> encryptor;
    std::unique_ptr<QTcpSocket> local;
    std::unique_ptr<QTcpSocket> remote;
    std::unique_ptr<QTimer> timer;
    QTime startTime;

    bool writeToRemote(const char *data, size_t length);

    virtual void handleStageAddr(std::string &data) = 0;
    virtual void handleLocalTcpData(std::string &data) = 0;
    virtual void handleRemoteTcpData(std::string &data) = 0;

protected slots:
    void onRemoteConnected();
    void onRemoteTcpSocketError();
    void onLocalTcpSocketError();
    void onLocalTcpSocketReadyRead();
    void onRemoteTcpSocketReadyRead();
    void onTimeout();
    void close();
};

}
#endif // TCPRELAY_H
