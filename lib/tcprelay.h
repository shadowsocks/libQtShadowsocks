/*
 * tcprelay.h - the header file of TcpRelay class
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

#ifndef TCPRELAY_H
#define TCPRELAY_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include "address.h"
#include "encryptor.h"

namespace QSS {

class TcpRelay : public QObject
{
    Q_OBJECT
public:
    explicit TcpRelay(QTcpSocket *localTcpSocket, int timeout, const Address &server_addr, const EncryptorPrivate *ep, bool is_local = true, QObject *parent = 0);

    enum STAGE {INIT, ADDR, UDP_ASSOC, DNS, CONNECTING, STREAM};//we don't have DESTROYED stage

signals:
    void debug(const QString &);
    void log(const QString &);

    /*
     * Count only remote socket's traffic
     * Either in local or server mode, the remote socket is used to communicate
     * with other-side shadowsocks instance (a local or a server)
     */
    void bytesRead(const qint64 &);
    void bytesSend(const qint64 &);

private:
    static const qint64 RecvSize = 32736;//32KB, same as shadowsocks-python

    STAGE stage;
    Address remoteAddress;
    Address serverAddress;
    QByteArray dataToWrite;
    const bool isLocal;

    QTcpSocket *local;
    QTcpSocket *remote;
    QTimer *timer;
    Encryptor *encryptor;

    void handleStageAddr(QByteArray);
    bool writeToRemote(const QByteArray &);

private slots:
    void onDNSResolved(const bool success, const QString errStr);
    void onRemoteConnected();
    void onRemoteTcpSocketError();
    void onRemoteTcpSocketReadyRead();
    void onLocalTcpSocketError();
    void onLocalTcpSocketReadyRead();
    void onTimeout();
};

}
#endif // TCPRELAY_H
