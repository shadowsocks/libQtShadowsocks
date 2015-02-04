/*
 * connection.h - the header file of Connection class
 *
 * This class represents TCP connection only.
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

#ifndef CONNECTION_H
#define CONNECTION_H

#include <QObject>
#include <QTcpSocket>
#include <QTimer>
#include "address.h"
#include "encryptor.h"

namespace QSS {

class Connection : public QObject
{
    Q_OBJECT
public:
    explicit Connection(QTcpSocket *localTcpSocket, bool is_local = true, QObject *parent = 0);

    enum STAGE {INIT, HELLO, UDP_ASSOC, DNS, STREAM};//we don't have REPLY, DESTROYED stages. the DNS is not implemented neither.

signals:
    void debug(const QString &);
    void info(const QString &);
    void error(const QString &);

    /*
     * Count only remote socket's traffic
     * Either in local or server mode, the remote socket is used to communicate
     * with other-side shadowsocks instance (a local or a server)
     */
    void bytesRead(const qint64 &);
    void bytesSend(const qint64 &);

private:
    const bool isLocal;

    QTcpSocket *local;
    QTcpSocket *remote;
    QTimer *timer;
    Encryptor *encryptor;

    STAGE stage;
    Address remoteAddress;

    void handleStageHello(QByteArray &);
    bool writeToRemote(const QByteArray &);

    static const qint64 RecvSize = 32736;//32KB, same as shadowsocks-python

private slots:
    void onRemoteTcpSocketError();
    void onRemoteTcpSocketReadyRead();
    void onLocalTcpSocketError();
    void onLocalTcpSocketReadyRead();
    void onTimeout();
};

}
#endif // CONNECTION_H
