/*
 * controller.h - the header file of Controller class
 *
 * Copyright (C) 2014-2016 Symeon Huang <hzwhuang@gmail.com>
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

#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <QByteArray>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include "tcpserver.h"
#include "encryptorprivate.h"
#include "export.h"
#include "httpproxy.h"
#include "profile.h"
#include "udprelay.h"

namespace QSS {

class QSS_EXPORT Controller : public QObject
{
    Q_OBJECT
public:
    explicit Controller(bool is_local,
                        bool auto_ban = false,
                        QObject *parent = 0);

    //overloaded function to construct a Controller with given profile
    explicit Controller(const Profile & _profile,
                        bool is_local,
                        bool auto_ban,
                        QObject *parent = 0);
    ~Controller();

    /*
     * You have to call setup before calling start() unless you use the
     * overloaded convenient construction function. This function can also be
     * used to change the Profile without the need to create a new Controller.
     */
    bool setup(const Profile &);

signals:
    /*
     * WARN: an ABI break here
     * You'll need to connect both signals if you need full debug-level log
     */
    void info(const QString &);//only general information
    void debug(const QString &);//only verbose

    //connect this signal to get notified when running state is changed
    void runningStateChanged(bool);

    //these two signals pass any new bytes read or sent
    void newBytesReceived(const quint64 &);
    void newBytesSent(const quint64 &);

    /*
     * these two signals pass accumulated bytes read or sent so far
     * (aka total in this session)
     */
    void bytesReceivedChanged(const qint64 &);
    void bytesSentChanged(const qint64 &);

    /*
     * time used to connect to remote host (msec)
     * remote host means shadowsocks server if this controller is in local mode,
     * or the address the client is accessing if it's in server mode.
     */
    void tcpLatencyAvailable(const int &);

public slots:
    bool start();//return true if start successfully, otherwise return false
    void stop();

protected://children can access protected members
    //the total bytes recevied or sent by/from all TCP and UDP connections.
    qint64 bytesReceived;
    qint64 bytesSent;

    Profile profile;
    Address serverAddress;
    bool valid;
    const bool isLocal;//run on local-side (client) or server-side (server)
    /*
     * auto ban IPs that use malformed header data as our anti-probe measure
     * (only used when it's a server)
     */
    const bool autoBan;
    EncryptorPrivate ep;
    TcpServer *tcpServer;
    UdpRelay *udpRelay;
    HttpProxy *httpProxy;

    QHostAddress getLocalAddr();

protected slots:
    void onTcpServerError(QAbstractSocket::SocketError err);
    void onBytesRead(const qint64 &);
    void onBytesSend(const qint64 &);
    void onServerAddressLookedUp(const bool success, const QString err);
};

}
#endif // CONTROLLER_H
