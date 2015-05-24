/*
 * controller.h - the header file of Controller class
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

#ifndef BASECONTROLLER_H
#define BASECONTROLLER_H

#include <QByteArray>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QObjectCleanupHandler>
#include <QTcpServer>
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
    explicit Controller(bool is_local = true, QObject *parent = 0);
    explicit Controller(const Profile & _profile, bool is_local = true, QObject *parent = 0);//overloaded function to construct a Controller with given profile
    ~Controller();

    /*
     * You have to call setup before calling start() unless you use the overloaded
     * convenient construction function. This function can also be used to change
     * Profile without the need to create a new Controller.
     * Set http_proxy to true then the local will serve as HTTP proxy server.
     * Because the HttpProxy is a second-level proxy, the actual process is to
     * use a random available port as SOCKS5 and then set HttpProxy listen on
     * the local port and forward traffics via SOCKS5 proxy.
     * The value http_proxy is ignored in server mode.
     */
    bool setup(const Profile &, bool http_proxy = false);

    const EncryptorPrivate* getEncryptorPrivate() const;
    Address getServerAddress() const;
    QString getServerString() const;//return the server config from profile
    quint16 getLocalPort() const;
    QHostAddress getLocalAddr();
    int getTimeout() const;//return timeout interval (millisecond)

signals:
    /*
     * Log level.
     * i.e. info signal will be emitted if there is an "error", but info won't transfer "debug" output.
     */
    void error(const QString &);
    void info(const QString &);
    void debug(const QString &);

    //connect this signal to get notified when running state is changed
    void runningStateChanged(bool);

    //these two signals pass any new bytes read or sent
    void newBytesReceived(const quint64 &);
    void newBytesSent(const quint64 &);

    //these two signals pass accumulated bytes read or sent so far (aka total in this session)
    void bytesReceivedChanged(const qint64 &);
    void bytesSentChanged(const qint64 &);

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
    bool useHttp;
    const bool isLocal;//run on local-side (client) or server-side (server)
    EncryptorPrivate *ep;
    QTcpServer *tcpServer;
    UdpRelay *udpRelay;
    QObjectCleanupHandler *connectionCollector;
    HttpProxy *httpProxy;

protected slots:
    void onTcpServerError(QAbstractSocket::SocketError err);
    void onNewTCPConnection();
    void onBytesRead(const qint64 &);
    void onBytesSend(const qint64 &);
    void onServerAddressLookedUp(const bool success, const QString err);
};

}
#endif // BASECONTROLLER_H
