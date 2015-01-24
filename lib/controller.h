/*
 * controller.h - the header file of Controller class
 *
 * Feel free to subclass this class if needed.
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
#include <botan/init.h>
#include "export.h"
#include "profile.h"
#include "udprelay.h"

namespace QSS {

class QSS_EXPORT Controller : public QObject
{
    Q_OBJECT
public:
    Controller(bool is_local = true, QObject *parent = 0);
    Controller(const Profile & _profile, bool is_local = true, QObject *parent = 0);//overloaded function to construct a Controller with given profile
    virtual ~Controller();

    /*
     * You have to call setup before calling start()
     * You can also change the Profile by call setup again with new Profile
     */
    virtual bool setup(const Profile &);

    virtual quint16 getServerPort();
    virtual QHostAddress getServerAddr();
    virtual quint16 getLocalPort();
    virtual QHostAddress getLocalAddr();
    virtual int getTimeout();//return timeout interval (millisecond)
    virtual bool isRunning() const;

signals:
    /*
     * Log level.
     * i.e. info signal will be emitted if there is an "error", but info won't transfer "debug" output.
     */
    void error(const QString &);
    void info(const QString &);
    void debug(const QString &);

    void bytesReceivedChanged(const qint64 &);
    void bytesSentChanged(const qint64 &);

public slots:
    virtual bool start();//return true if start successfully, otherwise return false
    virtual void stop();

protected://children can access protected members
    bool valid;
    bool running;
    const bool isLocal;//run on local-side (client) or server-side (server)
    QTcpServer *tcpServer;
    UdpRelay *udpRelay;
    QObjectCleanupHandler *connectionCollector;
    Profile profile;
    QList<QHostAddress> serverAddrList;
    Botan::LibraryInitializer init;

    //the total bytes recevied or sent by/from all TCP and UDP connections.
    qint64 bytesReceived;
    qint64 bytesSent;

protected slots:
    virtual void onTcpServerError();
    virtual void onNewTCPConnection();
    virtual void onBytesRead(const qint64 &);
    virtual void onBytesSend(const qint64 &);
};

}
#endif // BASECONTROLLER_H
