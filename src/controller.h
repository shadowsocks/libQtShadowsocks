/*
 * controller.h - the header file of Controller class
 *
 * Feel free to subclass this class if needed.
 *
 * Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
 *
 * This file is part of the libQtShadowsocks.
 *
 * libQtShadowsocks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libQtShadowsocks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#ifndef BASECONTROLLER_H
#define BASECONTROLLER_H

#include <QByteArray>
#include <QHostAddress>
#include <QList>
#include <QObject>
#include <QTcpServer>
#include <botan/init.h>
#include "profile.h"
#include "udprelay.h"

using namespace QSS;

namespace QSS {

class Controller : public QObject
{
    Q_OBJECT
public:
    explicit Controller(const Profile &p, bool is_local = true, QObject *parent = 0);
    virtual ~Controller();

    virtual quint16 getServerPort();
    virtual QHostAddress getServerAddr();
    virtual quint16 getLocalPort();
    virtual QHostAddress getLocalAddr();
    virtual int getTimeout();//return timeout interval (millisecond)
    virtual bool isRunning() const;

signals:
    void error(const QString &);
    void info(const QString &);

public slots:
    virtual bool start();//return true if start successfully, otherwise return false
    virtual void stop();

protected://children can access protected members
    bool hasError;
    bool running;
    const bool isLocal;//run on local-side (client) or server-side (server)
    QTcpServer *tcpServer;
    UdpRelay *udpRelay;
    Profile profile;
    QList<QHostAddress> serverAddrList;
    Botan::LibraryInitializer init;

protected slots:
    virtual void onTcpServerError();
    virtual void onNewTCPConnection();
};

}
#endif // BASECONTROLLER_H
