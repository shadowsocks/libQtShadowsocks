/*
 * basecontroller.h - the header file of BaseController class
 *
 * BaseController is an abstract class that should not be initialised
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
#include <QTcpSocket>
#include "profile.h"
#include "connection.h"
#include "udprelay.h"
#include "encryptor.h"

using namespace QSS;

namespace QSS {

class BaseController : public QObject
{
    Q_OBJECT
public:
    explicit BaseController(const Profile &p, QObject *parent = 0);
    virtual ~BaseController();

    virtual quint16 getServerPort();
    virtual QString getServerAddr();

    virtual quint16 getLocalPort();
    virtual QHostAddress getLocalAddr();

signals:
    void error(const QString &);
    void info(const QString &);

public slots:
    virtual void start() = 0;
    virtual void stop();

protected://children can access protected members
    bool running;
    QTcpServer *tcpServer;
    UdpRelay *udpRelay;
    Profile profile;
    QList<Connection *> conList;
    QCA::Initializer qi;

protected slots:
    virtual void onTcpServerError();
    virtual void onNewConnection();
    virtual void onConnectionDisconnected();
};

}
#endif // BASECONTROLLER_H
