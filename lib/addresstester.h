/*
 * addresstester.h - the header file of AddressTester class
 *
 * perform non-blocking address tests
 *
 * Copyright (C) 2015 Symeon Huang <hzwhuang@gmail.com>
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

#ifndef ADDRESSTESTER_H
#define ADDRESSTESTER_H

#include "export.h"
#include <QHostAddress>
#include <QTcpSocket>
#include <QTime>
#include <QTimer>

namespace QSS {

class QSS_EXPORT AddressTester : public QObject
{
    Q_OBJECT
public:
    AddressTester(const QHostAddress &_address, const quint16 &_port, QObject *parent = 0);
    ~AddressTester();

signals:
    /*
     * pass the lag, -1 if there is an error or timeout
     * the error can be obtained via testErrorString signal
     */
    void lagTestFinished(int);
    void testErrorString(const QString &);

public slots:
    void startLagTest(int timeout = 3000);//3000 msec by default

private:
    QHostAddress address;
    quint16 port;
    QTcpSocket *socket;
    QTimer *timer;
    QTime time;

private slots:
    void onTimeout();
    void onSocketError();
    void onConnected();
};

}
#endif // ADDRESSTESTER_H
