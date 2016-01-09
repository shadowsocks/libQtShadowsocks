/*
 * addresstester.cpp - the source file of AddressTester class
 *
 * Simple way to test the connection's latency.
 * Since it's a just socket connection without any data transfer,
 * the remote doesn't need to be a shadowsocks server.
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

#include "addresstester.h"

using namespace QSS;

AddressTester::AddressTester(const QHostAddress &_address,
                             const quint16 &_port,
                             QObject *parent) :
    QObject(parent),
    address(_address),
    port(_port)
{
    timer.setSingleShot(true);
    time = QTime::currentTime();

    connect(&timer, &QTimer::timeout, this, &AddressTester::onTimeout);
    connect(&socket,
            static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>
            (&QTcpSocket::error),
            this,
            &AddressTester::onSocketError);
    connect(&socket, &QTcpSocket::connected, this, &AddressTester::onConnected);
}

void AddressTester::startLagTest(int timeout)
{
    time = QTime::currentTime();
    timer.start(timeout);
    socket.connectToHost(address, port);
}

void AddressTester::onTimeout()
{
    socket.disconnectFromHost();
    emit lagTestFinished(LAG_TIMEOUT);
}

void AddressTester::onSocketError()
{
    timer.stop();
    emit testErrorString(socket.errorString());
    emit lagTestFinished(LAG_ERROR);
}

void AddressTester::onConnected()
{
    timer.stop();
    emit lagTestFinished(time.msecsTo(QTime::currentTime()));
}
