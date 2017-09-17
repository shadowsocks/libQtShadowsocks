/*
 * addresstester.cpp - the source file of AddressTester class
 *
 * Simple way to test the connection's latency.
 * Since it's a just socket connection without any data transfer,
 * the remote doesn't need to be a shadowsocks server.
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

#include "addresstester.h"
#include "address.h"
#include "encryptor.h"
#include "common.h"

using namespace QSS;

AddressTester::AddressTester(const QHostAddress &_address,
                             const uint16_t &_port,
                             QObject *parent) :
    QObject(parent),
    address(_address),
    port(_port),
    testingConnectivity(false)
{
    timer.setSingleShot(true);
    time = QTime::currentTime();
    socket.setSocketOption(QAbstractSocket::LowDelayOption, 1);

    connect(&timer, &QTimer::timeout, this, &AddressTester::onTimeout);
    connect(&socket, &QTcpSocket::connected, this, &AddressTester::onConnected);
    connect(&socket, &QTcpSocket::readyRead,
            this, &AddressTester::onSocketReadyRead);
    connect(&socket,
            static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>
            (&QTcpSocket::error),
            this,
            &AddressTester::onSocketError);
}

void AddressTester::connectToServer(int timeout)
{
    time = QTime::currentTime();
    timer.start(timeout);
    socket.connectToHost(address, port);
}

void AddressTester::startLagTest(int timeout)
{
    testingConnectivity = false;
    connectToServer(timeout);
}

void AddressTester::startConnectivityTest(const std::string &method,
                                          const std::string &password,
                                          int timeout)
{
    testingConnectivity = true;
    encryptionMethod = method;
    encryptionPassword = password;
    connectToServer(timeout);
}

void AddressTester::onTimeout()
{
    socket.abort();
    emit connectivityTestFinished(false);
    emit lagTestFinished(LAG_TIMEOUT);
}

void AddressTester::onSocketError(QAbstractSocket::SocketError)
{
    timer.stop();
    socket.abort();
    emit connectivityTestFinished(false);
    emit testErrorString(socket.errorString());
    emit lagTestFinished(LAG_ERROR);
}

void AddressTester::onConnected()
{
    timer.stop();
    emit lagTestFinished(time.msecsTo(QTime::currentTime()));
    if (testingConnectivity) {
        Encryptor encryptor(encryptionMethod, encryptionPassword);
        /*
         * A http request to Google to test connectivity
         * The payload is dumped from
         * `curl http://www.google.com --socks5 127.0.0.1:1080`
         *
         * TODO: find a better way to check connectivity
         */
        std::string dest =
                Common::packAddress(Address("www.google.com", 80));
        static const QByteArray expected = QByteArray::fromHex(
                        "474554202f20485454502f312e310d0a486f73743a"
                        "207777772e676f6f676c652e636f6d0d0a55736572"
                        "2d4167656e743a206375726c2f372e34332e300d0a"
                        "4163636570743a202a2f2a0d0a0d0a");
        std::string payload(expected.data(), expected.length());
        std::string toWrite = encryptor.encrypt(dest + payload);
        socket.write(toWrite.data(), toWrite.size());
    } else {
        socket.abort();
    }
}

void AddressTester::onSocketReadyRead()
{
    emit connectivityTestFinished(true);
    socket.abort();
}
