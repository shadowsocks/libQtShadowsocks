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

#include "types/address.h"
#include "addresstester.h"
#include "common.h"
#include "crypto/encryptor.h"

namespace QSS {

AddressTester::AddressTester(const QHostAddress &_address,
                             const uint16_t &_port,
                             QObject *parent) :
    QObject(parent),
    m_address(_address),
    m_port(_port),
    m_testingConnectivity(false)
{
    m_timer.setSingleShot(true);
    m_time = QTime::currentTime();
    m_socket.setSocketOption(QAbstractSocket::LowDelayOption, 1);

    connect(&m_timer, &QTimer::timeout, this, &AddressTester::onTimeout);
    connect(&m_socket, &QTcpSocket::connected, this, &AddressTester::onConnected);
    connect(&m_socket, &QTcpSocket::readyRead,
            this, &AddressTester::onSocketReadyRead);
    connect(&m_socket,
            static_cast<void (QTcpSocket::*)(QAbstractSocket::SocketError)>
            (&QTcpSocket::error),
            this,
            &AddressTester::onSocketError);
}

void AddressTester::connectToServer(int timeout)
{
    m_time = QTime::currentTime();
    m_timer.start(timeout);
    m_socket.connectToHost(m_address, m_port);
}

void AddressTester::startLagTest(int timeout)
{
    m_testingConnectivity = false;
    connectToServer(timeout);
}

void AddressTester::startConnectivityTest(const std::string &method,
                                          const std::string &password,
                                          int timeout)
{
    m_testingConnectivity = true;
    m_encryptionMethod = method;
    m_encryptionPassword = password;
    connectToServer(timeout);
}

void AddressTester::onTimeout()
{
    m_socket.abort();
    emit connectivityTestFinished(false);
    emit lagTestFinished(LAG_TIMEOUT);
}

void AddressTester::onSocketError(QAbstractSocket::SocketError)
{
    m_timer.stop();
    m_socket.abort();
    emit connectivityTestFinished(false);
    emit testErrorString(m_socket.errorString());
    emit lagTestFinished(LAG_ERROR);
}

void AddressTester::onConnected()
{
    m_timer.stop();
    emit lagTestFinished(m_time.msecsTo(QTime::currentTime()));
    if (m_testingConnectivity) {
        Encryptor encryptor(m_encryptionMethod, m_encryptionPassword);
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
        m_socket.write(toWrite.data(), toWrite.size());
    } else {
        m_socket.abort();
    }
}

void AddressTester::onSocketReadyRead()
{
    emit connectivityTestFinished(true);
    m_socket.abort();
}

} // namespace QSS
