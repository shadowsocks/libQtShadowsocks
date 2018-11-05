/*
 * addresstester.h - the header file of AddressTester class
 *
 * perform non-blocking address tests
 *
 * Copyright (C) 2015-2018 Symeon Huang <hzwhuang@gmail.com>
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

// This class is only meaningful for client-side applications
class QSS_EXPORT AddressTester : public QObject
{
    Q_OBJECT
public:
    AddressTester(const QHostAddress &server_address,
                  const uint16_t &server_port,
                  QObject *parent = 0);

    AddressTester(const AddressTester &) = delete;

    static const int LAG_TIMEOUT = -1;
    static const int LAG_ERROR = -2;

    /*
     * Connectivity test will try to establish a shadowsocks connection with
     * the server. The result is passed by signal connectivityTestFinished().
     * If the server times out, the connectivity will be passed as false.
     *
     * Calling this function does lag (latency) test as well. Therefore, it's
     * the recommended way to do connectivity and latency test with just one
     * function call.
     *
     * Don't call the same AddressTester instance's startConnectivityTest()
     * and startLagTest() at the same time!
     */
    void startConnectivityTest(const std::string &method,
                               const std::string &password,
                               int timeout = 3000);

signals:
    void lagTestFinished(int);
    void testErrorString(const QString &);
    void connectivityTestFinished(bool);

public slots:
    /*
     * The lag test only tests if the server port is open and listeninig
     * bind lagTestFinished() signal to get the test result
     */
    void startLagTest(int timeout = 3000);//3000 msec by default

private:
    QHostAddress m_address;
    uint16_t m_port;
    QTime m_time;
    QTcpSocket m_socket;
    QTimer m_timer;
    bool m_testingConnectivity;

    std::string m_encryptionMethod;
    std::string m_encryptionPassword;

    void connectToServer(int timeout);

private slots:
    void onTimeout();
    void onSocketError(QAbstractSocket::SocketError);
    void onConnected();
    void onSocketReadyRead();
};

}
#endif // ADDRESSTESTER_H
