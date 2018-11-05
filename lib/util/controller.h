/*
 * controller.h - the header file of Controller class
 *
 * Copyright (C) 2014-2018 Symeon Huang <hzwhuang@gmail.com>
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

#include <QHostAddress>
#include <QObject>
#include "network/tcpserver.h"
#include "export.h"
#include "network/httpproxy.h"
#include "types/profile.h"
#include "network/udprelay.h"

#ifndef USE_BOTAN2
namespace Botan {
class LibraryInitializer;
}
#endif

namespace QSS {

class QSS_EXPORT Controller : public QObject
{
    Q_OBJECT
public:
    Controller(Profile _profile,
               bool is_local,
               bool auto_ban,
               QObject *parent = nullptr);
    ~Controller() override;

    Controller(const Controller&) = delete;

signals:
    // Connect this signal to get notified when running state is changed
    void runningStateChanged(bool);

    // These two signals pass any new bytes read or sent
    void newBytesReceived(quint64);
    void newBytesSent(quint64);

    /*
     * These two signals pass accumulated bytes read or sent so far
     * (aka total in this session)
     */
    void bytesReceivedChanged(quint64);
    void bytesSentChanged(quint64);

    /*
     * Time used to connect to remote host (msec)
     * remote host means shadowsocks server if this controller is in local mode,
     * or the address the client is accessing if it's in server mode.
     */
    void tcpLatencyAvailable(int);

public slots:
    bool start(); // Return true if start successfully, otherwise return false
    void stop();

private:
#ifndef USE_BOTAN2
    // This needs to be destructed in the end
    std::unique_ptr<Botan::LibraryInitializer> botanInit;
#endif

protected:
    // The total bytes recevied or sent by/from all TCP and UDP connections.
    uint64_t m_bytesReceived;
    uint64_t m_bytesSent;

    Profile m_profile;
    Address m_serverAddress;
    const bool m_isLocal; // Run on local-side (client) or server-side (server)
    /*
     * auto ban IPs that use malformed header data as our anti-probe measure
     * (only used when it's a server)
     */
    const bool m_autoBan;
    std::unique_ptr<TcpServer> m_tcpServer;
    std::unique_ptr<UdpRelay> m_udpRelay;
    std::unique_ptr<HttpProxy> m_httpProxy;

    QHostAddress getLocalAddr();

protected slots:
    void onTcpServerError(QAbstractSocket::SocketError err);
    void onBytesRead(quint64);
    void onBytesSend(quint64);
};

}
#endif // CONTROLLER_H
