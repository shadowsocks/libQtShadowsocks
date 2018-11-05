/*
 * tcprelayserver.h - the header file of TcpRelayServer class
 *
 * Copyright (C) 2018 Symeon Huang <hzwhuang@gmail.com>
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

#ifndef TCPRELAYSERVER_H
#define TCPRELAYSERVER_H

#include "tcprelay.h"

namespace QSS {

class QSS_EXPORT TcpRelayServer : public TcpRelay
{
    Q_OBJECT
public:
    TcpRelayServer(QTcpSocket *localSocket,
                   int timeout,
                   Address server_addr,
                   const Encryptor::Creator& ec,
                   bool autoBan);

protected:
    const bool autoBan;

    void handleStageAddr(std::string &data) final;
    void handleLocalTcpData(std::string &data) final;
    void handleRemoteTcpData(std::string &data) final;
};

}
#endif // TCPRELAYSERVER_H
