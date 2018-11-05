/*
 * tcprelayclient.h - the header file of TcpRelayClient class
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

#ifndef TCPRELAYCLIENT_H
#define TCPRELAYCLIENT_H

#include "tcprelay.h"

namespace QSS {

class QSS_EXPORT TcpRelayClient : public TcpRelay
{
    Q_OBJECT
public:
    TcpRelayClient(QTcpSocket *localSocket,
                   int timeout,
                   Address server_addr,
                   const Encryptor::Creator &ec);

protected:
    void handleStageAddr(std::string &data) final;
    void handleLocalTcpData(std::string &data) final;
    void handleRemoteTcpData(std::string &data) final;
};

}
#endif // TCPRELAYCLIENT_H
