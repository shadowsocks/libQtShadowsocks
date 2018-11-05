/*
 * tcpserver.h - Shadowsocks TCP Server
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

#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <QTcpServer>
#include <list>
#include <memory>
#include "crypto/encryptor.h"
#include "types/address.h"
#include "util/export.h"

namespace QSS {

class TcpRelay;

class QSS_EXPORT TcpServer : public QTcpServer
{
    Q_OBJECT
public:
    TcpServer(Encryptor::Creator&& ec,
              int m_timeout,
              bool is_local,
              bool auto_ban,
              Address m_serverAddress);
    ~TcpServer() override;

    TcpServer(const TcpServer &) = delete;

signals:
    void bytesRead(quint64);
    void bytesSend(quint64);
    void latencyAvailable(int);

protected:
    void incomingConnection(qintptr socketDescriptor) Q_DECL_OVERRIDE;

private:
    Encryptor::Creator m_encryptorCreator;
    const bool m_isLocal;
    const bool m_autoBan;
    const Address m_serverAddress;
    const int m_timeout;

    std::list<std::shared_ptr<TcpRelay> > m_conList;
};

}

#endif // TCPSERVER_H
