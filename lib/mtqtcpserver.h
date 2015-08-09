/*
 * mtqtcpserver.h - Multi-threaded QTcpServer
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

#ifndef MTQTCPSERVER_H
#define MTQTCPSERVER_H

#include <QTcpServer>
#include <QList>
#include "address.h"
#include "encryptorprivate.h"
#include "mtsocketthread.h"

namespace QSS {

class MTQTcpServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit MTQTcpServer(const bool &is_local, const Address &serverAddress, QObject *parent = nullptr);

    void setup(const int &time_out, const EncryptorPrivate *_ep);
    void clear();

signals:
    void debug(const QString &);
    void log(const QString &);
    void bytesRead(const qint64 &);
    void bytesSend(const qint64 &);

protected:
    void incomingConnection(qintptr handler) Q_DECL_OVERRIDE;

private:
    QList<MTSocketThread*> childrenThreads;
    const bool &isLocal;
    const Address &serverAddress;
    int timeout;
    const EncryptorPrivate *ep;
};

}

#endif // MTQTCPSERVER_H
