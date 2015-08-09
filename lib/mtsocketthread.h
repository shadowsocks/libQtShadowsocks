/*
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

#ifndef MTSOCKETTHREAD_H
#define MTSOCKETTHREAD_H

#include <QThread>
#include <QTcpSocket>
#include "encryptorprivate.h"
#include "address.h"

namespace QSS {

class MTSocketThread : public QThread
{
    Q_OBJECT
public:
    explicit MTSocketThread(int socketDescriptor, const int &timeout, const Address &server, const EncryptorPrivate* ep, const bool &isLocal, QObject *parent = nullptr);

    void run() Q_DECL_OVERRIDE;

signals:
    void finished();
    void error(QTcpSocket::SocketError socketError);
    void debug(const QString &);
    void info(const QString &);
    void bytesRead(const qint64 &);
    void bytesSend(const qint64 &);

private:
    int socketDescriptor;
    const bool &isLocal;
    const int &timeout;
    const EncryptorPrivate* ep;
    const Address &serverAddress;
};

}

#endif // MTSOCKETTHREAD_H
