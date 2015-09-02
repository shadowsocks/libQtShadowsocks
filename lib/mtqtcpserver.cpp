/*
 * mtqtcpserver.cpp - Multi-threaded QTcpServer
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

#include "mtqtcpserver.h"

using namespace QSS;

MTQTcpServer::MTQTcpServer(const bool &is_local, const Address &serverAddress, QObject *parent) :
    QTcpServer(parent),
    isLocal(is_local),
    serverAddress(serverAddress)
{}

MTQTcpServer::~MTQTcpServer()
{
    clear();
}

void MTQTcpServer::setup(const int &time_out, const EncryptorPrivate *_ep)
{
    timeout = time_out;
    ep = _ep;
}

void MTQTcpServer::clear()
{
    for (auto &c : childrenThreads) {
        if (c->isRunning()) {
            c->quit();
        }
        c->deleteLater();
    }
    childrenThreads.clear();
}

void MTQTcpServer::incomingConnection(qintptr socketDescriptor)
{
    MTSocketThread *thread = new MTSocketThread(socketDescriptor, timeout, serverAddress, ep, isLocal, this);
    childrenThreads.push_back(thread);
    connect (thread, &MTSocketThread::finished, thread, &MTSocketThread::deleteLater);
    connect (thread, &MTSocketThread::error, this, &MTQTcpServer::acceptError);
    connect (thread, &MTSocketThread::info, this, &MTQTcpServer::info);
    connect (thread, &MTSocketThread::debug, this, &MTQTcpServer::debug);
    connect (thread, &MTSocketThread::bytesRead, this, &MTQTcpServer::bytesRead);
    connect (thread, &MTSocketThread::bytesSend, this, &MTQTcpServer::bytesSend);
    thread->start();
}
