/*
 * socketstream.cpp - the source file of SocketStream class
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

#include "socketstream.h"

using namespace QSS;

SocketStream::SocketStream(QAbstractSocket *a, QAbstractSocket *b,  QObject *parent) :
    QObject(parent),
    as(a),
    bs(b)
{
    connect (as, &QAbstractSocket::readyRead, this, &SocketStream::onSocketAReadyRead);
    connect (bs, &QAbstractSocket::readyRead, this, &SocketStream::onSocketBReadyRead);
}

void SocketStream::onSocketAReadyRead()
{
    if (bs->isWritable()) {
        bs->write(as->readAll());
    } else {
        emit error("The second socket is not writable");
    }
}

void SocketStream::onSocketBReadyRead()
{
    if (as->isWritable()) {
        as->write(bs->readAll());
    } else {
        emit error("The first socket is not writable");
    }
}
