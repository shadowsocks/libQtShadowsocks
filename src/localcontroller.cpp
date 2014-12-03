/*
 * localcontroller.cpp - the source file of LocalController class
 *
 * Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
 *
 * This file is part of the libQtShadowsocks.
 *
 * libQtShadowsocks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libQtShadowsocks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "localcontroller.h"

LocalController::LocalController(const Profile &p, QObject *parent) :
    BaseController (p, parent)
{}

void LocalController::start()
{
    emit info("initialising ciphers...");
    Encryptor::initialise(profile.method, profile.password);
    QString istr = profile.method + QString(" initialised.");
    emit info(istr);

    tcpServer->listen(profile.shareOverLAN ? QHostAddress::Any : QHostAddress::LocalHost, profile.local_port);
    QString sstr = QString("tcp server listen at port ") + QString::number(profile.local_port);
    emit info(sstr);

    running = true;
}
