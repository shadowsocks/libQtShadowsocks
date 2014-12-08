/*
 * client.cpp - source file of Client class
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

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include "client.h"

Client::Client(QObject *parent) :
    QObject(parent)
{
    lc = NULL;
}

void Client::readConfig(const QString &file)
{
    QFile c(file);
    c.open(QIODevice::ReadOnly | QIODevice::Text);
    if (!c.isOpen()) {
        qDebug() << "config file" << file << "is not open!";
        exit(1);
    }
    if (!c.isReadable()) {
        qDebug() << "config file" << file << "is not readable!";
        exit(1);
    }
    QByteArray confArray = c.readAll();
    c.close();

    QJsonDocument confJson = QJsonDocument::fromJson(confArray);
    QJsonObject confObj = confJson.object();
    profile.local_address = confObj["local_address"].toString();
    profile.local_port = confObj["local_port"].toInt();
    profile.method = confObj["method"].toString();
    profile.password = confObj["password"].toString();
    profile.server = confObj["server"].toString();
    profile.server_port = confObj["server_port"].toInt();
}

void Client::start()
{
    if (lc != NULL) {
        lc->deleteLater();
    }
    lc = new QSS::Controller(profile, true, this);
    connect (lc, &QSS::Controller::info, this, &Client::logHandler);
    connect (lc, &QSS::Controller::error, this, &Client::logHandler);
    lc->start();
}

void Client::logHandler(const QString &log)
{
    qDebug() << log;
}
