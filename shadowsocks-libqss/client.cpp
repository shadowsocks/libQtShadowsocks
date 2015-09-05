/*
 * client.cpp - source file of Client class
 *
 * Copyright (C) 2014-2015 Symeon Huang <hzwhuang@gmail.com>
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

#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include "client.h"

Client::Client(QObject *parent) :
    QObject(parent),
    lc(nullptr),
    autoBan(false)
{}

bool Client::readConfig(const QString &file)
{
    QFile c(file);
    if (!c.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QSS::Common::qOut << "can't open config file " << file << endl;
        return false;
    }
    if (!c.isReadable()) {
        QSS::Common::qOut << "config file " << file << " is not readable!" << endl;
        return false;
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
    profile.timeout = confObj["timeout"].toInt();
    profile.http_proxy = confObj["http_proxy"].toBool();

    return true;
}

void Client::setup(const QString &remote_addr, const QString &remote_port, const QString &local_addr, const QString &local_port, const QString &password, const QString &method, const QString &timeout, const bool http_proxy, const bool debug)
{
    profile.server = remote_addr;
    profile.server_port = remote_port.toInt();
    profile.local_address = local_addr;
    profile.local_port = local_port.toInt();
    profile.password = password;
    profile.method = method;
    profile.timeout = timeout.toInt();
    profile.http_proxy = http_proxy;
    profile.debug = debug;
}

void Client::setAutoBan(bool ban)
{
    autoBan = ban;
}

void Client::setDebug(bool debug)
{
    profile.debug = debug;
}

bool Client::start(bool _server)
{
    if (lc) {
        lc->deleteLater();
    }
    lc = new QSS::Controller(!_server, autoBan, this);
    connect (lc, &QSS::Controller::info, this, &Client::logHandler);
    if (profile.debug) {
        connect(lc, &QSS::Controller::debug, this, &Client::logHandler);
    }
    lc->setup(profile);
    return lc->start() && cipherTest();
}

bool Client::cipherTest()
{
    QSS::EncryptorPrivate ep(profile.method, profile.password);
    QSS::Encryptor e(ep);
    if(e.selfTest()) {
        return true;
    } else {
        QSS::Common::qOut << "Cipher test failed" << endl;
        return false;
    }
}

void Client::logHandler(const QString &log)
{
    QSS::Common::qOut << log << endl;
}

QString Client::getMethod() const
{
    return profile.method;
}
