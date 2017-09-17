/*
 * client.cpp - source file of Client class
 *
 * Copyright (C) 2014-2017 Symeon Huang <hzwhuang@gmail.com>
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
#include <iostream>
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
        std::cout << "can't open config file " << file.toStdString() << std::endl;
        return false;
    }
    if (!c.isReadable()) {
        std::cout << "config file " << file.toStdString() << " is not readable!" << std::endl;
        return false;
    }
    QByteArray confArray = c.readAll();
    c.close();

    QJsonDocument confJson = QJsonDocument::fromJson(confArray);
    QJsonObject confObj = confJson.object();
    profile.setLocalAddress(confObj["local_address"].toString().toStdString());
    profile.setLocalPort(confObj["local_port"].toInt());
    profile.setMethod(confObj["method"].toString().toStdString());
    profile.setPassword(confObj["password"].toString().toStdString());
    profile.setServerAddress(confObj["server"].toString().toStdString());
    profile.setServerPort(confObj["server_port"].toInt());
    profile.setTimeout(confObj["timeout"].toInt());
    profile.setHttpProxy(confObj["http_proxy"].toBool());
    if (confObj["auth"].toBool()) {
        std::cerr << "OTA is deprecated, please disable OTA in the config." << std::endl;
        return false;
    }

    return true;
}

void Client::setup(const QString &remote_addr,
                   const QString &remote_port,
                   const QString &local_addr,
                   const QString &local_port,
                   const QString &password,
                   const QString &method,
                   const QString &timeout,
                   const bool http_proxy,
                   const bool debug)
{
    profile.setServerAddress(remote_addr.toStdString());
    profile.setServerPort(remote_port.toInt());
    profile.setLocalAddress(local_addr.toStdString());
    profile.setLocalPort(local_port.toInt());
    profile.setPassword(password.toStdString());
    profile.setMethod(method.toStdString());
    profile.setTimeout(timeout.toInt());
    profile.setHttpProxy(http_proxy);
    if (debug) {
        profile.enableDebug();
    }
}

void Client::setAutoBan(bool ban)
{
    autoBan = ban;
}

void Client::setDebug(bool debug)
{
    if (debug) {
        profile.enableDebug();
    } else {
        profile.disableDebug();
    }
}

void Client::setHttpMode(bool http)
{
    profile.setHttpProxy(http);
}

bool Client::start(bool _server)
{
    if (profile.debug()) {
        if (!headerTest()) {
            std::cout << "Header test failed" << std::endl;
            return false;
        }
    }

    if (lc) {
        lc->deleteLater();
    }
    lc = new QSS::Controller(profile, !_server, autoBan, this);

    if (!_server) {
        QSS::Address server(profile.serverAddress(), profile.serverPort());
        server.blockingLookUp();
        QSS::AddressTester *tester =
                new QSS::AddressTester(server.getFirstIP(),
                                       server.getPort(),
                                       this);
        connect(tester, &QSS::AddressTester::connectivityTestFinished,
                this, &Client::onConnectivityResultArrived);
        connect(tester, &QSS::AddressTester::testErrorString,
                [] (const QString& error) {
            std::cout << "Connectivity testing error: " << error.toStdString() << std::endl;
        });
        tester->startConnectivityTest(profile.method(),
                                      profile.password());
    }

    return lc->start();
}

bool Client::headerTest()
{
    int length;
    QHostAddress test_addr("1.2.3.4");
    QHostAddress test_addr_v6("2001:0db8:85a3:0000:0000:8a2e:1010:2020");
    uint16_t test_port = 56;
    QSS::Address test_res, test_v6(test_addr_v6, test_port);
    std::string packed = QSS::Common::packAddress(test_v6);
    QSS::Common::parseHeader(packed, test_res, length);
    bool success = (test_v6 == test_res);
    if (!success) {
        std::cout << test_v6.toString() << " --> "
                  << test_res.toString() << std::endl;
    }
    packed = QSS::Common::packAddress(test_addr, test_port);
    QSS::Common::parseHeader(packed, test_res, length);
    bool success2 = ((test_res.getFirstIP() == test_addr)
                 && (test_res.getPort() == test_port));
    if (!success2) {
        std::cout << test_addr.toString().toStdString()
                  << ":" << test_port << " --> "
                  << test_res.toString() << std::endl;
    }
    return success & success2;
}

std::string Client::getMethod() const
{
    return profile.method();
}

void Client::onConnectivityResultArrived(bool c)
{
    if (c) {
        std::cout << "The shadowsocks connection is okay." << std::endl;
    } else {
        std::cout << "Destination is not reachable. "
                     "Please check your network and firewall settings. "
                     "And make sure the profile is correct."
                  << std::endl;
    }
}
