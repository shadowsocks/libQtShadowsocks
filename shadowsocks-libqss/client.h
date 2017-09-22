/*
 * client.h - header file of Client class
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

#ifndef CLIENT_H
#define CLIENT_H

#include <QtShadowsocks>

class Client
{
public:
    Client();
    bool readConfig(const QString &);

    void setup(const QString &remote_addr,
               const QString &remote_port,
               const QString &local_addr,
               const QString &local_port,
               const QString &password,
               const QString &method,
               const QString &timeout,
               const bool http_proxy,
               const bool debug);

    void setAutoBan(bool ban);
    void setDebug(bool debug);
    void setHttpMode(bool http);
    const std::string& getMethod() const;
    bool start(bool serverMode = false);

private:
    std::unique_ptr<QSS::Controller> controller;
    std::unique_ptr<QSS::AddressTester> tester;
    QSS::Profile profile;
    bool autoBan;
    bool headerTest();
};

#endif // CLIENT_H
