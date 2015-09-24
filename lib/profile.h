/*
 * profile.h - defines Profile struct
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

#ifndef PROFILE_H
#define PROFILE_H

#include <QString>

namespace QSS {

struct Profile {
    QString server;
    QString local_address;
    QString method;
    QString password;
    quint16 server_port;
    quint16 local_port;
    int timeout;

    /*
     * Set http_proxy to true then the local will serve as HTTP proxy server.
     * Because the HttpProxy is a second-level proxy, the actual process is to
     * use a random available port as SOCKS5 and then set HttpProxy listen on
     * the local port and forward traffics via SOCKS5 proxy.
     * It's false by default.
     */
    bool http_proxy;
    bool debug;//turn on debug output or not

    Profile() : local_address("127.0.0.1"), server_port(8388), local_port(1080),
                timeout(600), http_proxy(false), debug(false) {}
};

}
#endif // PROFILE_H
