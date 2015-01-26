/*
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

#include <QCoreApplication>
#include <QCommandLineParser>
#include <QDebug>
#include <signal.h>
#include "client.h"
#include "utils.h"

using namespace QSS;

static void onSIGINT_TERM(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) qApp->quit();
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    a.setApplicationName("Shadowsocks-libQtShadowsocks");
    a.setApplicationVersion("1.4.0");

    signal(SIGINT, onSIGINT_TERM);
    signal(SIGTERM, onSIGINT_TERM);

    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption configFile(QStringList() << "c" << "config-file", "specify config.json file.", "config.json", "config.json");
    QCommandLineOption serverMode(QStringList() << "s" << "server-mode", "run as shadowsocks server.");
    QCommandLineOption testSpeed("t", "test encrypt/decrypt speed.");
    parser.addOption(configFile);
    parser.addOption(serverMode);
    parser.addOption(testSpeed);
    parser.process(a);

    Client c;
    if (c.readConfig(parser.value(configFile))) {
        if (parser.isSet(testSpeed)) {
            qDebug() << "Encrypt Method      :" << c.getMethod();
            qDebug() << "Datagram size       : 100 MB";
            qDebug() << "Time used to encrypt:" << Utils::testSpeed(c.getMethod(), 100) << "ms";
            return 0;
        }
        else if (c.start(parser.isSet(serverMode))) {
            return a.exec();
        }
        else {
            return 2;
        }
    }
    else {
        return 1;
    }
}
