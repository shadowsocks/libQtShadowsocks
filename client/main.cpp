/*
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

#include <QCoreApplication>
#include <QCommandLineParser>
#include <signal.h>
#include "client.h"

using namespace QSS;

static void onSIGINT_TERM(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) qApp->quit();
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    a.setApplicationName("Shadowsocks-libQtShadowsocks");
    a.setApplicationVersion("0.9");

    signal(SIGINT, onSIGINT_TERM);
    signal(SIGTERM, onSIGINT_TERM);

    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption configFile(QStringList() << "c" << "config-file", "specify config.json file.", "config.json", "config.json");
    QCommandLineOption serverMode(QStringList() << "s" << "server-mode", "run as shadowsocks server.");
    parser.addOption(configFile);
    parser.addOption(serverMode);
    parser.process(a);

    Client c;
    c.readConfig(parser.value(configFile));
    c.start(parser.isSet(serverMode));

    return a.exec();
}
