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
#include "client.h"

using namespace QSS;

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    a.setApplicationName("Shadowsocks-libQtShadowsocks");
    a.setApplicationVersion("0.2");
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption configFile(QStringList() << "c" << "config-file", "specify config.json file", "config.json", "config.json");
    parser.addOption(configFile);
    parser.process(a);

    Client c;
    c.readConfig(parser.value(configFile));
    c.start();

    return a.exec();
}
