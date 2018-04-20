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
#include <signal.h>
#include <iostream>
#include "client.h"
#include "utils.h"

using namespace QSS;

static void onSIGINT_TERM(int sig)
{
    if (sig == SIGINT || sig == SIGTERM) qApp->quit();
}

Utils::LogLevel stringToLogLevel(const QString& str)
{
    if (str.compare("DEBUG", Qt::CaseInsensitive) == 0) {
        return Utils::LogLevel::DEBUG;
    } else if (str.compare("INFO", Qt::CaseInsensitive) == 0) {
        return Utils::LogLevel::INFO;
    } else if (str.compare("WARN", Qt::CaseInsensitive) == 0) {
        return Utils::LogLevel::WARN;
    } else if (str.compare("ERROR", Qt::CaseInsensitive) == 0) {
        return Utils::LogLevel::ERROR;
    } else if (str.compare("FATAL", Qt::CaseInsensitive) == 0) {
        return Utils::LogLevel::FATAL;
    }
    std::cerr << "Log level " << str.toStdString()
              << " is not recognised, default to INFO" << std::endl;
    return Utils::LogLevel::INFO;
}

int main(int argc, char *argv[])
{
    qInstallMessageHandler(Utils::messageHandler);

    QCoreApplication a(argc, argv);
    a.setApplicationName("Shadowsocks-libQtShadowsocks");
    a.setApplicationVersion(Common::version());

    signal(SIGINT, onSIGINT_TERM);
    signal(SIGTERM, onSIGINT_TERM);

    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption configFile("c",
                                  "specify config.json file.",
                                  "config_file",
                                  "config.json");
    QCommandLineOption serverAddress("s",
                              "host name or IP address of your remote server.",
                              "server_address");
    QCommandLineOption serverPort("p", "port number of your remote server.",
                                  "server_port");
    QCommandLineOption localAddress("b",
                              "local address to bind. ignored in server mode.",
                              "local_address",
                              "127.0.0.1");
    QCommandLineOption localPort("l",
                  "port number of your local server. ignored in server mode.",
                  "local_port");
    QCommandLineOption password("k",
                                "password of your remote server.",
                                "password");
    QCommandLineOption encryptionMethod("m",
                                        "encryption method.",
                                        "method");
    QCommandLineOption timeout("t",
                               "socket timeout in seconds.",
                               "timeout");
    QCommandLineOption http(
                QStringList() << "H" << "http-proxy",
                "run in HTTP(S) proxy mode. ignored in server mode.");
    QCommandLineOption serverMode(
                QStringList() << "S" << "server-mode",
                "run as shadowsocks server.");
    QCommandLineOption testSpeed(
                QStringList() << "T" << "speed-test",
                "test encrypt/decrypt speed.");
    QCommandLineOption log("L",
                           "logging level. Valid levels are: debug, info, "
                           "warn, error, fatal.",
                           "log_level",
                           "info");
    QCommandLineOption autoBan("autoban",
                "automatically ban IPs that send malformed header. "
                "ignored in local mode.");
    parser.addOption(configFile);
    parser.addOption(serverAddress);
    parser.addOption(serverPort);
    parser.addOption(localAddress);
    parser.addOption(localPort);
    parser.addOption(password);
    parser.addOption(encryptionMethod);
    parser.addOption(timeout);
    parser.addOption(http);
    parser.addOption(serverMode);
    parser.addOption(testSpeed);
    parser.addOption(log);
    parser.addOption(autoBan);
    parser.process(a);

    Utils::logLevel = stringToLogLevel(parser.value(log));
    Client c;
    if (!c.readConfig(parser.value(configFile))) {
        c.setup(parser.value(serverAddress),
                parser.value(serverPort),
                parser.value(localAddress),
                parser.value(localPort),
                parser.value(password),
                parser.value(encryptionMethod),
                parser.value(timeout),
                parser.isSet(http));
    }
    c.setAutoBan(parser.isSet(autoBan));

    //command-line option has a higher priority to make H, S, T consistent
    if (parser.isSet(http)) {
        c.setHttpMode(true);
    }

    if (parser.isSet(testSpeed)) {
        if (c.getMethod().empty()) {
            std::cout << "Testing all encryption methods..." << std::endl;
            Utils::testSpeed(100);
        } else {
            Utils::testSpeed(c.getMethod(), 100);
        }
        return 0;
    } else if (c.start(parser.isSet(serverMode))) {
        return a.exec();
    } else {
        return 2;
    }
}
