#include <QCoreApplication>
#include <QCommandLineParser>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include <localcontroller.h>

using namespace QSS;

void readConfig(const QString &file, Profile *profile)
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
    profile->local_port = confObj["local_port"].toInt();
    profile->method = confObj["method"].toString();
    profile->password = confObj["password"].toString();
    profile->server = confObj["server"].toString();
    profile->server_port = confObj["server_port"].toInt();
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    a.setApplicationName("Shadowsocks-libqtshadowsocks");
    a.setApplicationVersion("0.1");
    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption configFile(QStringList() << "c" << "config-file", "specify config.json file", "config.json", "config.json");
    QCommandLineOption shareOverLan("s", "Share over LAN");
    parser.addOption(configFile);
    parser.addOption(shareOverLan);
    parser.process(a);

    Profile profile;
    readConfig(parser.value(configFile), &profile);
    profile.shareOverLAN = parser.isSet(shareOverLan);
    LocalController lc;

    lc.start(profile);

    return a.exec();
}
