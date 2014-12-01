#include <QCoreApplication>
#include <QCommandLineParser>
#include "client.h"

#ifdef QCA_STATIC
#include <QtPlugin>
Q_IMPORT_PLUGIN(qca_ossl)
#endif

using namespace QSS;

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

    Client c;
    c.readConfig(parser.value(configFile));
    c.setShareOverLAN(parser.isSet(shareOverLan));
    c.start();

    return a.exec();
}
