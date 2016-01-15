#include <QtShadowsocks>
#include <QTime>
#include <QTextStream>
#include "utils.h"

void Utils::testSpeed(const QString &method, quint32 data_size_mb)
{
    static const QByteArray test(1024 * 32, '#');//32KB
    quint32 loops = 32 * data_size_mb;
    QSS::EncryptorPrivate ep(method, "barfoo!");
    QSS::Encryptor enc(ep);

    QTime startTime = QTime::currentTime();

    //encrypt per 1MB to reduce memory usage during the test
    for (quint32 i = 0; i < loops; ++i) {
        enc.encrypt(test);
    }

    static QTextStream qOut(stdout, QIODevice::WriteOnly);

    qOut << "Encrypt Method      : "
         << method << endl;
    qOut << "Datagram size       : "
         << data_size_mb << "MB" << endl;
    qOut << "Time used to encrypt: "
         << startTime.msecsTo(QTime::currentTime()) << "ms\n" << endl;
}

void Utils::testSpeed(quint32 data_size_mb)
{
    QList<QByteArray> allMethods = QSS::Cipher::getSupportedMethodList();
    foreach(const QByteArray &method, allMethods) {
        testSpeed(QString(method), data_size_mb);
    }
}
