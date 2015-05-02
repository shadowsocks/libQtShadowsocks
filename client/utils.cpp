#include <QtShadowsocks>
#include <QTime>
#include <QDebug>
#include "utils.h"

void Utils::testSpeed(const QString &method, quint32 data_size_mb)
{
    QByteArray test(1024 * 32, '#');//32KB
    quint32 loops = 32 * data_size_mb;
    QSS::EncryptorPrivate ep(method, "barfoo!");
    QSS::Encryptor enc(&ep);

    QTime startTime = QTime::currentTime();

    for (quint32 i = 0; i < loops; ++i) {//encrypt per 1MB to reduce memory usage during the test
        enc.encrypt(test);
    }

    qDebug() << "Encrypt Method      :" << method;
    qDebug() << "Datagram size       :" << data_size_mb << "MB";
    qDebug() << "Time used to encrypt:" << startTime.msecsTo(QTime::currentTime()) << "ms" << endl;
}

void Utils::testSpeed(quint32 data_size_mb)
{
    foreach(const QString method, allMethods) {
        testSpeed(method, data_size_mb);
    }
}

const QStringList Utils::allMethods = QStringList() << "TABLE" << "AES-128-CFB" << "AES-192-CFB" << "AES-256-CFB" << "BF-CFB" << "Camellia-128-CFB" << "Camellia-192-CFB" << "Camellia-256-CFB" << "CAST5-CFB" << "ChaCha20" << "DES-CFB" << "IDEA-CFB" << "RC2-CFB" << "RC4" << "RC4-MD5" << "Salsa20" << "SEED-CFB";
