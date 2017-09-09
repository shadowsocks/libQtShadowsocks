#include <QtShadowsocks>
#include <QTime>
#include <iostream>
#include "utils.h"

void Utils::testSpeed(const std::string &method, quint32 data_size_mb)
{
    const std::string test(1024 * 32, '#');//32KB
    quint32 loops = 32 * data_size_mb;
    QSS::Encryptor enc(method, "barfoo!");

    QTime startTime = QTime::currentTime();

    //encrypt per 1MB to reduce memory usage during the test
    for (quint32 i = 0; i < loops; ++i) {
        enc.encrypt(test);
    }

    static QTextStream qOut(stdout, QIODevice::WriteOnly);

    std::cout << "Encrypt Method      : " << method
              << "\nDatagram size       : " << data_size_mb << "MB\n"
              << "Time used to encrypt: "
              << startTime.msecsTo(QTime::currentTime()) << "ms\n" << std::endl;
}

void Utils::testSpeed(quint32 data_size_mb)
{
    std::vector<std::string> allMethods = QSS::Cipher::supportedMethods();
    for (const auto& method : allMethods) {
        testSpeed(method, data_size_mb);
    }
}
