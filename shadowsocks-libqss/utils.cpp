#include <QtShadowsocks>
#include <QTime>
#include <iostream>
#include "utils.h"

void Utils::testSpeed(const std::string &method, uint32_t data_size_mb)
{
    const std::string test(1024 * 32, '#');//32KB
    uint32_t loops = 32 * data_size_mb;
    QSS::Encryptor enc(method, "barfoo!");

    QTime startTime = QTime::currentTime();

    //encrypt per 1MB to reduce memory usage during the test
    for (uint32_t i = 0; i < loops; ++i) {
        enc.encrypt(test);
    }

    std::cout << "Encrypt Method      : " << method
              << "\nDatagram size       : " << data_size_mb << "MB\n"
              << "Time used to encrypt: "
              << startTime.msecsTo(QTime::currentTime()) << "ms\n" << std::endl;
}

void Utils::testSpeed(uint32_t data_size_mb)
{
    std::vector<std::string> allMethods = QSS::Cipher::supportedMethods();
    std::sort(allMethods.begin(), allMethods.end());
    for (const auto& method : allMethods) {
        testSpeed(method, data_size_mb);
    }
}
