#include <QtShadowsocks>
#include <QDateTime>
#include <QTime>
#include <iostream>
#include "utils.h"

Utils::LogLevel Utils::logLevel = Utils::LogLevel::INFO;

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

void Utils::messageHandler(QtMsgType type, const QMessageLogContext &, const QString &msg)
{
    const std::string timestamp =
            QDateTime::currentDateTime().toString("yyyy-MM-ddTHH:mm:ss.zzz").toStdString();
    const std::string message = msg.toStdString();
    switch(type) {
    case QtDebugMsg:
        if (Utils::logLevel <= LogLevel::DEBUG) {
            std::cout << timestamp << " DEBUG: " << message << std::endl;
        }
        break;
    case QtInfoMsg:
        if (Utils::logLevel <= LogLevel::INFO) {
            std::cout << timestamp << " INFO: " << message << std::endl;
        }
        break;
    case QtWarningMsg:
        if (Utils::logLevel <= LogLevel::WARN) {
            std::cerr << timestamp << " WARN: " << message << std::endl;
        }
        break;
    case QtCriticalMsg:
        if (Utils::logLevel <= LogLevel::ERROR) {
            std::cerr << timestamp << " ERROR: " << message << std::endl;
        }
        break;
    case QtFatalMsg:
        // FATAL is not allowed to skip
        std::cerr << timestamp << " FATAL: " << message << std::endl;
        abort();
    }
}
