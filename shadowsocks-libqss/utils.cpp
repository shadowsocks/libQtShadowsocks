#include <QtShadowsocks>
#include <QDateTime>
#include <QTime>
#include <iostream>
#include "utils.h"

bool Utils::debugEnabled = false;

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

void Utils::messageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    const std::string timestamp =
            QDateTime::currentDateTime().toString("yyyy-MM-ddTHH:mm:ss.zzz").toStdString();
    const std::string message = msg.toStdString();
    switch(type) {
    case QtDebugMsg:
        if (Utils::debugEnabled) {
            std::cout << timestamp << " DEBUG: " << message << std::endl;
        }
        break;
    case QtInfoMsg:
        std::cout << timestamp << " INFO: " << message << std::endl;
        break;
    case QtWarningMsg:
        std::cerr << timestamp << " WARN: " << message
                  << "(" << context.function << ")"
                  << std::endl;
        break;
    case QtCriticalMsg:
        std::cerr << timestamp << " ERROR: " << message
                  << "(" << context.file << ":" << context.line
                  << ", " << context.function << ")"
                  << std::endl;
        break;
    case QtFatalMsg:
        std::cerr << timestamp << " FATAL: " << message
                  << "(" << context.file << ":" << context.line
                  << ", " << context.function << ")"
                  << std::endl;
        abort();
    }
}
