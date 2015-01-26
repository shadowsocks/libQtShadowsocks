#include <QTime>
#include <QtShadowsocks>
#include "utils.h"

int Utils::testSpeed(const QString &method, int data_size_mb)
{
    QByteArray test(1024 * 1024, '#');//1MB
    QSS::Encryptor enc;
    enc.initialise(method, "barfoo!");

    QTime startTime = QTime::currentTime();

    for (int i = 0; i < data_size_mb; ++i) {//encrypt per 1MB to reduce memory usage during the test
        enc.encrypt(test);
    }

    return startTime.msecsTo(QTime::currentTime());
}
