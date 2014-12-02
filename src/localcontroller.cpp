#include "localcontroller.h"

LocalController::LocalController(const Profile &p, QObject *parent) :
    BaseController (p, parent)
{}

void LocalController::start()
{
    emit info("initialising ciphers...");
    Encryptor::initialise(profile.method, profile.password);
    QString istr = profile.method + QString(" initialised.");
    emit info(istr);

    tcpServer->listen(profile.shareOverLAN ? QHostAddress::Any : QHostAddress::LocalHost, profile.local_port);
    QString sstr = QString("tcp server listen at port ") + QString::number(profile.local_port);
    emit info(sstr);

    running = true;
}
