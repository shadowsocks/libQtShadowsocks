#include "localcontroller.h"

LocalController::LocalController(QObject *parent) :
    BaseController (parent)
{}

void LocalController::start(const Profile &p)
{
    profile = p;
    emit info("initialising ciphers...");
    Encryptor::initialise(profile.method, profile.password);
    QString istr = profile.method + QString(" initialised.");
    emit info(istr);

    tcpServer->listen(profile.shareOverLAN ? QHostAddress::Any : QHostAddress::LocalHost, profile.local_port);
    QString sstr = QString("tcp server listen at port ") + QString::number(profile.local_port);
    emit info(sstr);

    running = true;
}
