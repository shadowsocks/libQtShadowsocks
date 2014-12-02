#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>
#include "client.h"

Client::Client(QObject *parent) :
    QObject(parent)
{
    lc = NULL;
}

void Client::setShareOverLAN(bool s)
{
    profile.shareOverLAN = s;
}

void Client::readConfig(const QString &file)
{
    QFile c(file);
    c.open(QIODevice::ReadOnly | QIODevice::Text);
    if (!c.isOpen()) {
        qDebug() << "config file" << file << "is not open!";
        exit(1);
    }
    if (!c.isReadable()) {
        qDebug() << "config file" << file << "is not readable!";
        exit(1);
    }
    QByteArray confArray = c.readAll();
    c.close();

    QJsonDocument confJson = QJsonDocument::fromJson(confArray);
    QJsonObject confObj = confJson.object();
    profile.local_port = confObj["local_port"].toInt();
    profile.method = confObj["method"].toString();
    profile.password = confObj["password"].toString();
    profile.server = confObj["server"].toString();
    profile.server_port = confObj["server_port"].toInt();
}

void Client::start()
{
    if (lc != NULL) {
        lc->deleteLater();
    }
    lc = new QSS::LocalController(profile, this);
    connect (lc, &QSS::LocalController::info, this, &Client::logHandler);
    connect (lc, &QSS::LocalController::error, this, &Client::logHandler);
    lc->start();
}

void Client::logHandler(const QString &log)
{
    qDebug() << log;
}
