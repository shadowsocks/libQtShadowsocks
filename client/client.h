#ifndef CLIENT_H
#define CLIENT_H

#include <QObject>
#include <localcontroller.h>

class Client : public QObject
{
    Q_OBJECT
public:
    explicit Client(QObject *parent = 0);

    void setShareOverLAN(bool);
    void readConfig(const QString &);

public slots:
    void start();

private:
    QSS::LocalController *lc;
    QSS::Profile profile;

private slots:
    void logHandler(const QString &);

};

#endif // CLIENT_H
