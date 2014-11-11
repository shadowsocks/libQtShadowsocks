#ifndef SPROFILE_H
#define SPROFILE_H

#include <QString>

struct SProfile {
    QString server;
    QString method;
    quint16 server_port;
    quint16 local_port;
    bool shareOverLAN;
    QString password;
};
#endif // SPROFILE_H
