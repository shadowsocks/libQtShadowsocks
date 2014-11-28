#ifndef PROFILE_H
#define PROFILE_H

#include <QString>

namespace QSS {

struct Profile {
    QString server;
    QString method;
    quint16 server_port;
    quint16 local_port;
    bool shareOverLAN;
    QString password;
};

}
#endif // PROFILE_H
