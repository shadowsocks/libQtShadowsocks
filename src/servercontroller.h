#ifndef SERVERCONTROLLER_H
#define SERVERCONTROLLER_H

#include "basecontroller.h"

using namespace QSS;

namespace QSS {

class ServerController : public BaseController
{
    Q_OBJECT
public:
    explicit ServerController(const Profile &p, QObject *parent = NULL);

public slots:
    void start();

protected slots:
    void onNewConnection();
};

}

#endif // SERVERCONTROLLER_H
