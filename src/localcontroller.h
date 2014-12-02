#ifndef LOCALCONTROLLER_H
#define LOCALCONTROLLER_H

#include "basecontroller.h"

using namespace QSS;

namespace QSS {

class LocalController : public BaseController
{
    Q_OBJECT
public:
    explicit LocalController(const Profile &p, QObject *parent = 0);

public slots:
    void start();
};

}

#endif // LOCALCONTROLLER_H
