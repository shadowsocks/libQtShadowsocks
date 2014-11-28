#ifndef LOCALCONTROLLER_H
#define LOCALCONTROLLER_H

#include "basecontroller.h"

using namespace QSS;

namespace QSS {

class QTSHADOWSOCKS_EXPORT LocalController : public BaseController
{
    Q_OBJECT
public:
    LocalController(QObject *parent = 0) : BaseController (parent) {}

public slots:
    void start(const Profile &p);

protected slots:
    void onNewConnection();
};

}

#endif // LOCALCONTROLLER_H
