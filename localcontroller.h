#ifndef LOCALCONTROLLER_H
#define LOCALCONTROLLER_H

#include "basecontroller.h"

class QTSHADOWSOCKS_EXPORT LocalController : public BaseController
{
    Q_OBJECT
public:
    LocalController(QObject *parent = 0) : BaseController (parent) {}

public slots:
    void start(const SProfile &p);

protected slots:
    void onNewConnection();
};

#endif // LOCALCONTROLLER_H
