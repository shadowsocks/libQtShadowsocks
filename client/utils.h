#ifndef UTILS_H
#define UTILS_H

#include <QtGlobal>

class Utils
{
public:
    static int testSpeed(const QString &method, int data_size_mb = 100);//test 100MB data encrypt/decrypt speed by default. return time used (ms)
};

#endif // UTILS_H
