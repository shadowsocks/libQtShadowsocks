#ifndef UTILS_H
#define UTILS_H

#include <QtGlobal>
#include <QStringList>

class Utils
{
public:
    static void testSpeed(const QString &method, quint32 data_size_mb);//test data encrypt/decrypt speed. print result to terminal
    static void testSpeed(quint32 data_size_mb);//test all methods

private:
    static const QStringList allMethods;
};

#endif // UTILS_H
