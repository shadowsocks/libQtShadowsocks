#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <QObject>
#include <QVector>
#include <QCryptographicHash>
#include "qtshadowsocks_global.h"

class QTSHADOWSOCKS_EXPORT Encryptor : public QObject
{
    Q_OBJECT
public:
    explicit Encryptor(QObject *parent = 0);

    void setup(const QString &m, const QString &pwd);

    static int randomCompare(const quint8 &, const quint8 &, const quint32 &salt, const quint64 &key);
    QByteArray decrypt(const QByteArray &);
    QByteArray encrypt(const QByteArray &);

private:
    QString method;
    QString password;
    QVector<quint8> encTable;
    QVector<quint8> decTable;
    void tableInit();
    QVector<quint8> mergeSort(const QVector<quint8> &, quint32, quint64);
    QByteArray getPasswordHash();
};

#endif // ENCRYPTOR_H
