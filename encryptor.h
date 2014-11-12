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

    static int randomCompare(quint8, quint8, quint64, quint32);
    QByteArray decrypt(const QByteArray &);
    QByteArray encrypt(const QByteArray &);

private:
    QString method;
    QString password;
    QVector<quint8> encTable;
    QVector<quint8> decTable;
    void tableInit();
    QVector<quint8> mergeSort(QVector<quint8> &, quint64, quint32);
    QByteArray getPasswordHash();
};

#endif // ENCRYPTOR_H
