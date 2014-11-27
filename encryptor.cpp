#include <QDebug>
#include "encryptor.h"

Encryptor::Encryptor(QObject *parent) :
    QObject(parent)
{
}

void Encryptor::setup(const QString &m, const QString &pwd)
{
    method = m;
    password = pwd;
    tableInit();
}

void Encryptor::tableInit()
{
    quint32 i;
    quint64 key = 0;

    encTable.fill(0, 256);
    decTable.fill(0, 256);
    QByteArray digest = getPasswordHash();

    for (i = 0; i < 8; ++i)
    {
        key += (quint64(digest.at(i)) << (8 * i));
    }

    for(i = 0; i < 256; ++i)
    {
        encTable[i] = static_cast<quint8>(i);
    }
    for(i = 1; i < 1024; ++i)
    {
        encTable = mergeSort(encTable, i, key);
    }
    for(i = 0; i < 256; ++i)
    {
        decTable[encTable[i]] = static_cast<quint8>(i);
    }
    qDebug() << "table initialised.";
}

QVector<quint8> Encryptor::mergeSort(const QVector<quint8> &array, quint32 salt, quint64 key)
{
    int length = array.size();

    if (length <= 1) {
        return array;
    }

    int middle = length / 2;
    QVector<quint8> left = array.mid(0, middle);
    QVector<quint8> right = array.mid(middle);

    left = mergeSort(left, salt, key);
    right = mergeSort(right, salt, key);

    int leftptr = 0;
    int rightptr = 0;

    QVector<quint8> sorted;
    sorted.fill(0, length);
    for (int i = 0; i < length; ++i) {
        if (rightptr == right.size() || (leftptr < left.size() && randomCompare(left[leftptr], right[rightptr], salt, key) <= 0)) {
            sorted[i] = left[leftptr];
            leftptr++;
        }
        else if (leftptr == left.size() || (rightptr < right.size() && randomCompare(right[rightptr], left[leftptr], salt, key) <= 0)) {
            sorted[i] = right[rightptr];
            rightptr++;
        }
    }
    return sorted;
}

int Encryptor::randomCompare(const quint8 &x, const quint8 &y, const quint32 &i, const quint64 &a)
{
    return a % (x + i) - a % (y + i);
}

QByteArray Encryptor::encrypt(const QByteArray &in)
{
    //TODO: add other ciphers
    QByteArray out(in.size(), '0');
    for (int i = 0; i < in.size(); i++) {
        out[i] = encTable.at(in[i]);
    }
    return out;
}

QByteArray Encryptor::decrypt(const QByteArray &in)
{
    //TODO: add other ciphers
    QByteArray out(in.size(), '0');
    for (int i = 0; i < in.size(); i++) {
        out[i] = decTable.at(in[i]);
    }
    return out;
}

QByteArray Encryptor::getPasswordHash()
{
    QByteArray pwdByteArray = password.toLocal8Bit();
    return QCryptographicHash::hash(pwdByteArray, QCryptographicHash::Md5);
}
