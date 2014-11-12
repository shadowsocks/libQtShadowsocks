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

    for (i = 0; i < 8; i++)
    {
        key += (quint64(digest.at(i)) << (8 * i));
    }

    for(i = 0; i < 256; ++i)
    {
        encTable[i] = char(i);
    }
    for(i = 1; i < 1024; ++i)
    {
        encTable = mergeSort(encTable, key, i);
    }
    for(i = 0; i < 256; ++i)
    {
        decTable[int(encTable.at(i))] = char(i);
    }
}

QByteArray Encryptor::mergeSort(QByteArray &array, quint64 a, quint32 j)
{
    int length = array.size();
    int middle = length / 2;
    if (length == 1) {
        return array;
    }

    QByteArray left = array.left(middle);
    QByteArray right = array.right(length - middle);
    left = mergeSort(left, a, j);
    right = mergeSort(right, a, j);

    int leftptr = 0;
    int rightptr = 0;

    QByteArray sorted = array;
    for (int i = 0; i < array.size(); i++) {
        if (rightptr == right.size() || (leftptr < left.size() && randomCompare(left.at(leftptr), right.at(rightptr), a, j) <= 0)) {
            sorted[i] = left.at(leftptr);
        }
        else if (leftptr == left.size() || (rightptr < right.size() && randomCompare(right.at(rightptr), left.at(leftptr), a, j) <= 0)) {
            sorted[i] = right.at(rightptr);
        }
    }
    return sorted;
}

int Encryptor::randomCompare(char _x, char _y, quint64 a, quint32 i)
{
    quint8 x = quint8(_x);
    quint8 y = quint8(_y);
    return (a % (x + i) - a % (y + i));
}

QByteArray Encryptor::encrypt(const QByteArray &in)
{
    //TODO: add other ciphers
    QByteArray out(in.size(), '0');
    for (int i = 0; i < in.size(); i++) {
        out[i] = encTable.at(in.at(i));
    }
    return out;
}

QByteArray Encryptor::decrypt(const QByteArray &in)
{
    //TODO: add other ciphers
    QByteArray out(in.size(), '0');
    for (int i = 0; i < in.size(); i++) {
        out[i] = decTable.at(in.at(i));
    }
    return out;
}

QByteArray Encryptor::getPasswordHash()
{
    QByteArray pwdByteArray = password.toLocal8Bit();
    return QCryptographicHash::hash(pwdByteArray, QCryptographicHash::Md5);
}
