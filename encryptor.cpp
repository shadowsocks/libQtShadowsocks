#include <QDebug>
#include <QtConcurrent>
#include "encryptor.h"

Encryptor::Encryptor(QObject *parent) :
    QObject(parent)
{
}

const QVector<quint8> Encryptor::octVec = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255};

void Encryptor::setup(const QString &m, const QString &pwd)
{
    method = m;
    password = pwd;
    tableInit();

    if (selfTest()) {
        qDebug() << "encryptor self test passed.";
    }
    else {
        qCritical() << "encryptor self test failed.";
    }
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

    QtConcurrent::blockingMap(octVec, [&] (const quint8 &j) {
        encTable[j] = j;
    });
    for(i = 1; i < 1024; ++i)
    {
        encTable = mergeSort(encTable, i, key);
    }
    QtConcurrent::blockingMap(octVec, [&] (const quint8 &j) {
        decTable[encTable[j]] = j;
    });

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

bool Encryptor::selfTest()
{
    QByteArray test("barfoo!");
    QByteArray res = decrypt(encrypt(test));
    return test == res;
}
