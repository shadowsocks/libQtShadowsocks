/*
 * encryptor.h - the source file of Encryptor class
 *
 * Copyright (C) 2014, Symeon Huang <hzwhuang@gmail.com>
 *
 * This file is part of the libQtShadowsocks.
 *
 * libQtShadowsocks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libQtShadowsocks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with pdnsd; see the file COPYING. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <QtConcurrent>
#include "encryptor.h"

using namespace QSS;

Encryptor::Encryptor(QObject *parent) :
    QObject(parent)
{
    enCipher = NULL;
    deCipher = NULL;
}

const QVector<quint8> Encryptor::octVec = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255};

//define static member variables
Encryptor::TYPE Encryptor::type;
QByteArray Encryptor::method;
QByteArray Encryptor::password;
QVector<quint8> Encryptor::encTable;
QVector<quint8> Encryptor::decTable;
int Encryptor::keyLen = 0;
int Encryptor::ivLen = 0;
QByteArray Encryptor::key;

void Encryptor::reset()
{
    if (enCipher != NULL) {
        enCipher->deleteLater();
        enCipher = NULL;
    }
    if (deCipher != NULL) {
        deCipher->deleteLater();
        deCipher = NULL;
    }
}

bool Encryptor::initialise(const QString &m, const QString &pwd)
{
    method = m.toUpper().toLocal8Bit();//local8bit or utf-8?
    password = pwd.toLocal8Bit();

    if (m.compare("TABLE") == 0) {
        type = TABLE;
        tableInit();
        return true;
    }

    type = CIPHER;
    if (method.contains("BF")) {
        method = "Blowfish/CFB";
    }
    else if (method.contains("CAST5")) {
        method = "CAST-128/CFB";
    }
    else if (method.contains("SALSA20")) {
        method = "Salsa20";
    }
    else if (method.contains("CHACHA20")) {
        method = "ChaCha";
    }
    else {
        method.replace("-C", "/C");//i.e. -CFB to /CFB
    }

    QVector<int> ki = Cipher::keyIvMap.value(method);
    if (ki.isEmpty() || !Cipher::isSupported(method)) {
        qCritical() << "Abort. The method" << m.toLocal8Bit() << "is not supported.";
        return false;
    }
    keyLen = ki[0];
    ivLen = ki[1];
    evpBytesToKey();
    return true;
}

QString Encryptor::getInternalMethodName()
{
    return QString(method);
}

void Encryptor::tableInit()
{
    quint32 i;
    quint64 key = 0;

    encTable.fill(0, 256);
    decTable.fill(0, 256);
    QByteArray digest = Cipher::md5Hash(password);

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

void Encryptor::evpBytesToKey()
{
    QVector<QByteArray> m;
    QByteArray data;
    int i = 0;

    while (m.size() < keyLen + ivLen) {
        if (i == 0) {
            data = password;
        }
        else {
            data = m[i - 1] + password;
        }
        m.append(Cipher::md5Hash(data));
        i++;
    }
    QByteArray ms;
    for (QVector<QByteArray>::ConstIterator it = m.begin(); it != m.end(); ++it) {
        ms.append(*it);
    }

    key = ms.mid(0, keyLen);
}

QByteArray Encryptor::encrypt(const QByteArray &in)
{
    QByteArray out;
    QByteArray iv = Cipher::randomIv(ivLen);

    switch (type) {
    case TABLE:
        out.resize(in.size());
        for (int i = 0; i < in.size(); ++i) {
            out[i] = encTable.at(in[i]);
        }
        break;
    case CIPHER:
        if (enCipher == NULL) {
            enCipher = new Cipher(method, key, iv, true, this);
            out = iv + enCipher->update(in);
        }
        else {
            out = enCipher->update(in);
        }
        break;
    default:
        qWarning() << "Unknown encryption type";
    }

    return out;
}

QByteArray Encryptor::decrypt(const QByteArray &in)
{
    QByteArray out;

    switch (type) {
    case TABLE:
        out.resize(in.size());
        for (int i = 0; i < in.size(); ++i) {
            out[i] = decTable.at(in[i]);
        }
        break;
    case CIPHER:
        if (deCipher == NULL) {
            deCipher = new Cipher(method, key, in.mid(0, ivLen), false, this);
            out = deCipher->update(in.mid(ivLen));
        }
        else {
            out = deCipher->update(in);
        }
        break;
    default:
        qWarning() << "Unknown decryption type";
    }

    return out;
}

QByteArray Encryptor::encryptAll(const QByteArray &in)
{
    QByteArray out;
    QByteArray iv = Cipher::randomIv(ivLen);

    switch (type) {
    case TABLE:
        out = QByteArray(in.size(), '0');
        for (int i = 0; i < in.size(); ++i) {
            out[i] = encTable.at(in[i]);
        }
        break;
    case CIPHER:
        if (enCipher != NULL) {
            enCipher->deleteLater();
        }
        enCipher = new Cipher(method, key, iv, true, this);
        out = iv + enCipher->update(in);
        break;
    default:
        qWarning() << "Unknown encryption type";
    }

    return out;
}

QByteArray Encryptor::decryptAll(const QByteArray &in)
{
    QByteArray out;

    switch (type) {
    case TABLE:
        out = QByteArray(in.size(), '0');
        for (int i = 0; i < in.size(); ++i) {
            out[i] = decTable.at(in[i]);
        }
        break;
    case CIPHER:
        if (deCipher != NULL) {
            deCipher->deleteLater();
        }
        deCipher = new Cipher(method, key, in.mid(0, ivLen), false, this);
        out = deCipher->update(in.mid(ivLen));
        break;
    default:
        qWarning() << "Unknown decryption type";
    }

    return out;
}

bool Encryptor::selfTest()
{
    QByteArray test("barfoo!"), test2("Hello World!"), test3("libShadowsocks!");
    QByteArray res  = decrypt(encrypt(test)),
               res2 = decrypt(encrypt(test2)),
               res3 = decrypt(encrypt(test3));
    reset();
    return test == res && test2 == res2 && test3 == res3;
}
