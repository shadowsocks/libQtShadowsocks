/*
 * encryptorprivate.cpp - the source file of EncryptorPrivate class
 *
 * Copyright (C) 2014-2015 Symeon Huang <hzwhuang@gmail.com>
 *
 * This file is part of the libQtShadowsocks.
 *
 * libQtShadowsocks is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * libQtShadowsocks is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with libQtShadowsocks; see the file LICENSE. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include "encryptorprivate.h"
#include "cipher.h"

using namespace QSS;

EncryptorPrivate::EncryptorPrivate(const QString &m, const QString &pwd, QObject *parent) :
    QObject (parent)
{
    method = m.toUpper().toLocal8Bit();//local8bit or utf-8?
    password = pwd.toLocal8Bit();
    valid = true;

    if (method == "TABLE") {
        type = TABLE;
        tableInit();
    } else {
        type = CIPHER;
        if (method.contains("BF")) {
            method = "Blowfish/CFB";
        } else if (method.contains("CAST5")) {
            method = "CAST-128/CFB";
        } else if (method.contains("SALSA20")) {
            method = "Salsa20";
        } else if (method.contains("CHACHA20")) {
            method = "ChaCha";
        } else if (method.contains("SERPENT-CFB")) {
            method = "Serpent/CFB";
        } else {
            if (method.contains("CAMELLIA")) {
                    method.replace("CAMELLIA", "Camellia");
            }
            method.replace("-C", "/C");//i.e. -CFB to /CFB
        }

        Cipher::kiLenArray ki = Cipher::keyIvMap.value(method);
        if (ki[0] == 0 || !Cipher::isSupported(method)) {
            qCritical("The method %s is not supported.", m.toStdString().data());
            valid = false;
        }
        keyLen = ki[0];
        ivLen = ki[1];
        evpBytesToKey();
    }
}

bool EncryptorPrivate::isValid() const
{
    return valid;
}

QString EncryptorPrivate::getInternalMethodName() const
{
    return QString(method);
}

void EncryptorPrivate::tableInit()
{
    quint32 i;
    quint64 k = 0;
    encTable.resize(256);
    decTable.resize(256);

    QByteArray digest = Cipher::md5Hash(password);

    for (i = 0; i < 8; ++i) {
        k += (static_cast<quint64>(digest[i]) << (8 * i));
    }
    for (i = 0; i < 256; ++i) {
        encTable[i] = static_cast<quint8>(i);
    }
    for (i = 1; i < 1024; ++i) {
        encTable = mergeSort(encTable, i, k);
    }
    for (i = 0; i < 256; ++i) {
        decTable[encTable[i]] = static_cast<quint8>(i);
    }
}

QVector<quint8> EncryptorPrivate::mergeSort(const QVector<quint8> &array, quint32 salt, quint64 k)
{
    int length = array.size();

    if (length <= 1) {
        return array;
    }

    int middle = length / 2;
    QVector<quint8> left = array.mid(0, middle);
    QVector<quint8> right = array.mid(middle);

    left = mergeSort(left, salt, k);
    right = mergeSort(right, salt, k);

    int leftptr = 0;
    int rightptr = 0;

    QVector<quint8> sorted;
    sorted.fill(0, length);
    for (int i = 0; i < length; ++i) {
        if (rightptr == right.size() || (leftptr < left.size() && randomCompare(left[leftptr], right[rightptr], salt, k) <= 0)) {
            sorted[i] = left[leftptr++];
        } else if (leftptr == left.size() || (rightptr < right.size() && randomCompare(right[rightptr], left[leftptr], salt, k) <= 0)) {
            sorted[i] = right[rightptr++];
        }
    }
    return sorted;
}

int EncryptorPrivate::randomCompare(const quint8 &x, const quint8 &y, const quint32 &i, const quint64 &a)
{
    return a % (x + i) - a % (y + i);
}

void EncryptorPrivate::evpBytesToKey()
{
    QVector<QByteArray> m;
    QByteArray data;
    int i = 0;

    while (m.size() < keyLen + ivLen) {
        if (i == 0) {
            data = password;
        } else {
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
