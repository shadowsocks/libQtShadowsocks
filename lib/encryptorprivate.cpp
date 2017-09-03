/*
 * encryptorprivate.cpp - the source file of EncryptorPrivate class
 *
 * Copyright (C) 2014-2017 Symeon Huang <hzwhuang@gmail.com>
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

EncryptorPrivate::EncryptorPrivate(const QString &m,
                                   const QString &pwd,
                                   QObject *parent) :
    QObject (parent)
{
    method = m.toLower().toLocal8Bit();
    password = pwd.toLocal8Bit();
    valid = true;

    const auto it = Cipher::cipherInfoMap.find(method.toStdString());
    if (it == Cipher::cipherInfoMap.end() || !Cipher::isSupported(it->second.internalName)) {
        qCritical("The method \"%s\" is not supported.", m.toStdString().data());
        valid = false;
    } else {
        method = QByteArray::fromStdString(it->second.internalName);
        keyLen = it->second.keyLen;
        ivLen = it->second.ivLen;
        evpBytesToKey();
    }
}

EncryptorPrivate::EncryptorPrivate(QObject *parent) :
    QObject(parent),
    keyLen(0),
    ivLen(0),
    valid(false)
{}

bool EncryptorPrivate::isValid() const
{
    return valid;
}

const QByteArray& EncryptorPrivate::getInternalMethodName() const
{
    return method;
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
        m.append(QByteArray::fromStdString(Cipher::md5Hash(data.toStdString())));
        i++;
    }
    QByteArray ms;
    for (QVector<QByteArray>::ConstIterator it = m.begin();
         it != m.end();
         ++it) {
        ms.append(*it);
    }

    key = ms.mid(0, keyLen);
}

EncryptorPrivate &EncryptorPrivate::operator=(const EncryptorPrivate &o)
{
    keyLen = o.keyLen;
    ivLen = o.ivLen;
    method = o.method;
    password = o.password;
    key = o.key;
    valid = o.valid;
    return *this;
}
