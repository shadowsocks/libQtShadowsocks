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

EncryptorPrivate::EncryptorPrivate(const QString &m,
                                   const QString &pwd,
                                   QObject *parent) :
    QObject (parent)
{
    method = m.toUpper().toLocal8Bit();
    password = pwd.toLocal8Bit();
    valid = true;

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

    Cipher::CipherKeyIVLength ki = Cipher::keyIvMap.value(method);
    if (ki[0] == 0 || !Cipher::isSupported(method)) {
        qCritical("The method %s is not supported.", m.toStdString().data());
        valid = false;
    }
    keyLen = ki[0];
    ivLen = ki[1];
    evpBytesToKey();
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

QString EncryptorPrivate::getInternalMethodName() const
{
    return QString(method);
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
