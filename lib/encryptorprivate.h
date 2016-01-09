/*
 * encryptorprivate.cpp - the header file of EncryptorPrivate class
 *
 * Copyright (C) 2014-2016 Symeon Huang <hzwhuang@gmail.com>
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

#ifndef ENCRYPTORPRIVATE
#define ENCRYPTORPRIVATE

#include <QByteArray>
#include <QVector>
#include <QObject>
#include "export.h"

namespace QSS {

class QSS_EXPORT EncryptorPrivate : public QObject
{
    Q_OBJECT
public:
    /*
     * Initialise an EncryptorPrivate instance that is needed by Encryptor
     * Multiple encryptors can share one EncryptorPrivate so long as they're using same
     * encryption method and password.
     * If the initialisation doesn't succeed, isValid() function will return false
     */
    explicit EncryptorPrivate(const QString &method, const QString &password, QObject *parent = 0);
    explicit EncryptorPrivate(QObject *parent = 0);//construct an invalid/null instance

    bool isValid() const;

    /*
     * Because we use a different name internally, i.e. aes-128-cfb becomes AES-128/CFB. This function
     * may be helpful for developers to diagnose the problem (if there is a problem).
     */
    QString getInternalMethodName() const;

    EncryptorPrivate& operator= (const EncryptorPrivate &o);

private:
    int keyLen;
    int ivLen;
    QByteArray method;
    QByteArray password;
    QByteArray key;
    bool valid;

    void evpBytesToKey();

    friend class Encryptor;
};

}

#endif // ENCRYPTORPRIVATE

