/*
 * encryptor.h - the header file of Encryptor class
 *
 * High-level API to encrypt/decrypt data that send to or receive from
 * another shadowsocks side.
 *
 * This class shouldn't contain too many detailed (de)encrypt functions.
 * Instead, it should use Cipher class as much as possible.
 * The only exception for this rule is the deprecated TABLE method.
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

#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <QObject>
#include "cipher.h"
#include "export.h"
#include "encryptorprivate.h"

namespace QSS {

class QSS_EXPORT Encryptor : public QObject
{
    Q_OBJECT
public:
    explicit Encryptor(const EncryptorPrivate *_ep, QObject *parent = 0);

    QByteArray decrypt(const QByteArray &);
    QByteArray encrypt(const QByteArray &);
    QByteArray decryptAll(const QByteArray &);//(de)encryptAll is for updreplay
    QByteArray encryptAll(const QByteArray &);
    void reset();
    bool selfTest();
    QByteArray deCipherIV() const;

private:
    const EncryptorPrivate *ep;

protected:
    Cipher *enCipher;
    Cipher *deCipher;
};

}

#endif // ENCRYPTOR_H
