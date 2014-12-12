/*
 * cipher.h - the header file of Cipher class
 *
 * Communicate with lower-level encrytion library
 *
 * Seperated from Encryptor enables us to change low-level library easier.
 * If there is a modification associated with encryption/decryption, it's
 * this class that needs changes instead of messing up lots of classes.
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

#ifndef CIPHER_H
#define CIPHER_H

#include <QObject>
#include <QMap>
#include <QVector>
#include <botan/pipe.h>

namespace QSS {

class Cipher : public QObject
{
    Q_OBJECT
public:
    explicit Cipher(const QByteArray &method, const QByteArray &key, const QByteArray &iv, bool encode, QObject *parent = 0);

    QByteArray update(const QByteArray &data);

    /*
     * keyIvMap contains required key length and IV length
     * The QVector contains two integers, the first one is key length,
     * while the second one is IV length.
     * If there is no such cipher, then the QVector is empty.
     */
    static const QMap<QByteArray, QVector<int> > keyIvMap;

    static QByteArray randomIv(int length);
    static QByteArray md5Hash(const QByteArray &);
    static bool isSupported(const QByteArray &method);

private:
    Botan::Pipe pipe;

    static QMap<QByteArray, QVector<int> > generateKeyIvMap();
};

}

#endif // CIPHER_H
