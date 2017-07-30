/*
 * cipher.h - the header file of Cipher class
 *
 * Communicate with lower-level encrytion library
 *
 * Seperated from Encryptor enables us to change low-level library easier.
 * If there is a modification associated with encryption/decryption, it's
 * this class that needs changes instead of messing up lots of classes.
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

#ifndef CIPHER_H
#define CIPHER_H

#include <array>
#include <map>
#include <QObject>
#include "rc4.h"
#include "chacha.h"
#include "export.h"

namespace Botan {
class Pipe;
}

namespace QSS {

class QSS_EXPORT Cipher : public QObject
{
    Q_OBJECT
public:
    Cipher(const QByteArray &method, const QByteArray &key, const QByteArray &iv, bool encode, QObject *parent = 0);
    Cipher(Cipher &&) = default;
    ~Cipher();

    QByteArray update(const QByteArray &data);
    const QByteArray &getIV() const;

    typedef std::array<int, 2> CipherKeyIVLength;
    struct CipherInfo {
        QByteArray internalName; // internal implementation name
        int keyLen;
        int ivLen;
    };

    /*
     * The key of this map is the encryption method (shadowsocks convention)
     */
    static const std::map<QByteArray, CipherInfo> cipherInfoMap;

    static const int AUTH_LEN;

    static QByteArray randomIv(int length);
    static QByteArray hmacSha1(const QByteArray &key, const QByteArray &msg);
    static QByteArray md5Hash(const QByteArray &in);
    static bool isSupported(const QByteArray &method);

    static QList<QByteArray> getSupportedMethodList();

private:
    Botan::Pipe *pipe;
    RC4 *rc4;
    ChaCha *chacha;
    QByteArray iv;
};

}

#endif // CIPHER_H
