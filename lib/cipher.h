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
class KDF;
class HashFunction;
class MessageAuthenticationCode;
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

    enum CipherType {
        STREAM,
        AEAD
    };

    struct CipherInfo {
        QByteArray internalName; // internal implementation name
        int keyLen;
        int ivLen;
        CipherType type;
        int saltLen; // only for AEAD
        int tagLen; // only for AEAD
    };

    /*
     * The key of this map is the encryption method (shadowsocks convention)
     */
    static const std::map<QByteArray, CipherInfo> cipherInfoMap;

    /*
     * The label/info string used for key derivation function
     */
    static const std::string kdfLabel;

    static const int AUTH_LEN;

    /*
     * Generates a vector of random characters of given length
     */
    static QByteArray randomIv(int length);

    static QByteArray hmacSha1(const QByteArray &key, const QByteArray &msg);
    static QByteArray md5Hash(const QByteArray &in);
    static bool isSupported(const QByteArray &method);

    static QList<QByteArray> getSupportedMethodList();

private:
    Botan::Pipe *pipe;
    RC4 *rc4;
    ChaCha *chacha;
    const QByteArray key; // preshared key
    const QByteArray iv; // nonce
    const CipherInfo cipherInfo;

#ifdef USE_BOTAN2
    // AEAD support needs Botan-2 library

    Botan::HashFunction *msgHashFunc;
    Botan::MessageAuthenticationCode *msgAuthCode;
    Botan::KDF *kdf;

    QByteArray deriveSubkey();
#endif
};

}

#endif // CIPHER_H
