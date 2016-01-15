/*
 * cipher.cpp - the source file of Cipher class
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

#include "cipher.h"
#include <botan/auto_rng.h>
#include <botan/key_filt.h>
#include <botan/lookup.h>
#include <stdexcept>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>

using namespace QSS;

Cipher::Cipher(const QByteArray &method,
               const QByteArray &key,
               const QByteArray &iv,
               bool encode,
               QObject *parent) :
    QObject(parent),
    pipe(nullptr),
    rc4(nullptr),
    chacha(nullptr),
    iv(iv)
{
    if (method.contains("RC4")) {
        rc4 = new RC4(key, iv, this);
    } else {
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,11,0)
        if (method.contains("ChaCha")) {
            chacha = new ChaCha(key, iv, this);
        } else {
#endif
        try {
            std::string str(method.constData(), method.length());
            Botan::SymmetricKey _key(
                        reinterpret_cast<const Botan::byte *>(key.constData()),
                        key.size());
            Botan::InitializationVector _iv(
                        reinterpret_cast<const Botan::byte *>(iv.constData()),
                        iv.size());
            Botan::Keyed_Filter *filter = Botan::get_cipher(str, _key, _iv,
                        encode ? Botan::ENCRYPTION : Botan::DECRYPTION);
            // Botan::pipe will take control over filter
            // we shouldn't deallocate filter externally
            pipe = new Botan::Pipe(filter);
        } catch(Botan::Exception &e) {
            qWarning("%s\n", e.what());
        }
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,11,0)
        }
#endif
    }
}

Cipher::~Cipher()
{
    if (pipe)   delete pipe;
}

const QMap<QByteArray, Cipher::CipherKeyIVLength> Cipher::keyIvMap =
        Cipher::generateKeyIvMap();
const QMap<QByteArray, QByteArray> Cipher::cipherNameMap =
        Cipher::generateCipherNameMap();
const int Cipher::AUTH_LEN = 10;

QMap<QByteArray, Cipher::CipherKeyIVLength> Cipher::generateKeyIvMap()
{
    QMap<QByteArray, CipherKeyIVLength> map;
    map.insert("aes-128-cfb", {16, 16});
    map.insert("aes-192-cfb", {24, 16});
    map.insert("aes-256-cfb", {32, 16});
    map.insert("bf-cfb", {16, 8});
    map.insert("camellia-128-cfb", {16, 16});
    map.insert("camellia-192-cfb", {24, 16});
    map.insert("camellia-256-cfb", {32, 16});
    map.insert("cast5-cfb", {16, 8});
    map.insert("chacha20", {32, 8});
    map.insert("chacha20-ietf", {32, 12});
    map.insert("des-cfb", {8, 8});
    map.insert("idea-cfb", {16, 8});
    map.insert("rc2-cfb", {16, 8});
    map.insert("rc4-md5", {16, 16});
    map.insert("salsa20", {32, 8});
    map.insert("seed-cfb", {16, 16});
    map.insert("serpent-256-cfb", {32, 16});
    return map;
}

QMap<QByteArray, QByteArray> Cipher::generateCipherNameMap()
{
    QMap<QByteArray, QByteArray> map;
    map.insert("aes-128-cfb", "AES-128/CFB");
    map.insert("aes-192-cfb", "AES-192/CFB");
    map.insert("aes-256-cfb", "AES-256/CFB");
    map.insert("bf-cfb", "Blowfish/CFB");
    map.insert("camellia-128-cfb", "Camellia-128/CFB");
    map.insert("camellia-192-cfb", "Camellia-192/CFB");
    map.insert("camellia-256-cfb", "Camellia-256/CFB");
    map.insert("cast5-cfb", "CAST-128/CFB");
    map.insert("chacha20", "ChaCha");
    map.insert("chacha20-ietf", "ChaCha");
    map.insert("des-cfb", "DES/CFB");
    map.insert("idea-cfb", "IDEA/CFB");
    map.insert("rc2-cfb", "RC2/CFB");
    map.insert("rc4-md5", "RC4-MD5");
    map.insert("salsa20", "Salsa20");
    map.insert("seed-cfb", "SEED/CFB");
    map.insert("serpent-256-cfb", "Serpent/CFB");
    return map;
}

QByteArray Cipher::update(const QByteArray &data)
{
    if (chacha) {
        return chacha->update(data);
    } else if (rc4) {
        return rc4->update(data);
    } else if (pipe) {
        pipe->process_msg(reinterpret_cast<const Botan::byte *>
                          (data.constData()), data.size());
        SecureByteArray c = pipe->read_all(Botan::Pipe::LAST_MESSAGE);
        QByteArray out(reinterpret_cast<const char *>(DataOfSecureByteArray(c)),
                       c.size());
        return out;
    } else {
        throw std::runtime_error("Underlying ciphers are all uninitialised!");
    }
}

const QByteArray &Cipher::getIV() const
{
    return iv;
}

QByteArray Cipher::randomIv(int length)
{
    //directly return empty byte array if no need to genenrate iv
    if (length == 0) {
        return QByteArray();
    }

    Botan::AutoSeeded_RNG rng;
    QByteArray out;
    out.resize(length);
    rng.randomize(reinterpret_cast<Botan::byte *>(out.data()), length);
    return out;
}

QByteArray Cipher::hmacSha1(const QByteArray &key, const QByteArray &msg)
{
    return QMessageAuthenticationCode::hash(msg,
                                       key,
                                       QCryptographicHash::Sha1).left(AUTH_LEN);
}

QByteArray Cipher::md5Hash(const QByteArray &in)
{
    return QCryptographicHash::hash(in, QCryptographicHash::Md5);
}

bool Cipher::isSupported(const QByteArray &method)
{
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,11,0)
    if (method.contains("ChaCha"))  return true;
#endif

    if (method.contains("RC4")) {
        return true;
    } else {
        std::string str(method.constData(), method.length());
        Botan::Keyed_Filter *filter;
        try {
            filter = Botan::get_cipher(str, Botan::ENCRYPTION);
        } catch (Botan::Exception &e) {
            qWarning("%s\n", e.what());
            return false;
        }
        delete filter;
        return true;
    }
}

QList<QByteArray> Cipher::getSupportedMethodList()
{
    QList<QByteArray> supportedMethods;
    for (auto it = Cipher::cipherNameMap.cbegin();
         it != Cipher::cipherNameMap.cend();
         ++it) {
        if (Cipher::isSupported(it.value())) {
            supportedMethods.push_back(it.key());
        }
    }
    return supportedMethods;
}
