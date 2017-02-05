/*
 * cipher.cpp - the source file of Cipher class
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
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(2,0,0)
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
            qFatal("%s\n", e.what());
        }
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(2,0,0)
        }
#endif
    }
}

Cipher::~Cipher()
{
    if (pipe)   delete pipe;
}

const std::map<QByteArray, Cipher::CipherKeyIVLength> Cipher::keyIvMap = {
    {"aes-128-cfb", {16, 16}},
    {"aes-192-cfb", {24, 16}},
    {"aes-256-cfb", {32, 16}},
    {"aes-128-ctr", {16, 16}},
    {"aes-192-ctr", {24, 16}},
    {"aes-256-ctr", {32, 16}},
    {"bf-cfb", {16, 8}},
    {"camellia-128-cfb", {16, 16}},
    {"camellia-192-cfb", {24, 16}},
    {"camellia-256-cfb", {32, 16}},
    {"cast5-cfb", {16, 8}},
    {"chacha20", {32, 8}},
    {"chacha20-ietf", {32, 12}},
    {"des-cfb", {8, 8}},
    {"idea-cfb", {16, 8}},
    {"rc2-cfb", {16, 8}},
    {"rc4-md5", {16, 16}},
    {"salsa20", {32, 8}},
    {"seed-cfb", {16, 16}},
    {"serpent-256-cfb", {32, 16}}
};
const std::map<QByteArray, QByteArray> Cipher::cipherNameMap= {
    {"aes-128-cfb", "AES-128/CFB"},
    {"aes-192-cfb", "AES-192/CFB"},
    {"aes-256-cfb", "AES-256/CFB"},
    {"aes-128-ctr", "AES-128/CTR-BE"},
    {"aes-192-ctr", "AES-192/CTR-BE"},
    {"aes-256-ctr", "AES-256/CTR-BE"},
    {"bf-cfb", "Blowfish/CFB"},
    {"camellia-128-cfb", "Camellia-128/CFB"},
    {"camellia-192-cfb", "Camellia-192/CFB"},
    {"camellia-256-cfb", "Camellia-256/CFB"},
    {"cast5-cfb", "CAST-128/CFB"},
    {"chacha20", "ChaCha"},
    {"chacha20-ietf", "ChaCha"},
    {"des-cfb", "DES/CFB"},
    {"idea-cfb", "IDEA/CFB"},
    {"rc2-cfb", "RC2/CFB"},
    {"rc4-md5", "RC4-MD5"},
    {"salsa20", "Salsa20"},
    {"seed-cfb", "SEED/CFB"},
    {"serpent-256-cfb", "Serpent/CFB"}
};
const int Cipher::AUTH_LEN = 10;

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
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(2,0,0)
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
    for (auto& cipher : Cipher::cipherNameMap) {
        if (Cipher::isSupported(cipher.second)) {
            supportedMethods.push_back(cipher.first);
        }
    }
    return supportedMethods;
}
