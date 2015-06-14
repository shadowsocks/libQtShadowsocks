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

#include <botan/auto_rng.h>
#include <botan/key_filt.h>
#include <botan/lookup.h>
#include <stdexcept>
#include "cipher.h"

using namespace QSS;

Cipher::Cipher(const QByteArray &method, const QByteArray &key, const QByteArray &iv, bool encode, QObject *parent) :
    QObject(parent),
    pipe(nullptr),
    rc4(nullptr),
    chacha(nullptr)
{
    if (method.contains("RC4")) {
        rc4 = new RC4(key, iv, this);
    } else {
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,11,0)
        if (method.contains("ChaCha")) {
            chacha = new ChaCha(key, iv, this);
        } else {
#endif
        std::string str(method.constData(), method.length());
        Botan::SymmetricKey _key(reinterpret_cast<const Botan::byte *>(key.constData()), key.size());
        Botan::InitializationVector _iv(reinterpret_cast<const Botan::byte *>(iv.constData()), iv.size());
        Botan::Keyed_Filter *filter = Botan::get_cipher(str, _key, _iv, encode ? Botan::ENCRYPTION : Botan::DECRYPTION);
        //Botan::pipe will take control over filter, we shouldn't deallocate filter externally
        pipe = new Botan::Pipe(filter);
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,11,0)
        }
#endif
    }
}

Cipher::~Cipher()
{
    if (pipe)   delete pipe;
}

const QMap<QByteArray, QVector<int> > Cipher::keyIvMap = Cipher::generateKeyIvMap();

QMap<QByteArray, QVector<int> > Cipher::generateKeyIvMap()
{
    QMap<QByteArray, QVector<int> >map;
    map.insert("AES-128/CFB", {16, 16});
    map.insert("AES-192/CFB", {24, 16});
    map.insert("AES-256/CFB", {32, 16});
    map.insert("Blowfish/CFB", {16, 8});
    map.insert("Camellia-128/CFB", {16, 16});
    map.insert("Camellia-192/CFB", {24, 16});
    map.insert("Camellia-256/CFB", {32, 16});
    map.insert("CAST-128/CFB", {16, 8});
    map.insert("ChaCha", {32, 8});
    map.insert("DES/CFB", {8, 8});
    map.insert("IDEA/CFB", {16, 8});
    map.insert("RC2/CFB", {16, 8});
    map.insert("RC4", {16, 0});
    map.insert("RC4-MD5", {16, 16});
    map.insert("Salsa20", {32, 8});
    map.insert("SEED/CFB", {16, 16});
    map.insert("Serpent/CFB", {32, 16});//256-bit Serpent
    return map;
}

QByteArray Cipher::update(const QByteArray &data)
{
    if (chacha) {
        return chacha->update(data);
    } else if (rc4) {
        return rc4->update(data);
    } else if (pipe) {
        pipe->process_msg(reinterpret_cast<const Botan::byte *>(data.constData()), data.size());
        SecureByteArray c = pipe->read_all(Botan::Pipe::LAST_MESSAGE);
        QByteArray out(reinterpret_cast<const char *>(DataOfSecureByteArray(c)), c.size());
        return out;
    } else {
        throw std::runtime_error("Underlying ciphers are all uninitialised!");
    }
}

QByteArray Cipher::randomIv(int length)
{
    if (length == 0) {//directly return empty byte array if no need to genenrate iv
        return QByteArray();
    }

    Botan::AutoSeeded_RNG rng;
    QByteArray out;
    out.resize(length);
    rng.randomize(reinterpret_cast<Botan::byte *>(out.data()), length);
    return out;
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
