/*
 * cipher.cpp - the source file of Cipher class
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

#include <QCryptographicHash>
#include <botan/auto_rng.h>
#include <botan/key_filt.h>
#include <botan/lookup.h>
#include "cipher.h"

using namespace QSS;

Cipher::Cipher(const QByteArray &method, const QByteArray &key, const QByteArray &iv, bool encode, QObject *parent) :
    QObject(parent)
{
    Botan::Keyed_Filter *filter;
    if (method.contains("RC4")) {
        QByteArray rc4_key;
        if (iv.isEmpty()) {//old deprecated rc4's iv is empty
            rc4_key = key;
        }
        else {//otherwise, it's rc4-md5
            rc4_key = md5Hash(key + iv);
        }
        Botan::SymmetricKey _key(reinterpret_cast<const Botan::byte *>(rc4_key.constData()), key.size());
        filter = Botan::get_cipher("ARC4", _key, encode ? Botan::ENCRYPTION : Botan::DECRYPTION);//botan-1.10
    }
    else {
        std::string str(method.constData(), method.length());
        Botan::SymmetricKey _key(reinterpret_cast<const Botan::byte *>(key.constData()), key.size());
        Botan::InitializationVector _iv(reinterpret_cast<const Botan::byte *>(iv.constData()), iv.size());
        filter = Botan::get_cipher(str, _key, _iv, encode ? Botan::ENCRYPTION : Botan::DECRYPTION);
    }
    //Botan::pipe will take control over filter, we shouldn't deallocate filter externally
    pipe = new Botan::Pipe(filter);
}

Cipher::~Cipher()
{
    if(pipe != NULL)    delete pipe;
}

const QMap<QByteArray, QVector<int> > Cipher::keyIvMap = Cipher::generateKeyIvMap();

QMap<QByteArray, QVector<int> > Cipher::generateKeyIvMap()
{
    QMap<QByteArray, QVector<int> >map;
    map.insert("AES-128/CFB", {16, 16});
    map.insert("AES-192/CFB", {24, 16});
    map.insert("AES-256/CFB", {32, 16});
    map.insert("Blowfish/CFB", {16, 8});
    map.insert("CAST-128/CFB", {16, 8});
    map.insert("DES/CFB", {8, 8});
    map.insert("IDEA/CFB", {16, 8});
    map.insert("RC2/CFB", {16, 8});
    map.insert("RC4", {16, 0});
    map.insert("RC4-MD5", {16, 16});
    map.insert("Salsa20", {32, 8});
    map.insert("SEED/CFB", {16, 16});
    return map;
}

QByteArray Cipher::update(const QByteArray &data)
{
    pipe->process_msg(reinterpret_cast<const Botan::byte *>(data.constData()), data.size());
    size_t id = pipe->message_count() - 1;
    Botan::SecureVector<Botan::byte> c = pipe->read_all(id);
    QByteArray out(reinterpret_cast<char *>(c.begin()), c.size());
    return out;
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

QByteArray Cipher::md5Hash(const QByteArray &in)
{
    return QCryptographicHash::hash(in, QCryptographicHash::Md5);
}

bool Cipher::isSupported(const QByteArray &method)
{
    if (method.contains("RC4")) {
        return Botan::have_algorithm("ARC4");
    }
    else {
        //have_algorithm function take only the **algorithm** (so we need to omit the mode)
        std::string algorithm(method.constData(), method.lastIndexOf('/'));
        return Botan::have_algorithm(algorithm);
    }
}
