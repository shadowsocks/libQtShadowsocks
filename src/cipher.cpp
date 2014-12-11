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
            rc4_key = QCryptographicHash::hash(key + iv, QCryptographicHash::Md5);
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
    pipe = new Botan::Pipe(filter);
}

Cipher::~Cipher()
{
    if(pipe != NULL)    delete pipe;
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

bool Cipher::isSupported(const QByteArray &method)
{
    if (method.contains("RC4")) {
        return Botan::have_algorithm("ARC4");
    }
    else {
        //have_algorithm function take only the **algorithm** (so we need to omit the mode)
        return Botan::have_algorithm(method.mid(0, method.lastIndexOf('/')).toStdString());
    }
}
