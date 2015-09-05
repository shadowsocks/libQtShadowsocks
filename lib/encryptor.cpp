/*
 * encryptor.cpp - the source file of Encryptor class
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

#include "encryptor.h"

using namespace QSS;

Encryptor::Encryptor(const EncryptorPrivate *_ep, QObject *parent) :
    QObject(parent),
    ep(_ep),
    enCipher(nullptr),
    deCipher(nullptr)
{}

void Encryptor::reset()
{
    if (enCipher) {
        enCipher->deleteLater();
        enCipher = nullptr;
    }
    if (deCipher) {
        deCipher->deleteLater();
        deCipher = nullptr;
    }
}

QByteArray Encryptor::encrypt(const QByteArray &in)
{
    QByteArray out, iv;
    const quint8* inp = reinterpret_cast<const quint8 *>(in.constData());

    switch (ep->type) {
    case TABLE:
        out.resize(in.size());
        for (int i = 0; i < in.size(); ++i) {
            out[i] = ep->encTable[inp[i]];
        }
        break;
    case CIPHER:
        if (!enCipher) {
            iv = Cipher::randomIv(ep->ivLen);
            enCipher = new Cipher(ep->method, ep->key, iv, true, this);
            out = iv + enCipher->update(in);
        } else {
            out = enCipher->update(in);
        }
        break;
    }

    return out;
}

QByteArray Encryptor::decrypt(const QByteArray &in)
{
    QByteArray out;
    const quint8* inp = reinterpret_cast<const quint8 *>(in.constData());

    switch (ep->type) {
    case TABLE:
        out.resize(in.size());
        for (int i = 0; i < in.size(); ++i) {
            out[i] = ep->decTable[inp[i]];
        }
        break;
    case CIPHER:
        if (!deCipher) {
            deCipher = new Cipher(ep->method, ep->key, in.mid(0, ep->ivLen), false, this);
            out = deCipher->update(in.mid(ep->ivLen));
        } else {
            out = deCipher->update(in);
        }
        break;
    }

    return out;
}

QByteArray Encryptor::encryptAll(const QByteArray &in)
{
    QByteArray out, iv;
    const quint8* inp = reinterpret_cast<const quint8 *>(in.constData());

    switch (ep->type) {
    case TABLE:
        out.resize(in.size());
        for (int i = 0; i < in.size(); ++i) {
            out[i] = ep->encTable[inp[i]];
        }
        break;
    case CIPHER:
        if (enCipher) {
            enCipher->deleteLater();
        }
        iv = Cipher::randomIv(ep->ivLen);
        enCipher = new Cipher(ep->method, ep->key, iv, true, this);
        out = iv + enCipher->update(in);
        break;
    }

    return out;
}

QByteArray Encryptor::decryptAll(const QByteArray &in)
{
    QByteArray out;
    const quint8* inp = reinterpret_cast<const quint8 *>(in.constData());

    switch (ep->type) {
    case TABLE:
        out.resize(in.size());
        for (int i = 0; i < in.size(); ++i) {
            out[i] = ep->decTable[inp[i]];
        }
        break;
    case CIPHER:
        if (deCipher) {
            deCipher->deleteLater();
        }
        deCipher = new Cipher(ep->method, ep->key, in.mid(0, ep->ivLen), false, this);
        out = deCipher->update(in.mid(ep->ivLen));
        break;
    }

    return out;
}

bool Encryptor::selfTest()
{
    QByteArray test("barfoo!"), test2("Hello World!"), test3("libQtShadowsocks!");
    QByteArray res  = decrypt(encrypt(test)),
               res2 = decrypt(encrypt(test2)),
               res3 = decrypt(encrypt(test3));
    reset();
    return test == res && test2 == res2 && test3 == res3;
}

QByteArray Encryptor::deCipherIV() const
{
    if (deCipher) {
        return deCipher->getIV();
    } else {
        return QByteArray();
    }
}
