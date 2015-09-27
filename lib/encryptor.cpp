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
#include <QtEndian>

using namespace QSS;

Encryptor::Encryptor(const EncryptorPrivate &ep, QObject *parent) :
    QObject(parent),
    ep(ep),
    chunkId(0),
    enCipher(nullptr),
    deCipher(nullptr)
{
    enCipherIV = Cipher::randomIv(ep.ivLen);
}

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
    Q_ASSERT(ep.isValid());

    QByteArray out;
    if (!enCipher) {
        enCipher = new Cipher(ep.method, ep.key, enCipherIV, true, this);
        out = enCipherIV + enCipher->update(in);
    } else {
        out = enCipher->update(in);
    }
    return out;
}

QByteArray Encryptor::decrypt(const QByteArray &in)
{
    Q_ASSERT(ep.isValid());

    QByteArray out;
    if (!deCipher) {
        deCipher = new Cipher(ep.method, ep.key, in.mid(0, ep.ivLen), false, this);
        out = deCipher->update(in.mid(ep.ivLen));
    } else {
        out = deCipher->update(in);
    }
    return out;
}

QByteArray Encryptor::encryptAll(const QByteArray &in)
{
    Q_ASSERT(ep.isValid());

    if (enCipher) {
        enCipher->deleteLater();
    }
    QByteArray iv = Cipher::randomIv(ep.ivLen);
    enCipher = new Cipher(ep.method, ep.key, iv, true, this);
    return iv + enCipher->update(in);
}

QByteArray Encryptor::decryptAll(const QByteArray &in)
{
    Q_ASSERT(ep.isValid());

    if (deCipher) {
        deCipher->deleteLater();
    }
    deCipher = new Cipher(ep.method, ep.key, in.mid(0, ep.ivLen), false, this);
    return deCipher->update(in.mid(ep.ivLen));
}

bool Encryptor::selfTest()
{
    QByteArray test("barfoo!"), test2("Hello World!"), test3("libQtShadowsocks!");
    QByteArray res  = decrypt(encrypt(test)),
               res2 = decrypt(encrypt(test2)),
               res3 = decryptAll(encryptAll(test3));
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

void Encryptor::addHeaderAuth(QByteArray &headerData) const
{
    QByteArray key = enCipherIV + ep.key;
    QByteArray authCode = Cipher::hmacSha1(key, headerData);
    headerData.append(authCode);
}

void Encryptor::addHeaderAuth(QByteArray &data, const int &headerLen) const
{
    QByteArray key = enCipherIV + ep.key;
    QByteArray authCode = Cipher::hmacSha1(key, data.left(headerLen));
    data.insert(headerLen, authCode);
}

void Encryptor::addChunkAuth(QByteArray &data)
{
    QByteArray counter(4, 0);
    qToBigEndian(chunkId, reinterpret_cast<uchar*>(counter.data()));
    chunkId++;
    QByteArray key = enCipherIV + counter;
    QByteArray authCode = Cipher::hmacSha1(key, data);
    quint16 len = static_cast<quint16>(data.length());
    QByteArray len_c(2, 0);
    qToBigEndian(len, reinterpret_cast<uchar*>(len_c.data()));
    data.prepend(authCode);
    data.prepend(len_c);
}

bool Encryptor::verifyHeaderAuth(const QByteArray &data, const int &headerLen) const
{
    QByteArray key = deCipherIV() + ep.key;
    return Cipher::hmacSha1(key, data.left(headerLen)) == data.mid(headerLen, Cipher::AUTH_LEN);
}

bool Encryptor::verifyExtractChunkAuth(QByteArray &data)
{
    QByteArray result;
    bool verified = true;
    data.prepend(incompleteChunk);
    incompleteChunk.clear();
    for (int pos = 0; pos < data.size(); ) {
        char *dataPtr = data.data() + pos;
        quint16 len = qFromBigEndian(*reinterpret_cast<quint16*>(dataPtr));
        if (data.size() - pos - 2 - Cipher::AUTH_LEN < len) {
            incompleteChunk = QByteArray(dataPtr, data.size() - pos);
            break;
        }

        QByteArray counter(4, 0);
        qToBigEndian(chunkId, reinterpret_cast<uchar*>(counter.data()));
        chunkId++;
        QByteArray key = deCipherIV() + counter;
        QByteArray chunk = data.mid(pos + 2 + Cipher::AUTH_LEN, len);
        verified &= (Cipher::hmacSha1(key, chunk) == data.mid(pos + 2, Cipher::AUTH_LEN));
        if (verified) {
            result.append(chunk);
            pos += (2 + Cipher::AUTH_LEN + len);
        } else {
            break;
        }
    }
    data = result;
    return verified;
}
