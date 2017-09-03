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

namespace {
std::string evpBytesToKey(const std::string& method, const std::string &password)
{
    std::vector<std::string> m;
    std::string data;
    int i = 0;

    auto cipherInfo = Cipher::cipherInfoMap.at(method);
    while (m.size() < cipherInfo.keyLen + cipherInfo.ivLen) {
        if (i == 0) {
            data = password;
        } else {
            data = m[i - 1] + password;
        }
        m.push_back(Cipher::md5Hash(data));
        ++i;
    }

    std::string ms;
    std::for_each(m.begin(), m.end(), [&ms](const std::string& bytes) {
        ms += bytes;
    });

    return ms.substr(0, cipherInfo.keyLen);
}

}

Encryptor::Encryptor(const QByteArray& method,
                     const QByteArray& password,
                     QObject *parent) :
    QObject(parent),
    method(method.toStdString()),
    password(evpBytesToKey(this->method, password.toStdString())),
    chunkId(0),
    enCipher(nullptr),
    deCipher(nullptr)
{
    enCipherIV = Cipher::randomIv(this->method);
}

void Encryptor::reset()
{
    if (enCipher) {
        enCipher->deleteLater();
        enCipher = nullptr;
        enCipherIV = Cipher::randomIv(this->method);
    }
    if (deCipher) {
        deCipher->deleteLater();
        deCipher = nullptr;
    }
    chunkId = 0;
}

QByteArray Encryptor::encrypt(const QByteArray &in)
{
    QByteArray out;
    if (!enCipher) {
        enCipher = new Cipher(method, password, enCipherIV, true, this);
        out = QByteArray::fromStdString(enCipherIV + enCipher->update(in.toStdString()));
    } else {
        out = QByteArray::fromStdString(enCipher->update(in.toStdString()));
    }
    return out;
}

QByteArray Encryptor::decrypt(const QByteArray &in)
{
    QByteArray out;
    if (!deCipher) {
        int ivLen = Cipher::cipherInfoMap.at(method).ivLen;
        std::string iv = in.mid(0, ivLen).toStdString();
        if (iv.size() != ivLen) {
            return out;
        }
        deCipher = new Cipher(method, password, iv, false, this);
        out = QByteArray::fromStdString(deCipher->update(in.mid(ivLen).toStdString()));
    } else {
        out = QByteArray::fromStdString(deCipher->update(in.toStdString()));
    }
    return out;
}

QByteArray Encryptor::encryptAll(const QByteArray &in)
{
    if (enCipher) {
        enCipher->deleteLater();
    }
    std::string iv = enCipherIV;
    enCipherIV = Cipher::randomIv(method);
    enCipher = new Cipher(method, password, iv, true, this);
    return QByteArray::fromStdString(iv + enCipher->update(in.toStdString()));
}

QByteArray Encryptor::decryptAll(const QByteArray &in)
{
    if (deCipher) {
        deCipher->deleteLater();
    }
    int ivLen = Cipher::cipherInfoMap.at(method).ivLen;
    std::string iv = in.mid(0, ivLen).toStdString();
    if (iv.size() != ivLen) {
        return QByteArray();
    }
    deCipher = new Cipher(method, password, iv, false, this);
    return QByteArray::fromStdString(deCipher->update(in.mid(Cipher::cipherInfoMap.at(method).ivLen).toStdString()));
}

std::string Encryptor::deCipherIV() const
{
    if (deCipher) {
        return deCipher->getIV();
    } else {
        return std::string();
    }
}

void Encryptor::addHeaderAuth(QByteArray &headerData) const
{
    QByteArray key = QByteArray::fromStdString(enCipherIV + password);
    QByteArray authCode = Cipher::hmacSha1(key, headerData);
    headerData.append(authCode);
}

void Encryptor::addHeaderAuth(QByteArray &data, const int &headerLen) const
{
    QByteArray key = QByteArray::fromStdString(enCipherIV + password);
    QByteArray authCode = Cipher::hmacSha1(key, data.left(headerLen));
    data.insert(headerLen, authCode);
}

void Encryptor::addChunkAuth(QByteArray &data)
{
    char counter[4];
    qToBigEndian(chunkId, reinterpret_cast<uchar*>(counter));
    chunkId++;
    QByteArray key = QByteArray::fromStdString(enCipherIV + std::string(counter, 4));
    QByteArray authCode = Cipher::hmacSha1(key, data);
    quint16 len = static_cast<quint16>(data.length());
    QByteArray len_c(2, 0);
    qToBigEndian(len, reinterpret_cast<uchar*>(len_c.data()));
    data.prepend(len_c + authCode);
}

bool Encryptor::verifyHeaderAuth(const QByteArray &data, const int &headerLen) const
{
    QByteArray key = QByteArray::fromStdString(deCipherIV() + password);
    return Cipher::hmacSha1(key, data.left(headerLen))
            == data.mid(headerLen, Cipher::AUTH_LEN);
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

        char counter[4];
        qToBigEndian(chunkId, reinterpret_cast<uchar*>(counter));
        chunkId++;
        QByteArray key = QByteArray::fromStdString(deCipherIV() + std::string(counter, 4));
        QByteArray chunk = data.mid(pos + 2 + Cipher::AUTH_LEN, len);
        verified &= (
                    Cipher::hmacSha1(key, chunk)
                    == data.mid(pos + 2, Cipher::AUTH_LEN)
                    );
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

