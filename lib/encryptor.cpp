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

Encryptor::Encryptor(const std::string &method,
                     const std::string &password,
                     QObject *parent) :
    QObject(parent),
    method(method),
    password(evpBytesToKey(method, password)),
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

std::string Encryptor::encrypt(const std::string &in)
{
    std::string out;
    if (!enCipher) {
        enCipher = new Cipher(method, password, enCipherIV, true, this);
        out = enCipherIV + enCipher->update(in);
    } else {
        out = enCipher->update(in);
    }
    return out;
}

std::string Encryptor::decrypt(const std::string &in)
{
    std::string out;
    if (!deCipher) {
        int ivLen = Cipher::cipherInfoMap.at(method).ivLen;
        std::string iv = in.substr(0, ivLen);
        if (iv.size() != ivLen) {
            return out;
        }
        deCipher = new Cipher(method, password, iv, false, this);
        out = deCipher->update(in.substr(ivLen));
    } else {
        out = deCipher->update(in);
    }
    return out;
}

std::string Encryptor::encryptAll(const std::string &in)
{
    if (enCipher) {
        enCipher->deleteLater();
    }
    std::string iv = enCipherIV;
    enCipherIV = Cipher::randomIv(method);
    enCipher = new Cipher(method, password, iv, true, this);
    return iv + enCipher->update(in);
}

std::string Encryptor::decryptAll(const std::string &in)
{
    if (deCipher) {
        deCipher->deleteLater();
    }
    int ivLen = Cipher::cipherInfoMap.at(method).ivLen;
    std::string iv = in.substr(0, ivLen);
    if (iv.size() != ivLen) {
        return std::string();
    }
    deCipher = new Cipher(method, password, iv, false, this);
    return deCipher->update(in.substr(Cipher::cipherInfoMap.at(method).ivLen));
}

std::string Encryptor::deCipherIV() const
{
    if (deCipher) {
        return deCipher->getIV();
    } else {
        return std::string();
    }
}

void Encryptor::addHeaderAuth(std::string &headerData) const
{
    std::string authCode = Cipher::hmacSha1(enCipherIV + password, headerData);
    headerData.append(authCode);
}

void Encryptor::addHeaderAuth(std::string &data, const int &headerLen) const
{
    std::string authCode = Cipher::hmacSha1(enCipherIV + password, data.substr(0, headerLen));
    data.insert(headerLen, authCode.data(), authCode.size());
}

void Encryptor::addChunkAuth(std::string &data)
{
    char counter[4];
    qToBigEndian(chunkId, reinterpret_cast<uchar*>(counter));
    chunkId++;
    std::string key = enCipherIV + std::string(counter, 4);
    std::string authCode = Cipher::hmacSha1(key, data);
    quint16 len = static_cast<quint16>(data.size());
    char len_c[2];
    qToBigEndian(len, reinterpret_cast<uchar*>(len_c));
    data = std::string(len_c, 2) + authCode + data;
}

bool Encryptor::verifyHeaderAuth(const char *data, const int &headerLen) const
{
    return Cipher::hmacSha1(deCipherIV() + password, std::string(data, headerLen)).compare(
                std::string(data + headerLen, Cipher::AUTH_LEN)) == 0;
}

bool Encryptor::verifyExtractChunkAuth(std::string &data)
{
    std::string result;
    bool verified = true;
    data = incompleteChunk + data;
    incompleteChunk.clear();
    for (int pos = 0; pos < data.size(); ) {
        const char *dataPtr = data.data() + pos;
        quint16 len = qFromBigEndian(*reinterpret_cast<const quint16*>(dataPtr));
        if (data.size() - pos - 2 - Cipher::AUTH_LEN < len) {
            incompleteChunk = std::string(dataPtr, data.size() - pos);
            break;
        }

        char counter[4];
        qToBigEndian(chunkId, reinterpret_cast<uchar*>(counter));
        chunkId++;
        std::string key = deCipherIV() + std::string(counter, 4);
        std::string chunk = data.substr(pos + 2 + Cipher::AUTH_LEN, len);
        verified &= (Cipher::hmacSha1(key, chunk).compare(data.substr(pos + 2, Cipher::AUTH_LEN)) == 0);
        if (verified) {
            result += std::string(chunk.data(), chunk.size());
            pos += (2 + Cipher::AUTH_LEN + len);
        } else {
            break;
        }
    }
    data = result;
    return verified;
}

