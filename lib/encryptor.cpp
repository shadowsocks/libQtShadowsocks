/*
 * encryptor.cpp - the source file of Encryptor class
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

#include "encryptor.h"
#include <QtEndian>
#include <QDebug>

using namespace QSS;

namespace {
std::string evpBytesToKey(const Cipher::CipherInfo& cipherInfo, const std::string &password)
{
    std::vector<std::string> m;
    std::string data;
    int i = 0;

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
    cipherInfo(Cipher::cipherInfoMap.at(method)),
    method(method),
    masterKey(evpBytesToKey(cipherInfo, password))
{
}

void Encryptor::reset()
{
    enCipher.reset();
    deCipher.reset();
}

Cipher* Encryptor::initEncipher()
{
    const std::string iv = Cipher::randomIv(method);
    std::string key = masterKey;
#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        salt = Cipher::randomIv(cipherInfo.saltLen);
        key = Cipher::deriveAeadSubkey(cipherInfo.keyLen, masterKey, salt);
    }
#endif
    Cipher* cipher = new Cipher(method, key, iv, true);
    enCipherIV = iv;
    return cipher;
}

Cipher* Encryptor::initDecipher(const std::string& in)
{
    const std::string iv = cipherInfo.type == Cipher::CipherType::AEAD
                         ? std::string(cipherInfo.ivLen, static_cast<char>(0)) : in.substr(0, cipherInfo.ivLen);
    std::string key = masterKey;
#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        key = Cipher::deriveAeadSubkey(cipherInfo.keyLen, masterKey, in.substr(0, cipherInfo.saltLen));
    }
#endif
    Cipher* cipher = new Cipher(method, key, iv, false);
    return cipher;
}

std::string Encryptor::encrypt(const std::string &in)
{
    std::string header;
    if (!enCipher) {
        enCipher.reset(initEncipher());
        header = cipherInfo.type == Cipher::CipherType::AEAD ? salt : enCipherIV;
    }

    std::string encrypted;
#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        uint16_t inLen = in.length() & 0x3FFF;
        if (inLen != in.length()) {
            incompleteChunk += in.substr(inLen);
        }
        std::string length(2, static_cast<char>(0));
        qToBigEndian(inLen, reinterpret_cast<uint16_t*>(&length[0]));
        std::string encLength = enCipher->update(length); // length + tag
        std::string encPayload = enCipher->update(in.substr(0, inLen)); // payload + tag
        encrypted = encLength + encPayload;
    } else {
#endif
        encrypted = enCipher->update(in);
#ifdef USE_BOTAN2
    }
#endif
    return header + encrypted;
}

std::string Encryptor::decrypt(std::string in)
{
    std::string out;
    if (!deCipher) {
        deCipher.reset(initDecipher(in));
        if (cipherInfo.type == Cipher::CipherType::AEAD) {
            in = in.substr(cipherInfo.saltLen);
        } else {
            in = in.substr(cipherInfo.ivLen);
        }
    }

#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        in = incompleteChunk + in;
        std::string decLength = deCipher->update(in.substr(0, 2 + cipherInfo.tagLen));
        uint16_t length = qFromBigEndian(*reinterpret_cast<const uint16_t*>(decLength.data()));
        out = deCipher->update(in.substr(2 + cipherInfo.tagLen, length + cipherInfo.tagLen));
        incompleteChunk = in.substr(2 + cipherInfo.tagLen + length + cipherInfo.tagLen);
    } else {
#endif
        out = deCipher->update(in);
#ifdef USE_BOTAN2
    }
#endif
    return out;
}

std::string Encryptor::encryptAll(const std::string &in)
{
    std::string iv = enCipherIV;
    enCipherIV = Cipher::randomIv(method);
    enCipher.reset(new Cipher(method, masterKey, iv, true));
    return iv + enCipher->update(in);
}

std::string Encryptor::decryptAll(const std::string &in)
{
    int ivLen = Cipher::cipherInfoMap.at(method).ivLen;
    std::string iv = in.substr(0, ivLen);
    if (iv.size() != ivLen) {
        return std::string();
    }
    deCipher.reset(new Cipher(method, masterKey, iv, false));
    return deCipher->update(in.substr(Cipher::cipherInfoMap.at(method).ivLen));
}
