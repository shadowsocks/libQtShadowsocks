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
                     const std::string &password) :
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

Cipher* Encryptor::initEncipher(std::string *header)
{
    const std::string iv = Cipher::randomIv(method);
    std::string key;
#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        const std::string salt = Cipher::randomIv(cipherInfo.saltLen);
        key = Cipher::deriveAeadSubkey(cipherInfo.keyLen, masterKey, salt);
        *header = salt;
    } else {
#endif
        key = masterKey;
        *header = iv;
#ifdef USE_BOTAN2
    }
#endif
    Cipher* cipher = new Cipher(method, key, iv, true);
    return cipher;
}

Cipher* Encryptor::initDecipher(const char *data, size_t *offset)
{
    std::string key, iv;
#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        iv = std::string(cipherInfo.ivLen, static_cast<char>(0));
        key = Cipher::deriveAeadSubkey(cipherInfo.keyLen, masterKey, std::string(data, cipherInfo.saltLen));
        *offset = cipherInfo.saltLen;
    } else {
#endif
        iv = std::string(data, cipherInfo.ivLen);
        key = masterKey;
        *offset = cipherInfo.ivLen;
#ifdef USE_BOTAN2
    }
#endif
    Cipher* cipher = new Cipher(method, key, iv, false);
    return cipher;
}

std::string Encryptor::encrypt(const std::string &in)
{
    std::string header;
    if (!enCipher) {
        enCipher.reset(initEncipher(&header));
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

std::string Encryptor::decrypt(const std::string &data)
{
    return decrypt(reinterpret_cast<const uint8_t*>(data.data()), data.length());
}

std::string Encryptor::decrypt(const uint8_t* data, size_t length)
{
    std::string out;
    if (!deCipher) {
        size_t headerLength = 0;
        deCipher.reset(initDecipher(reinterpret_cast<const char*>(data), &headerLength));
        data += headerLength;
        length -= headerLength;
    }

#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        std::string enc = incompleteChunk + std::string(reinterpret_cast<const char*>(data), length);
        const uint8_t *encPtr = reinterpret_cast<const uint8_t*>(enc.data());
        std::string decLength = deCipher->update(encPtr, 2 + cipherInfo.tagLen);
        uint16_t length = qFromBigEndian(*reinterpret_cast<const uint16_t*>(decLength.data()));
        out = deCipher->update(encPtr + 2 + cipherInfo.tagLen, length + cipherInfo.tagLen);
        incompleteChunk = enc.substr(2 + cipherInfo.tagLen + length + cipherInfo.tagLen);
    } else {
#endif
        out = deCipher->update(data, length);
#ifdef USE_BOTAN2
    }
#endif
    return out;
}

std::string Encryptor::encryptAll(const std::string &in)
{
    std::string header;
    enCipher.reset(initEncipher(&header));
    return header + enCipher->update(in);
}

std::string Encryptor::decryptAll(const std::string &data)
{
    return decryptAll(reinterpret_cast<const uint8_t*>(data.data()), data.length());
}

std::string Encryptor::decryptAll(const uint8_t* data, size_t length)
{
    size_t headerLength = 0; // IV or salt length
    deCipher.reset(initDecipher(reinterpret_cast<const char*>(data), &headerLength));
    data += headerLength;
    length -= headerLength;
    return deCipher->update(data, length);
}
