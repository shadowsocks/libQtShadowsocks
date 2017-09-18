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
    masterKey(evpBytesToKey(cipherInfo, password)),
    incompleteLength(0)
{
}

void Encryptor::reset()
{
    enCipher.reset();
    deCipher.reset();
    incompleteChunk.clear();
    incompleteLength = 0;
}

void Encryptor::initEncipher(std::string *header)
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
    enCipher.reset(new Cipher(method, key, iv, true));
}

void Encryptor::initDecipher(const char *data, size_t length, size_t *offset)
{
    std::string key, iv;
#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        iv = std::string(cipherInfo.ivLen, static_cast<char>(0));
        if (length < cipherInfo.saltLen) {
            throw std::length_error("Data chunk is too small to initialise an AEAD decipher");
        }
        key = Cipher::deriveAeadSubkey(cipherInfo.keyLen, masterKey, std::string(data, cipherInfo.saltLen));
        *offset = cipherInfo.saltLen;
    } else {
#endif
        if (length < cipherInfo.ivLen) {
            throw std::length_error("Data chunk is too small to initialise a stream decipher");
        }
        iv = std::string(data, cipherInfo.ivLen);
        key = masterKey;
        *offset = cipherInfo.ivLen;
#ifdef USE_BOTAN2
    }
#endif
    deCipher.reset(new Cipher(method, key, iv, false));
}

std::string Encryptor::encrypt(const std::string &in)
{
    std::string header;
    if (!enCipher) {
        initEncipher(&header);
    }

    std::string encrypted;
#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        uint16_t inLen = in.length() & 0x3FFF;
        std::string length(2, static_cast<char>(0));
        qToBigEndian(inLen, reinterpret_cast<uint16_t*>(&length[0]));
        std::string encLength = enCipher->update(length); // length + tag
        enCipher->incrementIv();
        std::string encPayload = enCipher->update(in.substr(0, inLen)); // payload + tag
        enCipher->incrementIv();
        encrypted = encLength + encPayload;
        if (inLen != in.length()) {
            // Append the remaining part recursively if there is any
            encrypted += encrypt(in.substr(inLen));
        }
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
    const uint8_t *dataEnd = data + length;
    if (!deCipher) {
        size_t headerLength = 0;
        initDecipher(reinterpret_cast<const char*>(data), length, &headerLength);
        data += headerLength;
        length -= headerLength;
    }

#ifdef USE_BOTAN2
    if (cipherInfo.type == Cipher::CipherType::AEAD) {
        // Concatenate the data with incomplete chunk (if it exists)
        std::string chunk = incompleteChunk + std::string(reinterpret_cast<const char*>(data), length);
        data = reinterpret_cast<const uint8_t*>(chunk.data());
        length = chunk.length();
        dataEnd = data + length;

        uint16_t payloadLength = 0;
        if (incompleteLength) {
            payloadLength = incompleteLength;
            incompleteLength = 0;
            incompleteChunk.clear();
        } else {
            if (dataEnd - data < 2 + cipherInfo.tagLen) {
                throw std::length_error("AEAD data chunk is too small to decrypt the length");
            }
            std::string decLength = deCipher->update(data, 2 + cipherInfo.tagLen);
            deCipher->incrementIv();
            data += (2 + cipherInfo.tagLen);
            payloadLength = qFromBigEndian(*reinterpret_cast<const uint16_t*>(decLength.data()));
        }

        if (dataEnd - data < payloadLength + cipherInfo.tagLen) {
            qDebug("AEAD data chunk is incomplete");
            incompleteChunk = std::string(reinterpret_cast<const char*>(data), dataEnd - data);
            incompleteLength = payloadLength;
            return std::string();
        }
        out = deCipher->update(data, payloadLength + cipherInfo.tagLen);
        deCipher->incrementIv();
        data += (payloadLength + cipherInfo.tagLen);
        if (dataEnd > data) {
            // Append remaining decrypted chunks recursively if there is any
            out += decrypt(data, dataEnd - data);
        }
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
    initEncipher(&header);
    return header + enCipher->update(in);
}

std::string Encryptor::decryptAll(const std::string &data)
{
    return decryptAll(reinterpret_cast<const uint8_t*>(data.data()), data.length());
}

std::string Encryptor::decryptAll(const uint8_t* data, size_t length)
{
    size_t headerLength = 0; // IV or salt length
    initDecipher(reinterpret_cast<const char*>(data), length, &headerLength);
    data += headerLength;
    length -= headerLength;
    return deCipher->update(data, length);
}
