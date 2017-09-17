/*
 * encryptor.h - the header file of Encryptor class
 *
 * High-level API to encrypt/decrypt data that send to or receive from
 * another shadowsocks side.
 *
 * This class shouldn't contain too many detailed (de)encrypt functions.
 * Instead, it should use Cipher class as much as possible.
 * The only exception for this rule is the deprecated TABLE method.
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

#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <memory>
#include "cipher.h"

namespace QSS {

class Encryptor
{
public:
    /**
     * @brief Encryptor
     * @param method The encryption method in Shadowsocks convention
     * @param password The preshared password
     */
    Encryptor(const std::string& method,
              const std::string& password);

    std::string decrypt(std::string);
    std::string encrypt(const std::string &);

    std::string decryptAll(std::string);//(de)encryptAll is for updreplay
    std::string encryptAll(const std::string &);

    void reset();

private:
    const Cipher::CipherInfo cipherInfo;
    std::string method;
    std::string masterKey;

    // Incomplete data chunk that is pending
    std::string incompleteChunk;

    Cipher* initEncipher(std::string *header);
    Cipher* initDecipher(std::string *inOut);

protected:
    std::unique_ptr<Cipher> enCipher;
    std::unique_ptr<Cipher> deCipher;
};

}

#endif // ENCRYPTOR_H
