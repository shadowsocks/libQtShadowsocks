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

#ifndef ENCRYPTOR_H
#define ENCRYPTOR_H

#include <QObject>
#include "cipher.h"

namespace QSS {

class Encryptor : public QObject
{
    Q_OBJECT
public:
    explicit Encryptor(QObject *parent = 0);
    ~Encryptor();

    enum TYPE {TABLE, CIPHER};//CIPHER means we need to use Cipher class to do encryption/decryption
    QByteArray decrypt(const QByteArray &);
    QByteArray encrypt(const QByteArray &);
    QByteArray decryptAll(const QByteArray &);//(de)encryptAll is for updreplay
    QByteArray encryptAll(const QByteArray &);
    void reset();

    static const QVector<quint8> octVec;
    static int randomCompare(const quint8 &, const quint8 &, const quint32 &, const quint64 &);

    /*
     * Return true if initialised succesfully, otherwise return false.
     * Only need to call this function once if the encrpytion method and password don't change.
     * If you want to change the method and password, remember to call reset() function to remove
     * the old enCipher and(or) deCipher.
     * It's not recommended to change method and/or password on-process. The clean way to do that
     * is to delete and release the old library classes, then construct them with new values.
     */
    static bool initialise(const QString &m, const QString &pwd);

    /*
     * Because we use a different name internally, i.e. aes-128-cfb becomes AES-128/CFB. This function
     * may be helpful for developers to diagnose the problem (if there is a problem).
     */
    static QString getInternalMethodName();

private:
    static TYPE type;
    static QByteArray method;
    static QByteArray password;
    static QVector<quint8> encTable;
    static QVector<quint8> decTable;
    static int keyLen;
    static int ivLen;

    static void tableInit();
    static QVector<quint8> mergeSort(const QVector<quint8> &, quint32, quint64);
    static void evpBytesToKey();
    bool selfTest();

protected:
    Cipher *enCipher;
    Cipher *deCipher;
    static QByteArray key;
};

}

#endif // ENCRYPTOR_H
