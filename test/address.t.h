/*
 * address.t.h
 *
 * The unit test class of Address
 *
 * Copyright (C) 2015-2016 Symeon Huang <hzwhuang@gmail.com>
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

#ifndef ADDRESS_T_H
#define ADDRESS_T_H

#include <QString>
#include <QtTest>

class Address_T : public QObject
{
    Q_OBJECT

public:
    Address_T();

private Q_SLOTS:
    void testConstructor1();
    void testConstructor2();
    void testAssignment();
    void testSetAddress();
    void testSetIPAddress();
    void testSetPort();
    void testLookup();
};

#endif // ADDRESS_T_H
