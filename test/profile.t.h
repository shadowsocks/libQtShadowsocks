/*
 * profile.t.h
 *
 * The unit test class of Address
 *
 * Copyright (C) 2016 Symeon Huang <hzwhuang@gmail.com>
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

#ifndef PROFILE_T_H
#define PROFILE_T_H

#include <QString>
#include <QtTest>

class Profile_T : public QObject
{
    Q_OBJECT

public:
    Profile_T();

private Q_SLOTS:
    void testConstructorEmpty();
    void testFromUri();
    void testFromUriSip002();
    void testToUri();
};

#endif // PROFILE_T_H
