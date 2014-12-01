/*
 * qca_version.h - Qt Cryptographic Architecture
 * Copyright (C) 2014  Ivan Romanov <drizt@land.ru>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301  USA
 *
 */

/**
   \file qca_version.h

   Header file with %QCA version

   \note You should not use this header directly from an
   application. You should just use <tt> \#include \<QtCrypto>
   </tt> instead.
*/

#ifndef QCA_VERSION_H
#define QCA_VERSION_H

/**
   The major part of current %QCA version.
*/

#define QCA_MAJOR_VERSION 2

/**
   The minor part of current %QCA version.
*/

#define QCA_MINOR_VERSION 1

/**
   The patch part of current %QCA version.
*/

#define QCA_PATCH_VERSION 0

/**
   The current version of %QCA as string.
 */

#define QCA_VERSION_STR "2.1.0"

/**
   Can be used like #if (QCA_VERSION >= %QCA_VERSION_CHECK(2, 0, 3))

   \param major part of the version
   \param minor part of the version
   \param patch part of the version
*/

#define QCA_VERSION_CHECK(major, minor, patch) \
    ((major << 16) | (minor << 8) | (patch))

/**
   The current version of %QCA

   This provides you a compile time check of the %QCA version.

   \sa qcaVersion for a runtime check.
*/

#define QCA_VERSION \
    QCA_VERSION_CHECK(2, 1, 0)

#endif // QCA_VERSION_H
