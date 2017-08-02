cmake_minimum_required(VERSION 3.0)

project(QtShadowsocks
        VERSION 1.10.0
        LANGUAGES CXX)

option(BUILD_SHARED_LIBS "Build ${PROJECT_NAME} as a shared library" ON)
option(USE_BOTAN2 "Build ${PROJECT_NAME} with Botan-2" OFF)

set(LIB_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/lib
    CACHE PATH "Installation directory for libraries")
set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/include
    CACHE PATH "Installation directory for headers")
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Qt5Core)
find_package(Qt5Network)
find_package(PkgConfig)

if (USE_BOTAN2)
    pkg_check_modules(BOTAN REQUIRED botan-2>=2.2.0)
else()
    pkg_check_modules(BOTAN REQUIRED botan-1.10)
endif()
find_library(BOTAN_LIBRARY_VAR
             NAMES ${BOTAN_LIBRARIES}
             HINTS ${BOTAN_LIBRARY_DIRS} ${BOTAN_LIBDIR})

if(NOT BUILD_SHARED_LIBS)
    add_definitions(-DQSS_STATIC)
endif()

if(WIN32 OR APPLE)
    add_definitions(-DFD_SETSIZE=1024)
endif()

add_subdirectory(lib)
add_subdirectory(shadowsocks-libqss)
add_subdirectory(test)
