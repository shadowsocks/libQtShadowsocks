cmake_minimum_required(VERSION 3.0)

project(QtShadowsocks
        VERSION 1.10.0
        LANGUAGES CXX)

option(BUILD_SHARED_LIBS "Build ${PROJECT_NAME} as a shared library" ON)

set(LIB_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/lib
    CACHE PATH "Installation directory for libraries")
set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/include
    CACHE PATH "Installation directory for headers")
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 11)

find_package(Qt5Core)
find_package(Qt5Network)
find_package(PkgConfig)
pkg_search_module(BOTAN REQUIRED botan-1.10 botan-2)

if(BUILD_SHARED_LIBS)
    add_definitions(-DQSS_STATIC)
endif()

if(WIN32 OR APPLE)
    add_definitions(-DFD_SETSIZE=1024)
endif()

add_subdirectory(lib)
add_subdirectory(shadowsocks-libqss)
add_subdirectory(test)
