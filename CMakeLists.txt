cmake_minimum_required(VERSION 3.1)

project(QtShadowsocks
        VERSION 2.1.0.1
        LANGUAGES CXX)

option(BUILD_SHARED_LIBS "Build ${PROJECT_NAME} as a shared library" ON)
option(USE_CONAN "Use C++ Package Manager Conan" OFF)

set(LIB_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/lib
    CACHE PATH "Installation directory for libraries")
set(INCLUDE_INSTALL_DIR ${CMAKE_INSTALL_PREFIX}/include
    CACHE PATH "Installation directory for headers")
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Qt5Core 5.5)
find_package(Qt5Network 5.5)
find_package(PkgConfig)

if(USE_CONAN)
    include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
    conan_basic_setup()
    add_definitions(-DUSE_BOTAN2)
    set(BOTAN_LIBRARY_VAR ${CONAN_LIBS})
else()
pkg_search_module(BOTAN REQUIRED botan-2>=2.3.0 botan-1.10)
if(BOTAN_VERSION VERSION_GREATER 2.0)
    message(STATUS "Botan-2 is found and will be used in this build")
    add_definitions(-DUSE_BOTAN2)
    if(BOTAN_VERSION VERSION_GREATER_EQUAL 2.11.0)
        message(STATUS "Botan-2 Version 2.11+ is found and will be used in this build")
        add_definitions(-DUSE_BOTAN211P)
    endif()
else()
    message(DEPRECATION "Botan-1.10 is found and will be used in this build. However, Botan-1.10 is deprecated and should not be used if possible")
endif()
find_library(BOTAN_LIBRARY_VAR
             NAMES ${BOTAN_LIBRARIES}
             HINTS ${BOTAN_LIBRARY_DIRS} ${BOTAN_LIBDIR})
endif()
if(BUILD_SHARED_LIBS)
    add_definitions(-DQSS_LIBRARY)
else()
    add_definitions(-DQSS_STATIC)
    if (MINGW)
        # This however doesn't fix the problem that the executables are depending on the GCC shared libraries
        # I can't find a solution in CMake so far. The workaround is to manually append "-l:libgcc.a -l:libstdc++.a -l:libwinpthread.a" to the end of executables' linklibs.rsp files (in CMakeFiles directory)
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++")
    endif()
endif()

if(WIN32 OR APPLE)
    add_definitions(-DFD_SETSIZE=1024)
endif()

add_subdirectory(lib)
add_subdirectory(shadowsocks-libqss)
find_package(Qt5Test)
if (Qt5Test_FOUND)
    # enable_testing() has to be in the root CMakeLists.txt, see https://cmake.org/pipermail/cmake/2010-November/040725.html
    enable_testing()
    add_subdirectory(test)
endif()
