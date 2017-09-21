set(LIBNAME "QtShadowsocks")
add_definitions(-DQSS_VERSION="${PROJECT_VERSION}")

set(SOURCE
    address.cpp
    addresstester.cpp
    chacha.cpp
    cipher.cpp
    common.cpp
    controller.cpp
    encryptor.cpp
    rc4.cpp
    tcprelay.cpp
    udprelay.cpp
    httpproxy.cpp
    socketstream.cpp
    tcpserver.cpp
    profile.cpp
    )

set(HEADERS
    QtShadowsocks
    address.h
    addresstester.h
    chacha.cpp
    chacha.h
    cipher.h
    common.h
    controller.h
    encryptor.h
    export.h
    httpproxy.h
    profile.h
    QtShadowsocks
    rc4.h
    socketstream.h
    tcprelay.h
    tcpserver.h
    udprelay.h
    )

add_library(${LIBNAME} ${SOURCE})
set_target_properties(${LIBNAME} PROPERTIES VERSION ${PROJECT_VERSION}
                                            SOVERSION ${PROJECT_VERSION_MAJOR})
target_link_libraries(${LIBNAME}
    PUBLIC Qt5::Core
    PUBLIC Qt5::Network
    PRIVATE ${BOTAN_LIBRARY_VAR})
target_include_directories(${LIBNAME} PRIVATE ${BOTAN_INCLUDE_DIRS})

foreach(LIB Qt5Network Qt5Core ${BOTAN_LIBRARIES})
    set(PRIVATE_LIBS "${PRIVATE_LIBS} -l${LIB}")
endforeach()
configure_file(QtShadowsocks.pc.in ${CMAKE_CURRENT_BINARY_DIR}/QtShadowsocks.pc
    @ONLY
    NEWLINE_STYLE UNIX)

install(TARGETS ${LIBNAME}
    LIBRARY DESTINATION ${LIB_INSTALL_DIR}
    ARCHIVE DESTINATION ${LIB_INSTALL_DIR})
install(FILES ${HEADERS}
    DESTINATION ${INCLUDE_INSTALL_DIR}/${PROJECT_NAME})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/QtShadowsocks.pc
    DESTINATION ${LIB_INSTALL_DIR}/pkgconfig)
