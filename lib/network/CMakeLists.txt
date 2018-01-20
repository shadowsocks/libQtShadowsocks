list(APPEND SOURCE
    ${CMAKE_CURRENT_LIST_DIR}/httpproxy.cpp
    ${CMAKE_CURRENT_LIST_DIR}/socketstream.cpp
    ${CMAKE_CURRENT_LIST_DIR}/tcprelay.cpp
    ${CMAKE_CURRENT_LIST_DIR}/tcpserver.cpp
    ${CMAKE_CURRENT_LIST_DIR}/udprelay.cpp
    )

set(NETWORK_HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/httpproxy.h
    ${CMAKE_CURRENT_LIST_DIR}/socketstream.h
    ${CMAKE_CURRENT_LIST_DIR}/tcprelay.h
    ${CMAKE_CURRENT_LIST_DIR}/tcpserver.h
    ${CMAKE_CURRENT_LIST_DIR}/udprelay.h
    )

install(FILES ${NETWORK_HEADERS}
    DESTINATION ${INCLUDE_INSTALL_DIR}/${PROJECT_NAME}/network)
