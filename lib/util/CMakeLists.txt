list(APPEND SOURCE
    ${CMAKE_CURRENT_LIST_DIR}/addresstester.cpp
    ${CMAKE_CURRENT_LIST_DIR}/common.cpp
    ${CMAKE_CURRENT_LIST_DIR}/controller.cpp
    )

set(UTIL_HEADERS
    ${CMAKE_CURRENT_LIST_DIR}/addresstester.h
    ${CMAKE_CURRENT_LIST_DIR}/common.h
    ${CMAKE_CURRENT_LIST_DIR}/controller.h
    ${CMAKE_CURRENT_LIST_DIR}/export.h
    )

install(FILES ${UTIL_HEADERS}
    DESTINATION ${INCLUDE_INSTALL_DIR}/${PROJECT_NAME}/util)
