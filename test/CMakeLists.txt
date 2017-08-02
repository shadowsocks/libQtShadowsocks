set(TASK "qss_test")

set(SOURCE
    main.cpp
    address.t.cpp
    chacha.t.cpp
    cipher.t.cpp
    profile.t.cpp
    encryptor.t.cpp
    )

add_executable(${TASK} ${SOURCE})

find_package(Qt5Test)
target_link_libraries(${TASK} Qt5::Core Qt5::Network Qt5::Test QtShadowsocks)
target_include_directories(${TASK}
    PUBLIC ${PROJECT_SOURCE_DIR}/lib)
