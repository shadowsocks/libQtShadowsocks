SOURCES  += \
    src/encryptor.cpp \
    src/connection.cpp \
    src/basecontroller.cpp \
    src/localcontroller.cpp

HEADERS  += \
    src/profile.h \
    src/encryptor.h \
    src/connection.h \
    src/basecontroller.h \
    src/localcontroller.h

unix: {
    target.path = /usr/lib
    INSTALLS   += target

    CONFIG     += link_pkgconfig
    PKGCONFIG  += qca2

    VERSION     = 0.1
}

win32: {
    INCLUDEPATH += $$top_srcdir/qca/include
    contains(DEFINES, mingw64): {
        LIBS += -L$$top_srcdir/qca/lib/mingw64
        DESTDIR = $$top_srcdir/lib/mingw64
    }
    else {
        LIBS += -L$$top_srcdir/qca/lib/mingw32
        DESTDIR = $$top_srcdir/lib/mingw32
    }
}

LIBS     += -lqca
