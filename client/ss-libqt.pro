QT       += core network

QT       -= gui

TARGET    = ss-libqt
CONFIG   += console

TEMPLATE  = app

INCLUDEPATH += $$top_srcdir/../src

SOURCES     += main.cpp

unix: {
    CONFIG    += link_pkgconfig
    PKGCONFIG += qca2
    LIBS      += -L/home/symeon/Projects/build/libqtshadowsocks-Desktop-Debug
}

win32: {
    INCLUDEPATH += $$top_srcdir/../qca/include
    contains(DEFINES, mingw64): {
        DEPENDPATH += $$top_srcdir/lib/mingw64
        LIBS += -L$$top_srcdir/../lib/mingw64 \
                -L$$top_srcdir/../qca/lib/mingw64
        PRE_TARGETDEPS += $$top_srcdir/../lib/mingw64/libQtShadowsocks.a \
                          $$top_srcdir/../qca/lib/mingw64/libqca.a
    }
    else {
        DEPENDPATH += $$top_srcdir/lib/mingw32
        LIBS += -L$$top_srcdir/../lib/mingw32 \
                -L$$top_srcdir/../qca/lib/mingw32
        PRE_TARGETDEPS += $$top_srcdir/../lib/mingw32/libQtShadowsocks.a \
                          $$top_srcdir/../qca/lib/mingw32/libqca.a
    }
}

LIBS += -lqca -lQtShadowsocks
