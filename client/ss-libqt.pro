QT       += core network concurrent

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
    DEFINES += QCA_STATIC
    win32-msvc2013: {
        LIBS += -L$$top_srcdir/../lib/msvc2013 \
                -L$$top_srcdir/../qca/lib/msvc2013
        QTPLUGIN += qca-ossl
    }
    else: {
        contains(DEFINES, mingw64): {
            LIBS += -L$$top_srcdir/../lib/mingw64 \
                    -L$$top_srcdir/../qca/lib/mingw64
            PRE_TARGETDEPS += $$top_srcdir/../lib/mingw64/libQtShadowsocks.a \
                              $$top_srcdir/../qca/lib/mingw64/libqca.a
        }
        else {
            LIBS += -L$$top_srcdir/../lib/mingw32 \
                    -L$$top_srcdir/../qca/lib/mingw32
            PRE_TARGETDEPS += $$top_srcdir/../lib/mingw32/libQtShadowsocks.a \
                              $$top_srcdir/../qca/lib/mingw32/libqca.a
        }
    }
}

LIBS += -lqca -lqca-ossl -lQtShadowsocks
