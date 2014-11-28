QT       += core network

QT       -= gui

TARGET = ss-libqt
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app

INCLUDEPATH += ../

#You have to change the directory to suit your case
LIBS    += -L/home/symeon/Projects/build/libqtshadowsocks-Desktop-Debug \
            -lQtShadowsocks

SOURCES += main.cpp

unix: {
    CONFIG    += link_pkgconfig
    PKGCONFIG += qca2
}

LIBS  += -lqca
