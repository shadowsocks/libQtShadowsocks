#include "profile.h"
#include <QStringList>

using namespace QSS;

Profile::Profile() :
    local_address("127.0.0.1"), server_port(8388), local_port(1080),
    timeout(600), http_proxy(false), debug(false), auth(false)
{
}

Profile::Profile(QByteArray uri) : Profile()
{
    uri.remove(0, 5);//remove the prefix "ss://" from uri
    QStringList resultList = QString(QByteArray::fromBase64(uri)).split(':');
    method = resultList.takeFirst();
    if (method.endsWith(QStringLiteral("-auth"))) {
        method = method.remove(QStringLiteral("-auth"));
        auth = true;
    }
    server_port = resultList.takeLast().toUShort();
    QStringList ser = resultList.join(':').split('@');//there are lots of ':' in IPv6 address
    server = ser.takeLast();
    password = ser.join('@');//incase there is a '@' in password
}

QByteArray Profile::toURI()
{
    QString ssurl = QString("%1%2:%3@%4:%5").arg(method.toLower()).arg(auth ? "-auth" : "").arg(password).arg(server).arg(QString::number(server_port));
    QByteArray uri = QByteArray(ssurl.toStdString().c_str()).toBase64();
    uri.prepend("ss://");
    return uri;
}
