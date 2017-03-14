#ifndef HTTPHEADERS_H
#define HTTPHEADERS_H

#include <QtCore>
#include "export.h"

#define HTTP_METHOD(V) V(OPTIONS) \
      V(GET) \
      V(HEAD ) \
      V(POST) \
      V(PUT) \
      V(DELETE) \
      V(TRACE) \
      V(CONNECT)

namespace QSS {

class QSS_EXPORT HttpHeaders final : QObject {

    Q_OBJECT

public:

#define XX(NAME) NAME,
    enum HttpMethod {
        HTTP_METHOD(XX)
    };
#undef XX

    explicit HttpHeaders(const char* data, QObject* parent = Q_NULLPTR);
    explicit HttpHeaders(const HttpHeaders&) = delete;
    HttpHeaders& operator=(const HttpHeaders&) = delete;

    int offset() const;
    bool isValid() const;

    void setHttpMethod(const char*);
    void setHttpUri(const char*);
    void setHttpVersion(const char *);
    bool setValue(const char* key, const char* value);
    bool clearValue(const char* key);

    const char* getHttpMethod() const;
    const char* getHttpUri() const;
    const char* getHttpVertion() const;

    const char* getValue(const char* key) const;

    QByteArray toByteArray() const;

private:

    QByteArray _httpMethod;
    QByteArray _httpUri;
    QByteArray _httpVersion;
    QHash<QByteArray, QByteArray> _map;

    void beginParse();

    bool isDigit(char ch);

    // move ptr foward if success
    bool testStr(const char* dest);
    int eatSpace();
    bool eatCRLF();
    bool parseHttpMethod();
    bool parseUri();
    bool parseHttpVersion();
    bool parseKeyValue();

    const char* _data;
    const char* _ptr;
    bool _isValid;

};

}

#endif // HTTPHEADERS_H
