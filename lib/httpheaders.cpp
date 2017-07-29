#include "httpheaders.h"

namespace QSS {

HttpHeaders::HttpHeaders(const char *data, QObject* parent):
    QObject(parent), _data(data), _ptr(data), _isValid(false) {

    beginParse();
}

void HttpHeaders::beginParse() {
    _isValid = parseHttpMethod();
    if (!_isValid) return;

    eatSpace();
    _isValid = parseUri();
    if (!_isValid) return;

    eatSpace();
    _isValid = parseHttpVersion();
    if (!_isValid) return;

    eatSpace();
    eatCRLF();

    while (!eatCRLF()) {
        _isValid = parseKeyValue();
        if (!_isValid) return;
    }
    _isValid = true;
}

bool HttpHeaders::testStr(const char *dest) {
    const char* src = _ptr;
    const char* destPtr = dest;
    while (*destPtr != '\0') {
        if (*src != *destPtr) return false;
        ++destPtr;
        ++src;
    }
    _ptr = src;
    return true;
}

bool HttpHeaders::isDigit(char ch) {
    return ch >= '0' && ch <= '9';
}

bool HttpHeaders::eatCRLF() {
    if (*_ptr == '\r' && *(_ptr + 1) == '\n') {
        _ptr += 2;
        return true;
    }
    return false;
}

int HttpHeaders::eatSpace() {
    int count = 0;
    const char* tmp = _ptr;
    while (*tmp == ' ') {
        ++count;
        ++tmp;
    }
    if (_ptr != tmp) {
        _ptr = tmp;
    }
    return count;
}

#define XX(METHOD) else if (testStr(#METHOD)) { \
    _httpMethod = #METHOD; \
    return true; \
}

bool HttpHeaders::parseHttpMethod() {
    if (false) {
    }
    HTTP_METHOD(XX)

    return false;
}

#undef XX

#define CHECK(X) ((X) != ' ' && (X) != '\r')
bool HttpHeaders::parseUri() {
    if (!CHECK(*_ptr)) return false;
    _httpUri.push_back(*_ptr++);
    while (CHECK(*_ptr)) _httpUri.push_back(*_ptr++);
    return true;
}
#undef CHECK

bool HttpHeaders::parseHttpVersion() {
    _httpVersion = "HTTP/";
    bool result = testStr("HTTP/");
    if (!result) return result;
    if (!isDigit(*_ptr)) return false;
    _httpVersion.push_back(*_ptr++);
    if (*_ptr != '.') return false;
    _httpVersion.push_back(*_ptr++);
    if (!isDigit(*_ptr)) return false;
    _httpVersion.push_back(*_ptr++);
    return true;
}

bool HttpHeaders::parseKeyValue() {
    QByteArray key, value;
    while (*_ptr != ':') key.push_back(*_ptr++);
    ++_ptr;
    while (*_ptr != '\r') value.push_back(*_ptr++);
    bool result = eatCRLF();
    if (!result) return false;
    key = key.trimmed();
    value = value.trimmed();
    _map.insert(key, value);
    return true;
}

int HttpHeaders::offset() const {
    return _ptr - _data;
}

bool HttpHeaders::isValid() const { return _isValid; }

void HttpHeaders::setHttpMethod(const char *content) {
    _httpMethod = content;
}

void HttpHeaders::setHttpUri(const char *content) {
    _httpUri = content;
}

void HttpHeaders::setHttpVersion(const char *content) {
    _httpVersion = content;
}

bool HttpHeaders::setValue(const char *key, const char *value) {
    QHash<QByteArray, QByteArray>::iterator iter = _map.insert(key, value);
    return iter != _map.end();
}

bool HttpHeaders::clearValue(const char *key) {
    return _map.remove(key) > 0;
}

const char* HttpHeaders::getHttpMethod() const {
    return _httpMethod.constData();
}

const char* HttpHeaders::getHttpUri() const {
    return _httpUri.constData();
}

const char* HttpHeaders::getHttpVersion() const {
    return _httpVersion.constData();
}

const char* HttpHeaders::getValue(const char *key) const {
    QHash<QByteArray, QByteArray>::const_iterator that = _map.find(key);
    if (that != _map.end()) {
        return that->constData();
    }
    return '\0';
}

QByteArray HttpHeaders::toByteArray() const {
    QByteArray result;
    result.append(_httpMethod);
    result.append(' ');
    result.append(_httpUri);
    result.append(' ');
    result.append(_httpVersion);
    result.append("\r\n");
    for (QHash<QByteArray, QByteArray>::const_iterator iter = _map.begin();
         iter != _map.end(); ++iter) {
        result.append(iter.key());
        result.append(": ");
        result.append(iter.value());
        result.append("\r\n");
    }
    result.append("\r\n");
    return result;
}

}
