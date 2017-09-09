#include "profile.h"
#include <stdexcept>
#include <QByteArray>

namespace QSS {

struct ProfilePrivate {
    bool httpProxy = false;
    bool otaAuth = false;
};

Profile::Profile() :
    d_private(new ProfilePrivate()),
    d_localAddress("127.0.0.1"),
    d_serverPort(0),
    d_localPort(0),
    d_timeout(600),
    d_debug(false)
{
}

Profile::~Profile()
{
    delete d_private;
}

const std::string& Profile::name() const
{
    return d_name;
}

const std::string& Profile::method() const
{
    return d_method;
}

const std::string& Profile::password() const
{
    return d_password;
}

const std::string& Profile::serverAddress() const
{
    return d_serverAddress;
}

const std::string& Profile::localAddress() const
{
    return d_localAddress;
}

uint16_t Profile::serverPort() const
{
    return d_serverPort;
}

uint16_t Profile::localPort() const
{
    return d_localPort;
}

int Profile::timeout() const
{
    return d_timeout;
}

bool Profile::debug() const
{
    return d_debug;
}

bool Profile::httpProxy() const
{
    return d_private->httpProxy;
}

bool Profile::otaEnabled() const
{
    return d_private->otaAuth;
}

void Profile::setName(const std::string& name)
{
    d_name = name;
}

void Profile::setMethod(const std::string& method)
{
    d_method = method;
}

void Profile::setPassword(const std::string& password)
{
    d_password = password;
}

void Profile::setServerAddress(const std::string& server)
{
    d_serverAddress = server;
}

void Profile::setLocalAddress(const std::string& local)
{
    d_localAddress = local;
}

void Profile::setServerPort(uint16_t p)
{
    d_serverPort = p;
}

void Profile::setLocalPort(uint16_t p)
{
    d_localPort = p;
}

void Profile::setTimeout(int t)
{
    d_timeout = t;
}

void Profile::setHttpProxy(bool e)
{
    d_private->httpProxy = e;
}

void Profile::enableDebug()
{
    d_debug = true;
}

void Profile::disableDebug()
{
    d_debug = false;
}

void Profile::enableOta()
{
    d_private->otaAuth = true;
}

void Profile::disableOta()
{
    d_private->otaAuth = false;
}

Profile Profile::fromUri(const std::string& ssUri)
{
    if (ssUri.length() < 5) {
        throw std::invalid_argument("SS URI is too short");
    }

    Profile result;
    //remove the prefix "ss://" from uri
    std::string uri(ssUri.data() + 5, ssUri.length() - 5);
    size_t hashPos = uri.find_last_of('#');
    if (hashPos != std::string::npos) {
        // Get the name/remark
        result.setName(uri.substr(hashPos + 1));
        uri.erase(hashPos);
    }
    size_t pluginPos = uri.find_first_of('/');
    if (pluginPos != std::string::npos) {
        // TODO support plugins. For now, just ignore them
        uri.erase(pluginPos);
    }
    size_t atPos = uri.find_first_of('@');
    if (atPos == std::string::npos) {
        // Old URI scheme
        std::string decoded(QByteArray::fromBase64(QByteArray(uri.data(), uri.length()), QByteArray::Base64Option::OmitTrailingEquals).data());
        size_t colonPos = decoded.find_first_of(':');
        if (colonPos == std::string::npos) {
            throw std::invalid_argument("Can't find the colon separator between method and password");
        }
        std::string method = decoded.substr(0, colonPos);
        if (method.substr(method.length() - 5) == "-auth") {
            result.enableOta();
            method.erase(method.length() - 5);
        }
        result.setMethod(method);
        decoded.erase(0, colonPos + 1);
        atPos = decoded.find_last_of('@');
        if (atPos == std::string::npos) {
            throw std::invalid_argument("Can't find the at separator between password and hostname");
        }
        result.setPassword(decoded.substr(0, atPos));
        decoded.erase(0, atPos + 1);
        colonPos = decoded.find_last_of(':');
        if (colonPos == std::string::npos) {
            throw std::invalid_argument("Can't find the colon separator between hostname and port");
        }
        result.setServerAddress(decoded.substr(0, colonPos));
        result.setServerPort(std::stoi(decoded.substr(colonPos + 1)));
    } else {
        // SIP002 URI scheme
        std::string userInfo(QByteArray::fromBase64(QByteArray(uri.data(), atPos), QByteArray::Base64Option::Base64UrlEncoding).data());
        size_t userInfoSp = userInfo.find_first_of(':');
        if (userInfoSp == std::string::npos) {
            throw std::invalid_argument("Can't find the colon separator between method and password");
        }
        std::string method = userInfo.substr(0, userInfoSp);
        result.setMethod(method);
        if (method.substr(method.length() - 5) == "-auth") {
            result.enableOta();
            method.erase(method.length() - 5);
        }
        result.setPassword(userInfo.substr(userInfoSp + 1));

        uri.erase(0, atPos + 1);
        size_t hostSpPos = uri.find_last_of(':');
        if (hostSpPos == std::string::npos) {
            throw std::invalid_argument("Can't find the colon separator between hostname and port");
        }
        result.setServerAddress(uri.substr(0, hostSpPos));
        result.setServerPort(std::stoi(uri.substr(hostSpPos + 1)));
    }

    return result;
}

std::string Profile::toUri() const
{
    std::string ssUri = method() + (otaEnabled() ? "-auth" : "") + ":" + password() + "@" + serverAddress() + ":" + std::to_string(serverPort());
    QByteArray uri = QByteArray(ssUri.data()).toBase64(QByteArray::Base64Option::OmitTrailingEquals);
    uri.prepend("ss://");
    uri.append("#");
    uri.append(d_name.data(), d_name.length());
    return std::string(uri.data(), uri.length());
}

std::string Profile::toUriSip002() const
{
    std::string plainUserInfo = method() + (otaEnabled() ? "-auth" : "") + ":" + password();
    std::string userinfo(QByteArray(plainUserInfo.data()).toBase64(QByteArray::Base64Option::Base64UrlEncoding).data());
    return "ss://" + userinfo + "@" + serverAddress() + ":" + std::to_string(serverPort()) + "#" + name();
}

}
