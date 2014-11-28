#include <QDebug>
#include <QtConcurrent>
#include "encryptor.h"

Encryptor::Encryptor(QObject *parent) :
    QObject(parent)
{
    enCipher = NULL;
    deCipher = NULL;
}

Encryptor::~Encryptor()
{
    if (enCipher != NULL) {
        delete enCipher;
    }
    if (deCipher != NULL) {
        delete deCipher;
    }
}

const QVector<quint8> Encryptor::octVec = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255};

const QMap<QByteArray, QVector<int> > Encryptor::cipherMap = Encryptor::generateCihperMap();

QMap<QByteArray, QVector<int> > Encryptor::generateCihperMap()
{
    QMap<QByteArray, QVector<int> >map;
    map.insert("aes128-cfb", {16, 16});
    map.insert("aes192-cfb", {24, 16});
    map.insert("aes256-cfb", {32, 16});
    map.insert("blowfish-cfb", {16, 8});
    map.insert("cast5-cfb", {16, 8});
    map.insert("des-cfb", {8, 8});
    /*
     * below ciphers are currently unsupported.
     */
    /*
    map.insert("rc4", {16, 0});
    map.insert("rc4-md5", {16, 16});

    //those are unlikely get supported in the future
    map.insert("idea-cfb", {16, 8});
    map.insert("rc2-cfb", {16, 8});
    map.insert("seed-cfb", {16, 16});
    */
    return map;
}

//define static member variables
bool Encryptor::usingTable = false;
QString Encryptor::cipherMode;
QByteArray Encryptor::method;
QByteArray Encryptor::password;
QVector<quint8> Encryptor::encTable;
QVector<quint8> Encryptor::decTable;
int Encryptor::keyLen = 0;
int Encryptor::ivLen = 0;
QCA::SymmetricKey Encryptor::_key;

void Encryptor::setup()
{
    if (!usingTable) {
        if (deCipher != NULL) {
            delete deCipher;
            deCipher = NULL;
        }
        if (enCipher != NULL) {
            delete enCipher;
        }
    }
}

void Encryptor::initialise(const QString &m, const QString &pwd)
{
    method = m.toLower().toLocal8Bit();//local8bit or utf-8?
    password = pwd.toLocal8Bit();

    if (m.compare("table") == 0) {
        usingTable = true;
        tableInit();
    }
    else {
        //change method name according to QCA
        if (method.contains("aes")) {
            method.remove(3, 1);//i.e. aes-256-cfb to aes256-cfb
        }
        else if (method.contains("bf")) {
            method = QByteArray("blowfish-cfb");
        }
        cipherMode = method.mid(0, method.indexOf('-'));//drop "-cfb"

        if (!QCA::isSupported(method.data())) {
            qCritical() << method << "is not supported!";
            qDebug() << "supported methods are " << QCA::supportedFeatures();
        }

        QVector<int> cipher = cipherMap.value(method);
        if (cipher.size() < 2) {
            qCritical() << "Abort. The method is not supported.";
            exit(223);
        }
        keyLen = cipher[0];
        ivLen = cipher[1];
        evpBytesToKey();
    }
}

void Encryptor::tableInit()
{
    quint32 i;
    quint64 key = 0;

    encTable.fill(0, 256);
    decTable.fill(0, 256);
    QByteArray digest = QCryptographicHash::hash(password, QCryptographicHash::Md5);

    for (i = 0; i < 8; ++i)
    {
        key += (quint64(digest.at(i)) << (8 * i));
    }

    QtConcurrent::blockingMap(octVec, [&] (const quint8 &j) {
        encTable[j] = j;
    });
    for(i = 1; i < 1024; ++i)
    {
        encTable = mergeSort(encTable, i, key);
    }
    QtConcurrent::blockingMap(octVec, [&] (const quint8 &j) {
        decTable[encTable[j]] = j;
    });
}

QVector<quint8> Encryptor::mergeSort(const QVector<quint8> &array, quint32 salt, quint64 key)
{
    int length = array.size();

    if (length <= 1) {
        return array;
    }

    int middle = length / 2;
    QVector<quint8> left = array.mid(0, middle);
    QVector<quint8> right = array.mid(middle);

    left = mergeSort(left, salt, key);
    right = mergeSort(right, salt, key);

    int leftptr = 0;
    int rightptr = 0;

    QVector<quint8> sorted;
    sorted.fill(0, length);
    for (int i = 0; i < length; ++i) {
        if (rightptr == right.size() || (leftptr < left.size() && randomCompare(left[leftptr], right[rightptr], salt, key) <= 0)) {
            sorted[i] = left[leftptr];
            leftptr++;
        }
        else if (leftptr == left.size() || (rightptr < right.size() && randomCompare(right[rightptr], left[leftptr], salt, key) <= 0)) {
            sorted[i] = right[rightptr];
            rightptr++;
        }
    }
    return sorted;
}

int Encryptor::randomCompare(const quint8 &x, const quint8 &y, const quint32 &i, const quint64 &a)
{
    return a % (x + i) - a % (y + i);
}

void Encryptor::evpBytesToKey()
{
    QVector<QByteArray> m;
    QByteArray data;
    int i = 0;

    while (m.size() < keyLen + ivLen) {
        if (i == 0) {
            data = password;
        }
        else {
            data = m[i - 1] + password;
        }
        m.append(QCryptographicHash::hash(data, QCryptographicHash::Md5));
        i++;
    }
    QByteArray ms;
    for (QVector<QByteArray>::ConstIterator it = m.begin(); it != m.end(); ++it) {
        ms.append(*it);
    }

    _key = QCA::SymmetricKey(QCA::SecureArray(ms.mid(0, keyLen)));
}

QByteArray Encryptor::randomIv()
{
    return QCA::Random::randomArray(ivLen).toByteArray();
}

QByteArray Encryptor::encrypt(const QByteArray &in)
{
    QByteArray out;

    if (usingTable) {
        out = QByteArray(in.size(), '0');
        for (int i = 0; i < in.size(); ++i) {
            out[i] = encTable.at(in[i]);
        }
    }
    else {
        QCA::SecureArray data(in);

        if (enCipher == NULL) {
            QByteArray iv = randomIv();
            enCipher = new QCA::Cipher(cipherMode, QCA::Cipher::CFB, QCA::Cipher::DefaultPadding, QCA::Encode, _key, QCA::InitializationVector(iv));
            out = iv + enCipher->update(data).toByteArray();
        }
        else {
            out = enCipher->update(data).toByteArray();
        }
    }

    return out;
}

QByteArray Encryptor::decrypt(const QByteArray &in)
{
    QByteArray out;

    if (usingTable) {
        out = QByteArray(in.size(), '0');
        for (int i = 0; i < in.size(); ++i) {
            out[i] = decTable.at(in[i]);
        }
    }
    else {
        QCA::SecureArray data(in);

        if (deCipher == NULL) {
            QByteArray div(in.mid(0, ivLen));
            QCA::SecureArray srd(in.mid(ivLen));
            deCipher = new QCA::Cipher(cipherMode, QCA::Cipher::CFB, QCA::Cipher::DefaultPadding, QCA::Decode, _key, QCA::InitializationVector(div));
            out = deCipher->update(srd).toByteArray();
        }
        else {
            out = deCipher->update(data).toByteArray();
        }
    }

    return out;
}

bool Encryptor::selfTest()
{
    QByteArray test("barfoo!");
    QByteArray res = decrypt(encrypt(test));
    if (!usingTable) {
        delete enCipher;
        enCipher = NULL;
        delete deCipher;
        deCipher = NULL;
    }

    return test == res;
}
