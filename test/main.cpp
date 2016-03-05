#include <QTest>
#include "address.t.h"
#include "chacha.t.h"

int main(int, char **)
{
    Address_T addr_t;
    ChaCha_T chacha_t;

    QTest::qExec(&addr_t);
    QTest::qExec(&chacha_t);

    return 0;
}
